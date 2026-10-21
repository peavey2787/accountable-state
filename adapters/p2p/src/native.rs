//! Real p2p-net + hydra-msg adapter with authenticated, retryable application delivery.
//!
//! p2p-net's addressed messages use Gossipsub: `send_message` confirms LOCAL
//! publication, not remote delivery. The game protocol cannot safely assume
//! that every publish reaches its peer. This layer adds per-direction sequence
//! numbers, end-to-end encrypted receipts, retransmission, and replay filtering.
#![forbid(unsafe_code)]

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use crate::reliable::Reliable;
use tokio::sync::mpsc;

use gv_core::MatchId;
use hydra_msg::{ContactId, Hydra, HydraMessage};
use p2p_net::{start_node, AppSubscription, Multiaddr, NodeConfig, NodeHandle, PeerId};

const OFFER: u8 = 1;
const ANSWER: u8 = 2;
const FINISH: u8 = 3;
const ENCRYPTED: u8 = 4;
const INNER_MAGIC: &[u8] = b"GV-EDGE/P2P/V1\0";
const READY_PING: &[u8] = b"GV-P2P-READY/V1";
const READY_PONG: &[u8] = b"GV-P2P-READY-ACK/V1";
const FRAME_DATA: u8 = 1;
const FRAME_ACK: u8 = 2;
/// Session channels (see `LiveSession`): windowed reliable data, its cumulative
/// acknowledgement, and best-effort datagrams for the 60 Hz input stream.
const FRAME_RDATA: u8 = 3;
const FRAME_RACK: u8 = 4;
const FRAME_STREAM: u8 = 5;
/// Several session frames in one HYDRA packet (see `Bundle`).
const FRAME_BUNDLE: u8 = 6;
/// HYDRA's Lite envelope (4 KiB). Game messages are tiny; the default 32 KiB
/// padding class would put ~170 KB on the wire for every input frame.
const GAME_PACKET_BYTES: usize = 4096;
const FRAME_HEADER_BYTES: usize = 1 + 8;
const RETRY_INTERVAL: Duration = Duration::from_millis(550);
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(28);
const MAX_QUEUED_MESSAGES: usize = 4;
pub const MAX_ENCRYPTED_PACKET: usize = 1024 * 1024;

#[derive(Debug)]
pub enum LiveError {
    Transport(String),
    Security(String),
    Timeout,
    Oversize,
    BadFrame,
}

fn net<T: std::fmt::Display>(e: T) -> LiveError {
    LiveError::Transport(e.to_string())
}
fn sec<T: std::fmt::Display>(e: T) -> LiveError {
    LiveError::Security(e.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DataFrame {
    kind: u8,
    sequence: u64,
    payload: Vec<u8>,
}

impl DataFrame {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FRAME_HEADER_BYTES + self.payload.len());
        bytes.push(self.kind);
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, LiveError> {
        if bytes.len() < FRAME_HEADER_BYTES {
            return Err(LiveError::BadFrame);
        }
        let kind = bytes[0];
        if !(FRAME_DATA..=FRAME_BUNDLE).contains(&kind) {
            return Err(LiveError::BadFrame);
        }
        if (kind == FRAME_ACK || kind == FRAME_RACK) && bytes.len() != FRAME_HEADER_BYTES {
            return Err(LiveError::BadFrame);
        }
        let sequence = u64::from_le_bytes(
            bytes[1..FRAME_HEADER_BYTES]
                .try_into()
                .map_err(|_| LiveError::BadFrame)?,
        );
        Ok(Self {
            kind,
            sequence,
            payload: bytes[FRAME_HEADER_BYTES..].to_vec(),
        })
    }
}

/// Deliver each remote input at most once, even if Gossipsub or Hydra resends
/// the same application sequence. Peers ACK duplicates without replaying them.
#[derive(Default)]
struct ReceiveWindow {
    next: u64,
    pending: VecDeque<Vec<u8>>,
}

enum Admission {
    Fresh,
    Duplicate,
    Future,
}

impl ReceiveWindow {
    fn admit(&mut self, seq: u64, payload: &[u8]) -> Result<Admission, LiveError> {
        if seq < self.next {
            return Ok(Admission::Duplicate);
        }
        if seq > self.next {
            return Ok(Admission::Future);
        }
        if self.pending.len() >= MAX_QUEUED_MESSAGES {
            return Err(LiveError::Security(
                "game transport receive queue overflow".into(),
            ));
        }
        self.next = self.next.checked_add(1).ok_or(LiveError::BadFrame)?;
        self.pending.push_back(payload.to_vec());
        Ok(Admission::Fresh)
    }
}

/// Native P2P session: p2p-net authenticated message sender, Hydra encryption,
/// and delivery ACKs from the exact pinned remote contact. Membership comes
/// from the match manifest, not discovery or contact-card lookup.
pub struct LiveLink {
    pub node: NodeHandle,
    pub peer: PeerId,
    pub match_id: MatchId,
    hydra: Hydra,
    contact: ContactId,
    sub: AppSubscription,
    topic: String,
    next_send: u64,
    incoming: ReceiveWindow,
    /// Round trip of the most recent first-try send (publication to receipt).
    pub last_ack_rtt: Option<Duration>,
    /// Messages dropped because this side fell behind the node's fan-out channel.
    pub lagged: u64,
    /// Worst single HYDRA `send` / `receive` call, in microseconds.
    pub hydra_send_max_us: u64,
    pub hydra_recv_max_us: u64,
    /// Number of HYDRA calls slower than 100 ms (expected: zero).
    pub hydra_slow_calls: u64,
    /// HYDRA operations since the message history was last pruned.
    hydra_ops: u32,
    /// RAM-backed copy of the HYDRA store used for this match (removed on drop).
    ram_dir: Option<PathBuf>,
}

/// HYDRA is a messenger: every `send`/`receive` appends to a per-contact history
/// and rewrites the whole encrypted state. Left alone, game frames pile up
/// (hard limit: 10,000 messages) and each call gets slower. Frames are already
/// consumed by the time they are stored, so the history is pruned regularly.
const PRUNE_EVERY_OPS: u32 = 16;

/// Copy the (small) HYDRA store to RAM-backed storage for the match. Identity and
/// contacts stay on disk untouched; only this run's throwaway session state
/// lives in the copy, which saves a disk write per message.
fn ram_copy(src: &Path) -> Option<PathBuf> {
    let base = Path::new("/dev/shm");
    if !base.is_dir() {
        return None;
    }
    let dst = base.join(format!(
        "gv-hydra-{}-{}",
        std::process::id(),
        hex(&rand_tag())
    ));
    fn copy(from: &Path, to: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(to)?;
        for entry in std::fs::read_dir(from)? {
            let entry = entry?;
            let target = to.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy(&entry.path(), &target)?;
            } else {
                std::fs::copy(entry.path(), &target)?;
            }
        }
        Ok(())
    }
    if src.is_dir() {
        copy(src, &dst).ok()?;
    } else {
        std::fs::create_dir_all(&dst).ok()?;
    }
    Some(dst)
}
fn rand_tag() -> [u8; 8] {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    (nanos as u64).to_le_bytes()
}

impl Drop for LiveLink {
    fn drop(&mut self) {
        if let Some(dir) = self.ram_dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

impl LiveLink {
    pub async fn start(
        config: NodeConfig,
        store: impl AsRef<Path>,
        password: &str,
        trusted_card: &[u8],
        match_id: MatchId,
        peer: Option<PeerId>,
        dial: Option<Multiaddr>,
    ) -> Result<Self, LiveError> {
        Self::start_on(
            config,
            store,
            password,
            trusted_card,
            match_id,
            peer,
            dial,
            "",
            None,
        )
        .await
    }

    /// Like [`Self::start`] on a named channel (`""` is the gameplay link) so several
    /// independent links of one match never share a gossip topic. `announce` receives the
    /// node's own dial address (with `/p2p/<id>`) once it is listening, for the other side.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_on(
        config: NodeConfig,
        store: impl AsRef<Path>,
        password: &str,
        trusted_card: &[u8],
        match_id: MatchId,
        peer: Option<PeerId>,
        dial: Option<Multiaddr>,
        channel: &str,
        announce: Option<&Path>,
    ) -> Result<Self, LiveError> {
        let boot = Instant::now();
        let ram_dir = if std::env::var("GV_HYDRA_RAM").is_ok_and(|v| v == "1") {
            ram_copy(store.as_ref())
        } else {
            None
        };
        let store_path = ram_dir.as_deref().unwrap_or(store.as_ref());
        let mut hydra = Hydra::open(store_path, password).map_err(sec)?;
        hydra.set_packet_size(GAME_PACKET_BYTES).map_err(sec)?;
        let ids = hydra.list_ids();
        let id = match ids.as_slice() {
            [] => hydra.generate_id(password).map_err(sec)?,
            [only] => only.id(),
            _ => {
                return Err(LiveError::Security(
                    "multiple Hydra identities; use a dedicated profile".into(),
                ));
            }
        };
        hydra.set_active_id(id, password).map_err(sec)?;
        let contact = hydra.add_contact(trusted_card).map_err(sec)?;
        hydra
            .verify_contact(contact.id(), contact.safety_code())
            .map_err(sec)?;
        let hydra_ready = boot.elapsed();
        let node = start_node(config).await.map_err(net)?;
        let node_ready = boot.elapsed();
        let topic = if channel.is_empty() {
            format!("gv/edge/v1/{}", hex(&match_id))
        } else {
            format!("gv/edge/v1/{}/{channel}", hex(&match_id))
        };
        let sub = node.subscribe(&topic).await.map_err(net)?;
        let binding = node.local_binding().await;
        eprintln!(
            "p2p-net local peer: {} | advertised addresses: {:?}",
            binding.peer_id, binding.dial_addresses
        );
        if let Some(path) = announce {
            let addrs: Vec<String> = binding
                .dial_addresses
                .iter()
                .map(|a| a.to_string())
                .collect();
            let pick = addrs
                .iter()
                .find(|a| a.contains("127.0.0.1") && a.contains("quic-v1"))
                .or_else(|| addrs.first())
                .cloned()
                .unwrap_or_default();
            let full = if pick.contains("/p2p/") {
                pick
            } else {
                format!("{pick}/p2p/{}", binding.peer_id)
            };
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, full).map_err(|e| LiveError::Security(e.to_string()))?;
            std::fs::rename(&tmp, path).map_err(|e| LiveError::Security(e.to_string()))?;
        }
        if let Some(addr) = dial {
            node.connect_peer(addr).await.map_err(net)?;
        }
        let peer = if let Some(peer) = peer {
            peer
        } else {
            let started = Instant::now();
            loop {
                if started.elapsed() > Duration::from_secs(90) {
                    return Err(LiveError::Timeout);
                }
                let connected: Vec<_> = node
                    .get_peers()
                    .await
                    .map_err(net)?
                    .into_iter()
                    .filter(|p| p.connected)
                    .collect();
                if connected.len() > 1 {
                    return Err(LiveError::Security(format!(
                        "ambiguous peer discovery: {}",
                        connected
                            .iter()
                            .map(|p| format!("{p:?}"))
                            .collect::<Vec<_>>()
                            .join(" | ")
                    )));
                }
                if let Some(candidate) = connected.first() {
                    eprintln!(
                        "startup: hydra {:?} · p2p node {:?} · peer connected {:?}",
                        hydra_ready,
                        node_ready,
                        boot.elapsed()
                    );
                    break PeerId::from_str(&candidate.peer_id).map_err(net)?;
                }
                tokio::time::sleep(Duration::from_millis(350)).await;
            }
        };
        Ok(Self {
            node,
            peer,
            match_id,
            hydra,
            contact: contact.id(),
            sub,
            topic,
            next_send: 0,
            incoming: ReceiveWindow::default(),
            last_ack_rtt: None,
            lagged: 0,
            hydra_send_max_us: 0,
            hydra_recv_max_us: 0,
            hydra_slow_calls: 0,
            hydra_ops: 0,
            ram_dir,
        })
    }

    pub fn local_card(&self) -> Result<Vec<u8>, LiveError> {
        self.hydra.create_contact_card().map_err(sec)
    }

    async fn raw_send(&self, kind: u8, bytes: &[u8]) -> Result<(), LiveError> {
        if bytes.len() > MAX_ENCRYPTED_PACKET - 1 {
            return Err(LiveError::Oversize);
        }
        let mut frame = Vec::with_capacity(bytes.len() + 1);
        frame.push(kind);
        frame.extend_from_slice(bytes);
        // Gossipsub learns the remote subscription asynchronously. Until then
        // publishing fails with NoPeersSubscribedToTopic; that is transient
        // (not a security or protocol fault), so retry for a bounded time.
        let started = Instant::now();
        loop {
            match self
                .node
                .send_message(self.peer, self.topic.clone(), frame.clone())
                .await
            {
                Ok(()) => return Ok(()),
                Err(err)
                    if err.to_string().contains("NoPeersSubscribedToTopic")
                        && started.elapsed() < Duration::from_secs(30) =>
                {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(err) => return Err(net(err)),
            }
        }
    }

    async fn raw_receive(&mut self) -> Result<(u8, Vec<u8>), LiveError> {
        loop {
            let msg = match self.sub.recv().await {
                Ok(msg) => msg,
                // p2p-net fans messages out through a bounded broadcast channel.
                // Falling behind drops the oldest entries, which is exactly a
                // lost packet: the reliable layer retransmits and the input
                // stream is redundant, so keep going instead of ending the match.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                    self.lagged = self.lagged.saturating_add(missed);
                    continue;
                }
                Err(e @ tokio::sync::broadcast::error::RecvError::Closed) => return Err(net(e)),
            };
            if msg.source_peer_id != self.peer.to_string() {
                continue;
            }
            if msg.payload.is_empty() || msg.payload.len() > MAX_ENCRYPTED_PACKET {
                return Err(LiveError::BadFrame);
            }
            return Ok((msg.payload[0], msg.payload[1..].to_vec()));
        }
    }

    /// Hydra handshake. First encrypted game packet is retried until an
    /// authenticated delivery ACK is returned, closing the post-FINISH race.
    pub async fn handshake(&mut self, initiator: bool) -> Result<(), LiveError> {
        if initiator {
            let offer = self.hydra.init_handshake(self.contact).map_err(sec)?;
            self.raw_send(OFFER, offer.as_bytes()).await?;
            let (kind, answer) = self.raw_receive().await?;
            if kind != ANSWER {
                return Err(LiveError::BadFrame);
            }
            let finish = self.hydra.finish_handshake(answer).map_err(sec)?;
            self.raw_send(FINISH, finish.as_bytes()).await?;
            // A local FINISH publish does not mean Bob has processed it.
            // This authenticated, retransmitted barrier proves both sides
            // are actually ready before their first signed input commitment.
            self.send(READY_PING).await?;
            if self.recv().await? != READY_PONG {
                return Err(LiveError::Security(
                    "mismatched peer readiness response".into(),
                ));
            }
        } else {
            let (kind, offer) = self.raw_receive().await?;
            if kind != OFFER {
                return Err(LiveError::BadFrame);
            }
            let answer = self.hydra.reply_handshake(offer).map_err(sec)?;
            self.raw_send(ANSWER, answer.as_bytes()).await?;
            let (kind, finish) = self.raw_receive().await?;
            if kind != FINISH {
                return Err(LiveError::BadFrame);
            }
            self.hydra.accept_handshake_finish(finish).map_err(sec)?;
            if self.recv().await? != READY_PING {
                return Err(LiveError::Security(
                    "mismatched peer readiness request".into(),
                ));
            }
            self.send(READY_PONG).await?;
        }
        eprintln!("authenticated encrypted P2P delivery/ACK barrier complete");
        Ok(())
    }

    async fn encrypted_send(&mut self, frame: &DataFrame) -> Result<(), LiveError> {
        let bytes = frame.encode();
        if bytes.len() > MAX_ENCRYPTED_PACKET / 2 {
            return Err(LiveError::Oversize);
        }
        let mut plain = Vec::with_capacity(INNER_MAGIC.len() + 32 + bytes.len());
        plain.extend_from_slice(INNER_MAGIC);
        plain.extend_from_slice(&self.match_id);
        plain.extend_from_slice(&bytes);
        let timed = Instant::now();
        let packets = self
            .hydra
            .send(self.contact, HydraMessage::bytes(plain))
            .map_err(sec)?;
        let us = timed.elapsed().as_micros() as u64;
        self.hydra_send_max_us = self.hydra_send_max_us.max(us);
        self.hydra_slow_calls += u64::from(us > 100_000);
        self.prune_history();
        for packet in packets {
            self.raw_send(ENCRYPTED, packet.as_bytes()).await?;
        }
        Ok(())
    }

    /// Keep HYDRA's per-contact message history (and with it the state it
    /// rewrites on every call) from growing for the whole match.
    fn prune_history(&mut self) {
        self.hydra_ops += 1;
        if self.hydra_ops >= PRUNE_EVERY_OPS {
            self.hydra_ops = 0;
            let timed = Instant::now();
            let _ = self.hydra.clear_messages(self.contact);
            self.hydra_slow_calls += u64::from(timed.elapsed() > Duration::from_millis(100));
        }
    }

    async fn next_encrypted(&mut self) -> Result<DataFrame, LiveError> {
        loop {
            let (kind, packet) = self.raw_receive().await?;
            if kind != ENCRYPTED {
                // Handshake retransmissions or other foreign-phase packets may
                // race with gameplay; never treat them as accepted game input.
                eprintln!("game transport ignored stale pre-game frame: {kind}");
                continue;
            }
            let timed = Instant::now();
            let received = self.hydra.receive(packet);
            let us = timed.elapsed().as_micros() as u64;
            self.hydra_recv_max_us = self.hydra_recv_max_us.max(us);
            self.hydra_slow_calls += u64::from(us > 100_000);
            let Some(message) = received.map_err(sec)? else {
                continue;
            };
            self.prune_history();
            if message.from() != self.contact {
                return Err(LiveError::Security("unexpected Hydra sender".into()));
            }
            let plain = message.plaintext();
            let prefix = INNER_MAGIC.len() + 32;
            if plain.len() < prefix + FRAME_HEADER_BYTES
                || !plain.starts_with(INNER_MAGIC)
                || plain[INNER_MAGIC.len()..prefix] != self.match_id
            {
                return Err(LiveError::Security(
                    "wrong game match/session domain".into(),
                ));
            }
            return DataFrame::decode(&plain[prefix..]);
        }
    }

    /// Process an authenticated packet, even while waiting for a delivery
    /// receipt for the opposite direction. This prevents symmetric send
    /// deadlocks and makes re-sent frames idempotent.
    async fn ingest(&mut self, frame: DataFrame) -> Result<Option<u64>, LiveError> {
        if frame.kind == FRAME_ACK {
            return Ok(Some(frame.sequence));
        }
        match self.incoming.admit(frame.sequence, &frame.payload)? {
            Admission::Fresh | Admission::Duplicate => {
                let receipt = DataFrame {
                    kind: FRAME_ACK,
                    sequence: frame.sequence,
                    payload: Vec::new(),
                };
                // If an ACK publication temporarily fails, the sender will
                // retransmit and receive another ACK. The input remains queued.
                if let Err(err) = self.encrypted_send(&receipt).await {
                    eprintln!("transport ACK publication failed; awaiting retry: {err:?}");
                }
            }
            Admission::Future => {
                eprintln!(
                    "ignored out-of-order game frame sequence {}",
                    frame.sequence
                );
            }
        }
        Ok(None)
    }

    /// Wait for a remotely decrypted/authenticated ACK, retransmitting after
    /// lossy Gossipsub publishes. Local publish success is NOT delivery.
    pub async fn send(&mut self, bytes: &[u8]) -> Result<(), LiveError> {
        if bytes.len().saturating_add(FRAME_HEADER_BYTES) > MAX_ENCRYPTED_PACKET / 2 {
            return Err(LiveError::Oversize);
        }
        let seq = self.next_send;
        let frame = DataFrame {
            kind: FRAME_DATA,
            sequence: seq,
            payload: bytes.to_vec(),
        };
        let start = Instant::now();
        let mut retries = 0u32;
        while start.elapsed() < DELIVERY_TIMEOUT {
            if let Err(err) = self.encrypted_send(&frame).await {
                eprintln!("game frame {seq} local publication failed: {err:?}");
            }
            retries = retries.saturating_add(1);
            if retries == 1 || retries % 8 == 0 {
                eprintln!(
                    "game transport waiting for remote encrypted delivery ACK: seq={seq} publications={retries} peer={}",
                    self.peer
                );
            }
            let until = tokio::time::Instant::now() + RETRY_INTERVAL;
            while tokio::time::Instant::now() < until {
                let left = until.saturating_duration_since(tokio::time::Instant::now());
                match tokio::time::timeout(left, self.next_encrypted()).await {
                    Ok(Ok(remote)) => {
                        if self.ingest(remote).await? == Some(seq) {
                            self.next_send =
                                self.next_send.checked_add(1).ok_or(LiveError::BadFrame)?;
                            if retries > 1 {
                                eprintln!(
                                    "game frame {seq} delivered after {retries} publications"
                                );
                            } else {
                                self.last_ack_rtt = Some(start.elapsed());
                            }
                            return Ok(());
                        }
                    }
                    Ok(Err(err)) => return Err(err),
                    Err(_) => break,
                }
            }
        }
        eprintln!(
            "game transport delivery timed out: seq={seq} peer={} (local Gossipsub publication is not remote delivery)",
            self.peer
        );
        Err(LiveError::Timeout)
    }

    /// Receive exactly one in-order authenticated game packet. ACK and
    /// duplicate packets are never exposed to the game rules or replay engine.
    pub async fn recv(&mut self) -> Result<Vec<u8>, LiveError> {
        if let Some(payload) = self.incoming.pending.pop_front() {
            return Ok(payload);
        }
        loop {
            let frame = self.next_encrypted().await?;
            self.ingest(frame).await?;
            if let Some(payload) = self.incoming.pending.pop_front() {
                return Ok(payload);
            }
        }
    }

    /// Resolve once an in-order game packet is queued, without consuming it.
    /// Lets an idle player notice that the opponent opened a new epoch.
    pub async fn wait_incoming(&mut self) -> Result<(), LiveError> {
        while self.incoming.pending.is_empty() {
            let frame = self.next_encrypted().await?;
            self.ingest(frame).await?;
        }
        Ok(())
    }

    pub async fn shutdown(&self) {
        self.node.shutdown().await;
    }
}

/// Something the game hands to the session.
#[derive(Debug)]
pub enum Outgoing {
    /// Ordered, acknowledged, retransmitted. For the checkpoint pipeline.
    Reliable(Vec<u8>),
    /// Best effort, may be lost or reordered. For the 60 Hz input stream.
    Stream(Vec<u8>),
    Shutdown,
}

/// Something the session hands to the game.
#[derive(Debug)]
pub enum Incoming {
    Reliable(Vec<u8>),
    Stream(Vec<u8>),
    /// The session ended (peer unresponsive, transport closed).
    Closed(String),
}

/// Live counters for benchmarking; all updated by the session task.
#[derive(Default)]
pub struct SessionStats {
    pub stream_tx: AtomicU64,
    pub stream_rx: AtomicU64,
    pub stream_suppressed: AtomicU64,
    /// Provisional stream frames dropped because the application was not keeping up.
    pub stream_dropped: AtomicU64,
    pub reliable_tx: AtomicU64,
    pub reliable_retransmits: AtomicU64,
    pub reliable_rx: AtomicU64,
    pub bytes_tx: AtomicU64,
    pub bytes_rx: AtomicU64,
    pub bad_frames: AtomicU64,
    pub send_errors: AtomicU64,
    /// Messages dropped because the node's fan-out channel overflowed.
    pub lagged: AtomicU64,
    /// Time spent inside `encrypted_send` (Hydra + p2p-net publish), for tuning.
    pub send_count: AtomicU64,
    pub send_micros_total: AtomicU64,
    pub send_micros_max: AtomicU64,
    /// Longest time the session task went without servicing its inbox.
    pub loop_gap_micros_max: AtomicU64,
    pub hydra_send_max_micros: AtomicU64,
    pub hydra_recv_max_micros: AtomicU64,
    pub hydra_slow_calls: AtomicU64,
}

/// Non-blocking game transport. The caller never waits for the network: it
/// pushes `Outgoing` and drains `Incoming`; a background task owns Hydra and
/// the p2p-net node, ACKs, retransmits, and keeps the link healthy.
pub struct LiveSession {
    tx: mpsc::Sender<Outgoing>,
    pub rx: mpsc::Receiver<Incoming>,
    pub peer: PeerId,
    /// Round trip measured during the handshake (initiator only).
    pub rtt: Option<Duration>,
    pub stats: Arc<SessionStats>,
    task: tokio::task::JoinHandle<()>,
}

/// Cloneable handle for tasks that only need to send.
#[derive(Clone)]
pub struct SessionSender(mpsc::Sender<Outgoing>);

/// Why a send was not queued. `Full` is backpressure: keep the message and retry; a reliable
/// message is never dropped by the transport itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    Full,
    Closed,
}
fn queued(r: Result<(), mpsc::error::TrySendError<Outgoing>>) -> Result<(), SendError> {
    r.map_err(|e| match e {
        mpsc::error::TrySendError::Full(_) => SendError::Full,
        mpsc::error::TrySendError::Closed(_) => SendError::Closed,
    })
}
/// Commands waiting for the session task (backpressure beyond this).
pub const OUTGOING_CAPACITY: usize = 1024;
/// Events waiting for the application.
pub const INCOMING_CAPACITY: usize = 4096;
/// The session stops taking new reliable messages while this many are unacknowledged.
const MAX_IN_FLIGHT: usize = 1024;
/// The session stops reading the link while fewer event slots than this are free, so a slow
/// application pushes back on the peer (unacknowledged data is retransmitted, never lost).
const INCOMING_HEADROOM: usize = 512;

impl SessionSender {
    /// Queue a reliable message, or report `Full` so the caller keeps it (never discards).
    #[must_use = "Full means the message was NOT queued; keep it and retry"]
    pub fn send_reliable(&self, bytes: Vec<u8>) -> Result<(), SendError> {
        queued(self.0.try_send(Outgoing::Reliable(bytes)))
    }
    /// Queue a reliable message or hand it back when the queue is full (backpressure): the
    /// caller keeps the bytes and retries. This is the path for evidence and signed state.
    pub fn try_send_reliable(&self, bytes: Vec<u8>) -> Result<(), Vec<u8>> {
        match self.0.try_reserve() {
            Ok(permit) => {
                permit.send(Outgoing::Reliable(bytes));
                Ok(())
            }
            Err(_) => Err(bytes),
        }
    }
    /// Queue a provisional stream frame; `Full` means it was dropped (the next one supersedes it).
    pub fn send_stream(&self, bytes: Vec<u8>) -> Result<(), SendError> {
        queued(self.0.try_send(Outgoing::Stream(bytes)))
    }
}

impl LiveSession {
    pub fn sender(&self) -> SessionSender {
        SessionSender(self.tx.clone())
    }
    #[must_use = "Full means the message was NOT queued; keep it and retry"]
    pub fn send_reliable(&self, bytes: Vec<u8>) -> Result<(), SendError> {
        queued(self.tx.try_send(Outgoing::Reliable(bytes)))
    }
    pub fn send_stream(&self, bytes: Vec<u8>) -> Result<(), SendError> {
        queued(self.tx.try_send(Outgoing::Stream(bytes)))
    }
    pub async fn shutdown(self) {
        let _ = self.tx.send(Outgoing::Shutdown).await;
        let _ = self.task.await;
    }
}

/// A peer that has said nothing for this long is treated as unresponsive: the
/// stream and retransmissions fall back to a trickle so Hydra's bounded
/// out-of-order window is never exhausted by a dead link.
const SILENCE_BACKOFF: Duration = Duration::from_millis(1500);
const SILENT_STREAM_PERIOD: Duration = Duration::from_millis(500);
const PEER_DEAD_AFTER: Duration = Duration::from_secs(45);
/// On a local close: leave once everything sent is acknowledged and the peer has
/// been quiet this long, or after `DRAIN_MAX` regardless.
const DRAIN_QUIET: Duration = Duration::from_millis(1500);
const DRAIN_MAX: Duration = Duration::from_secs(10);

impl LiveLink {
    /// Hand the established, handshaken link to a background task.
    pub fn into_session(self) -> LiveSession {
        let (tx, cmds) = mpsc::channel(OUTGOING_CAPACITY);
        let (events, rx) = mpsc::channel(INCOMING_CAPACITY);
        let stats = Arc::new(SessionStats::default());
        let (peer, rtt) = (self.peer, self.last_ack_rtt);
        let task = tokio::spawn(session_task(self, cmds, events, Arc::clone(&stats)));
        LiveSession {
            tx,
            rx,
            peer,
            rtt,
            stats,
            task,
        }
    }
}

async fn timed_send(
    link: &mut LiveLink,
    frame: &DataFrame,
    stats: &SessionStats,
) -> Result<(), LiveError> {
    let started = Instant::now();
    let result = link.encrypted_send(frame).await;
    let us = started.elapsed().as_micros() as u64;
    stats.send_count.fetch_add(1, Ordering::Relaxed);
    stats.send_micros_total.fetch_add(us, Ordering::Relaxed);
    stats.send_micros_max.fetch_max(us, Ordering::Relaxed);
    result
}

/// One HYDRA message costs a fixed ~2 ms to encrypt and ~5 ms to decrypt, almost
/// regardless of size, so many small session frames are packed into one packet.
/// Entry: `kind u8 | sequence u64 | length u16 | payload`.
const BUNDLE_LIMIT: usize = 3_500;
const BUNDLE_ENTRY_HEADER: usize = 1 + 8 + 2;

fn bundle(frames: Vec<DataFrame>) -> Vec<DataFrame> {
    let mut out = Vec::new();
    let mut group: Vec<DataFrame> = Vec::new();
    let mut size = 0usize;
    let flush = |group: &mut Vec<DataFrame>, size: &mut usize, out: &mut Vec<DataFrame>| {
        match group.len() {
            0 => {}
            1 => out.append(group),
            _ => {
                let mut payload = Vec::with_capacity(*size);
                for f in group.drain(..) {
                    payload.push(f.kind);
                    payload.extend_from_slice(&f.sequence.to_le_bytes());
                    payload.extend_from_slice(&(f.payload.len() as u16).to_le_bytes());
                    payload.extend_from_slice(&f.payload);
                }
                out.push(DataFrame {
                    kind: FRAME_BUNDLE,
                    sequence: 0,
                    payload,
                });
            }
        }
        *size = 0;
    };
    for f in frames {
        let entry = BUNDLE_ENTRY_HEADER + f.payload.len();
        if entry > BUNDLE_LIMIT {
            // Too big to share a packet: it goes alone (HYDRA may split it).
            flush(&mut group, &mut size, &mut out);
            out.push(f);
            continue;
        }
        if size + entry > BUNDLE_LIMIT {
            flush(&mut group, &mut size, &mut out);
        }
        size += entry;
        group.push(f);
    }
    flush(&mut group, &mut size, &mut out);
    out
}

fn unbundle(payload: &[u8]) -> Option<Vec<DataFrame>> {
    let mut frames = Vec::new();
    let mut pos = 0usize;
    while pos < payload.len() {
        let header = payload.get(pos..pos + BUNDLE_ENTRY_HEADER)?;
        let kind = header[0];
        if !matches!(kind, FRAME_RDATA | FRAME_RACK | FRAME_STREAM) {
            return None;
        }
        let sequence = u64::from_le_bytes(header[1..9].try_into().ok()?);
        let len = u16::from_le_bytes([header[9], header[10]]) as usize;
        pos += BUNDLE_ENTRY_HEADER;
        let body = payload.get(pos..pos + len)?;
        if kind == FRAME_RACK && !body.is_empty() {
            return None;
        }
        frames.push(DataFrame {
            kind,
            sequence,
            payload: body.to_vec(),
        });
        pos += len;
        if frames.len() > 256 {
            return None;
        }
    }
    Some(frames)
}

struct Inbox<'a> {
    rel: &'a mut Reliable,
    events: &'a mpsc::Sender<Incoming>,
    /// Reliable payloads the application had no room for yet (bounded by the reliable window).
    held: &'a mut std::collections::VecDeque<Incoming>,
    stats: &'a SessionStats,
}
impl Inbox<'_> {
    fn dispatch(&mut self, f: DataFrame) {
        match f.kind {
            FRAME_RDATA => {
                for payload in self.rel.on_data(f.sequence, f.payload) {
                    self.stats.reliable_rx.fetch_add(1, Ordering::Relaxed);
                    let item = Incoming::Reliable(payload);
                    if self.held.is_empty() {
                        if let Err(e) = self.events.try_send(item) {
                            self.held.push_back(e.into_inner()); // reliable: never discarded
                        }
                    } else {
                        self.held.push_back(item);
                    }
                }
            }
            FRAME_RACK => self.rel.on_ack(f.sequence, Instant::now()),
            FRAME_STREAM => {
                self.stats.stream_rx.fetch_add(1, Ordering::Relaxed);
                // Provisional and superseded by the next frame: the one explicitly disposable path.
                if self.events.try_send(Incoming::Stream(f.payload)).is_err() {
                    self.stats.stream_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            FRAME_BUNDLE => match unbundle(&f.payload) {
                Some(frames) => frames.into_iter().for_each(|inner| self.dispatch(inner)),
                None => {
                    self.stats.bad_frames.fetch_add(1, Ordering::Relaxed);
                }
            },
            _ => {}
        }
    }
}

async fn session_task(
    mut link: LiveLink,
    mut cmds: mpsc::Receiver<Outgoing>,
    events: mpsc::Sender<Incoming>,
    stats: Arc<SessionStats>,
) {
    let mut rel = Reliable::new();
    let mut timer = tokio::time::interval(Duration::from_millis(15));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_rx = Instant::now();
    let mut last_stream_tx: Option<Instant> = None;
    let mut staged: Vec<DataFrame> = Vec::new();
    let mut shutdown = false;
    let mut draining: Option<Instant> = None;
    let mut held: std::collections::VecDeque<Incoming> = std::collections::VecDeque::new();
    // Queue one command; returns true if it asked us to stop.
    let stage = |cmd: Outgoing,
                 rel: &mut Reliable,
                 staged: &mut Vec<DataFrame>,
                 last_rx: Instant,
                 last_stream_tx: &mut Option<Instant>|
     -> bool {
        match cmd {
            Outgoing::Reliable(bytes) => {
                // First transmission only; retransmits are counted separately.
                stats
                    .bytes_tx
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                rel.queue(bytes);
            }
            Outgoing::Stream(bytes) => {
                let quiet = last_rx.elapsed() > SILENCE_BACKOFF;
                if quiet && last_stream_tx.is_some_and(|t| t.elapsed() < SILENT_STREAM_PERIOD) {
                    stats.stream_suppressed.fetch_add(1, Ordering::Relaxed);
                } else {
                    stats
                        .bytes_tx
                        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                    stats.stream_tx.fetch_add(1, Ordering::Relaxed);
                    *last_stream_tx = Some(Instant::now());
                    staged.push(DataFrame {
                        kind: FRAME_STREAM,
                        sequence: 0,
                        payload: bytes,
                    });
                }
            }
            Outgoing::Shutdown => return true,
        }
        false
    };
    let reason = loop {
        tokio::select! {
            biased;
            cmd = cmds.recv(), if !shutdown && rel.in_flight() < MAX_IN_FLIGHT => match cmd {
                Some(cmd) => {
                    shutdown |= stage(cmd, &mut rel, &mut staged, last_rx, &mut last_stream_tx);
                }
                None => shutdown = true,
            },
            frame = link.next_encrypted(), if draining.is_some() || (held.is_empty() && events.capacity() >= INCOMING_HEADROOM) => match frame {
                Ok(f) => {
                    last_rx = Instant::now();
                    stats.bytes_rx.fetch_add(f.payload.len() as u64, Ordering::Relaxed);
                    Inbox { rel: &mut rel, events: &events, held: &mut held, stats: &stats }.dispatch(f);
                }
                // A transport that is gone for good ends the session; a bad or
                // undecryptable packet is counted and skipped.
                Err(LiveError::Transport(e)) => break format!("transport closed: {e}"),
                Err(_) => {
                    stats.bad_frames.fetch_add(1, Ordering::Relaxed);
                }
            },
            _ = timer.tick() => {}
        }
        // Everything already waiting goes out together in as few packets as fit.
        while let Some(item) = held.pop_front() {
            if let Err(e) = events.try_send(item) {
                held.push_front(e.into_inner());
                break;
            }
        }
        while !shutdown && rel.in_flight() < MAX_IN_FLIGHT {
            let Ok(cmd) = cmds.try_recv() else { break };
            shutdown |= stage(cmd, &mut rel, &mut staged, last_rx, &mut last_stream_tx);
        }
        // A local close drains first: what this side already sent must still be
        // acknowledged, and the peer's trailing frames acknowledged in turn, or a
        // peer that is still finishing waits on a link that vanished under it.
        // Nothing is delivered to the application any more while draining.
        if shutdown {
            let started = *draining.get_or_insert_with(Instant::now);
            held.clear();
            if (rel.in_flight() == 0 && last_rx.elapsed() >= DRAIN_QUIET)
                || started.elapsed() >= DRAIN_MAX
            {
                break "session closed locally".to_string();
            }
        }
        // Everything from here to the next `select!` is time the inbox is not
        // being read; its worst case explains broadcast-channel lag.
        let work_started = Instant::now();
        stats.lagged.store(link.lagged, Ordering::Relaxed);
        stats
            .hydra_send_max_micros
            .store(link.hydra_send_max_us, Ordering::Relaxed);
        stats
            .hydra_recv_max_micros
            .store(link.hydra_recv_max_us, Ordering::Relaxed);
        stats
            .hydra_slow_calls
            .store(link.hydra_slow_calls, Ordering::Relaxed);
        let now = Instant::now();
        let backoff = last_rx.elapsed() > SILENCE_BACKOFF;
        for (seq, payload) in rel.poll_transmit(now, backoff) {
            stats.reliable_tx.fetch_add(1, Ordering::Relaxed);
            staged.push(DataFrame {
                kind: FRAME_RDATA,
                sequence: seq,
                payload,
            });
        }
        stats
            .reliable_retransmits
            .store(rel.retransmissions, Ordering::Relaxed);
        if let Some(next) = rel.take_ack() {
            staged.push(DataFrame {
                kind: FRAME_RACK,
                sequence: next,
                payload: Vec::new(),
            });
        }
        for frame in bundle(std::mem::take(&mut staged)) {
            if timed_send(&mut link, &frame, &stats).await.is_err() {
                stats.send_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        stats
            .loop_gap_micros_max
            .fetch_max(work_started.elapsed().as_micros() as u64, Ordering::Relaxed);
        if rel
            .oldest_outstanding(now)
            .is_some_and(|age| age > PEER_DEAD_AFTER)
        {
            break "peer unresponsive".to_string();
        }
    };
    let _ = events.send(Incoming::Closed(reason)).await;
    link.shutdown().await;
}

pub fn parse_peer(peer: &str) -> Result<PeerId, LiveError> {
    PeerId::from_str(peer).map_err(net)
}
pub fn parse_multiaddr(addr: &str) -> Result<Multiaddr, LiveError> {
    Multiaddr::from_str(addr).map_err(net)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        bundle, unbundle, Admission, DataFrame, ReceiveWindow, FRAME_ACK, FRAME_BUNDLE, FRAME_DATA,
        FRAME_RACK, FRAME_RDATA, FRAME_STREAM,
    };

    #[test]
    fn slow_application_never_loses_reliable_payloads_and_only_drops_stream_frames() {
        use super::{Inbox, Incoming, SessionStats};
        use crate::reliable::Reliable;
        use std::collections::VecDeque;
        use std::sync::atomic::Ordering;
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Incoming>(2);
        let mut rel = Reliable::new();
        let mut held = VecDeque::new();
        let stats = SessionStats::default();
        for seq in 0..50u64 {
            let mut inbox = Inbox {
                rel: &mut rel,
                events: &tx,
                held: &mut held,
                stats: &stats,
            };
            inbox.dispatch(DataFrame {
                kind: FRAME_RDATA,
                sequence: seq,
                payload: vec![seq as u8],
            });
            inbox.dispatch(DataFrame {
                kind: FRAME_STREAM,
                sequence: 0,
                payload: vec![0xEE],
            });
        }
        assert!(held.len() >= 40, "reliable payloads wait, none discarded");
        assert!(stats.stream_dropped.load(Ordering::Relaxed) > 0);
        let mut got = Vec::new();
        loop {
            while let Ok(v) = rx.try_recv() {
                if let Incoming::Reliable(b) = v {
                    got.push(b[0]);
                }
            }
            match held.pop_front() {
                Some(i) => {
                    let _ = tx.try_send(i);
                }
                None => break,
            }
        }
        while let Ok(v) = rx.try_recv() {
            if let Incoming::Reliable(b) = v {
                got.push(b[0]);
            }
        }
        assert_eq!(got, (0..50u8).collect::<Vec<_>>(), "all 50, in order");
    }

    #[test]
    fn authenticated_frame_rejects_noncanonical_ack() {
        let frame = DataFrame {
            kind: FRAME_DATA,
            sequence: 3,
            payload: vec![9, 10],
        };
        assert_eq!(DataFrame::decode(&frame.encode()).unwrap(), frame);
        assert!(DataFrame::decode(&[FRAME_ACK, 0, 0, 0]).is_err());
        let mut extra_ack = DataFrame {
            kind: FRAME_ACK,
            sequence: 3,
            payload: vec![99],
        };
        assert!(DataFrame::decode(&extra_ack.encode()).is_err());
        extra_ack.payload.clear();
        assert_eq!(DataFrame::decode(&extra_ack.encode()).unwrap(), extra_ack);
    }

    #[test]
    fn lost_packet_and_lost_receipt_do_not_duplicate_game_actions() {
        let payload = b"signed-commit";
        let mut receiver = ReceiveWindow::default();
        // Publication 1 is lost before it reaches the receiver.
        // Publication 2 arrives but the corresponding ACK is lost.
        assert!(matches!(
            receiver.admit(0, payload).unwrap(),
            Admission::Fresh
        ));
        // Publication 3 is another encrypted envelope with the same
        // authenticated application sequence. Only a new receipt is needed.
        assert!(matches!(
            receiver.admit(0, payload).unwrap(),
            Admission::Duplicate
        ));
        assert_eq!(receiver.pending.len(), 1);
        assert_eq!(receiver.pending.pop_front().unwrap(), payload);
        assert!(receiver.pending.is_empty());
    }

    #[test]
    fn retransmitted_inputs_are_delivered_once_and_future_packets_rejected() {
        let mut r = ReceiveWindow::default();
        assert!(matches!(r.admit(1, b"next").unwrap(), Admission::Future));
        assert!(r.pending.is_empty());
        assert!(matches!(r.admit(0, b"commit").unwrap(), Admission::Fresh));
        assert!(matches!(
            r.admit(0, b"commit").unwrap(),
            Admission::Duplicate
        ));
        assert_eq!(r.pending.pop_front().unwrap(), b"commit");
        assert!(r.pending.is_empty());
        assert!(matches!(r.admit(1, b"lock").unwrap(), Admission::Fresh));
        assert_eq!(r.pending.pop_front().unwrap(), b"lock");
    }

    fn frame(kind: u8, seq: u64, n: usize) -> DataFrame {
        DataFrame {
            kind,
            sequence: seq,
            payload: vec![seq as u8; n],
        }
    }

    #[test]
    fn small_frames_share_one_packet_and_unpack_in_order() {
        let frames: Vec<_> = (0..15u64)
            .map(|i| frame(FRAME_RDATA, i, 210))
            .chain([frame(FRAME_STREAM, 0, 40), frame(FRAME_RACK, 9, 0)])
            .collect();
        let packed = bundle(frames.clone());
        assert_eq!(
            packed.len(),
            1,
            "15 reveals + stream + ack share ONE packet"
        );
        assert!(packed.iter().all(|p| p.kind == FRAME_BUNDLE));
        let mut back = Vec::new();
        for p in &packed {
            assert!(p.encode().len() <= 3_600);
            back.extend(unbundle(&p.payload).unwrap());
        }
        assert_eq!(back, frames);
        // More than fits splits into several, still in order.
        let many: Vec<_> = (0..40u64).map(|i| frame(FRAME_RDATA, i, 210)).collect();
        let packed = bundle(many.clone());
        assert!(packed.len() >= 3 && packed.iter().all(|p| p.encode().len() <= 3_600));
        let back: Vec<_> = packed
            .iter()
            .flat_map(|p| unbundle(&p.payload).unwrap())
            .collect();
        assert_eq!(back, many);
    }

    #[test]
    fn a_single_frame_is_not_wrapped_and_a_huge_one_goes_alone() {
        let one = bundle(vec![frame(FRAME_RDATA, 1, 100)]);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].kind, FRAME_RDATA);
        let mixed = bundle(vec![
            frame(FRAME_RDATA, 1, 100),
            frame(FRAME_RDATA, 2, 9_000),
            frame(FRAME_RDATA, 3, 100),
        ]);
        assert_eq!(mixed.len(), 3, "the oversized frame breaks the bundle");
        assert_eq!(mixed[1].payload.len(), 9_000);
    }

    #[test]
    fn malformed_bundles_are_rejected_not_panicked_on() {
        assert!(unbundle(&[FRAME_RDATA, 0, 0]).is_none(), "truncated header");
        let mut p = vec![FRAME_RDATA];
        p.extend_from_slice(&1u64.to_le_bytes());
        p.extend_from_slice(&50u16.to_le_bytes());
        p.extend_from_slice(&[0; 10]);
        assert!(unbundle(&p).is_none(), "length past the end");
        let mut nested = vec![FRAME_BUNDLE];
        nested.extend_from_slice(&0u64.to_le_bytes());
        nested.extend_from_slice(&0u16.to_le_bytes());
        assert!(unbundle(&nested).is_none(), "bundles do not nest");
        let mut bad_ack = vec![FRAME_RACK];
        bad_ack.extend_from_slice(&1u64.to_le_bytes());
        bad_ack.extend_from_slice(&1u16.to_le_bytes());
        bad_ack.push(7);
        assert!(unbundle(&bad_ack).is_none(), "acks carry no payload");
        assert_eq!(unbundle(&[]).unwrap().len(), 0);
    }
}
