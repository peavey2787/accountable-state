//! Real-network witness links: one authenticated, encrypted `p2p-net` + Hydra link per
//! (player, witness) pair, supervised so a dropped or restarted peer is re-dialled, plus the
//! player-side hub and the witness process loop. Witness traffic runs in its own tasks and
//! never touches the 60 Hz simulation thread.
use gv_core::{Digest, MatchId, PlayerId};
use gv_edge::audit::Evidence;
use gv_edge::witness::{Event, Msg, Remote, WitnessNode};
use gv_edge::{live::PipeMsg, ArenaRules};
use gv_p2p::native::{parse_multiaddr, Incoming, LiveLink};
use gv_sig::SigningKey;
use p2p_net::NodeConfig;
use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::sync::mpsc::{self, Receiver, Sender};

const CHANNEL_BOUND: usize = 512;
/// Link events waiting for the hub/witness loop; a full queue stalls the link task, which stops
/// reading the transport (so the sender's reliable layer retransmits instead of us losing data).
const NET_EVENTS: usize = 4096;
/// Messages from the player hub to the local pipeline awaiting room.
const PIPE_BOUND: usize = 1024;
const HUB_IN_BOUND: usize = 4096;
/// Witness frames refused by a full link queue. They are not lost evidence: every item stays in
/// the node's store and is re-offered by the periodic inventory exchange.
pub static FRAMES_DEFERRED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
fn offer(session: &gv_p2p::native::LiveSession, b: Vec<u8>) {
    if session.send_reliable(b).is_err() {
        FRAMES_DEFERRED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
const SILENCE_RECYCLE: Duration = Duration::from_secs(10);
const RECONNECT_BACKOFF: Duration = Duration::from_millis(1500);

#[derive(Clone, Debug)]
pub struct LinkSpec {
    pub cfg: String,
    pub hydra: String,
    pub card: String,
    /// Pinned `GV-PUBKEY/V1` of the remote (player for a witness, witness for a player).
    pub peer_pub: String,
    /// Witness side: file holding the player's dial address. Player side: file it writes.
    pub addr_file: String,
}

/// `cfg,hydra-dir,peer-card,peer.pub,addr-file`
pub fn parse_link(s: &str) -> Result<LinkSpec, String> {
    let p: Vec<&str> = s.split(',').collect();
    if p.len() != 5 {
        return Err("link spec: cfg,hydra-dir,peer-card,peer.pub,addr-file".into());
    }
    Ok(LinkSpec {
        cfg: p[0].into(),
        hydra: p[1].into(),
        card: p[2].into(),
        peer_pub: p[3].into(),
        addr_file: p[4].into(),
    })
}

#[derive(Debug)]
pub enum NetEvent {
    Up(u32),
    Down(u32),
    Msg(u32, Vec<u8>),
}

/// Hostile-network emulation on top of the real transport, from `GV_FAULTS`
/// (`loss=P,dup=P,delay=MS,jitter=MS,seed=N`, P in 0..1). Applied per link to both directions,
/// so loss, duplication, delay and (through jitter) reordering hit the witness protocol itself.
#[derive(Clone, Copy, Debug, Default)]
struct FaultCfg {
    loss: f64,
    dup: f64,
    delay_ms: u64,
    jitter_ms: u64,
    seed: u64,
}

impl FaultCfg {
    fn from_env() -> Option<Self> {
        let v = std::env::var("GV_FAULTS").ok()?;
        let mut c = FaultCfg {
            seed: 1,
            ..Default::default()
        };
        for kv in v.split(',') {
            let (k, x) = kv.split_once('=')?;
            match k {
                "loss" => c.loss = x.parse().ok()?,
                "dup" => c.dup = x.parse().ok()?,
                "delay" => c.delay_ms = x.parse().ok()?,
                "jitter" => c.jitter_ms = x.parse().ok()?,
                "seed" => c.seed = x.parse().ok()?,
                _ => return None,
            }
        }
        Some(c)
    }
}

struct Shaper {
    cfg: Option<FaultCfg>,
    rng: u64,
    queue: Vec<(Instant, Vec<u8>)>,
}

impl Shaper {
    fn new(cfg: Option<FaultCfg>, salt: u64) -> Self {
        let seed = cfg.map(|c| c.seed).unwrap_or(1);
        Self {
            cfg,
            rng: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ salt | 1,
            queue: Vec::new(),
        }
    }
    fn rand(&mut self) -> f64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        (self.rng >> 11) as f64 / (1u64 << 53) as f64
    }
    /// Queue a message; returns it immediately when no emulation is configured.
    fn push(&mut self, b: Vec<u8>) -> Option<Vec<u8>> {
        let Some(c) = self.cfg else { return Some(b) };
        if self.rand() < c.loss {
            return None;
        }
        let copies = if self.rand() < c.dup { 2 } else { 1 };
        for _ in 0..copies {
            let d = c.delay_ms + (self.rand() * c.jitter_ms as f64) as u64;
            self.queue
                .push((Instant::now() + Duration::from_millis(d), b.clone()));
        }
        None
    }
    fn due(&mut self) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.queue.len() {
            if self.queue[i].0 <= now {
                out.push(self.queue.swap_remove(i).1);
            } else {
                i += 1;
            }
        }
        out
    }
}

fn password() -> Result<String, String> {
    std::env::var("GV_HYDRA_PASSWORD").map_err(|_| "set GV_HYDRA_PASSWORD".to_string())
}

/// Dial/handshake/serve loop for one link; re-dials on any failure. `initiator` (the witness)
/// dials the address in `addr_file`; the responder (the player) announces its own.
pub fn spawn_link(
    id: u32,
    spec: LinkSpec,
    initiator: bool,
    match_id: MatchId,
    events: Sender<NetEvent>,
) -> mpsc::Sender<Vec<u8>> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(CHANNEL_BOUND);
    tokio::spawn(async move {
        loop {
            match serve_once(id, &spec, initiator, match_id, &events, &mut rx).await {
                Ok(()) => {}
                Err(e) => eprintln!("witness link {id}: {e}"),
            }
            let _ = events.send(NetEvent::Down(id)).await;
            while rx.try_recv().is_ok() {} // stale frames are never replayed after a reconnect
            tokio::time::sleep(RECONNECT_BACKOFF).await;
        }
    });
    tx
}

async fn serve_once(
    id: u32,
    spec: &LinkSpec,
    initiator: bool,
    match_id: MatchId,
    events: &Sender<NetEvent>,
    rx: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<(), String> {
    let config = NodeConfig::load_json_file(&spec.cfg).map_err(|e| e.to_string())?;
    let card = fs::read(&spec.card).map_err(|e| e.to_string())?;
    let dial = if initiator {
        let started = Instant::now();
        let addr = loop {
            if let Ok(a) = fs::read_to_string(&spec.addr_file) {
                if !a.trim().is_empty() {
                    break a;
                }
            }
            if started.elapsed() > Duration::from_secs(60) {
                return Err("peer address never appeared".into());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        Some(parse_multiaddr(addr.trim()).map_err(|e| format!("{e:?}"))?)
    } else {
        None
    };
    let announce = (!initiator).then(|| PathBuf::from(&spec.addr_file));
    // Both ends of a link must agree on the topic, so it is named after the shared address
    // file, never after the (per-process) link index.
    let channel = Path::new(&spec.addr_file)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| format!("w{id}"));
    let mut link = LiveLink::start_on(
        config,
        Path::new(&spec.hydra),
        &password()?,
        &card,
        match_id,
        None,
        dial,
        &channel,
        announce.as_deref(),
    )
    .await
    .map_err(|e| format!("start: {e:?}"))?;
    tokio::time::timeout(Duration::from_secs(60), link.handshake(initiator))
        .await
        .map_err(|_| "handshake timed out".to_string())?
        .map_err(|e| format!("handshake: {e:?}"))?;
    let mut session = link.into_session();
    let _ = events.send(NetEvent::Up(id)).await;
    let mut last_rx = Instant::now();
    let mut watchdog = tokio::time::interval(Duration::from_secs(1));
    let faults = FaultCfg::from_env();
    let mut shape_out = Shaper::new(faults, u64::from(id) * 2 + 1);
    let mut shape_in = Shaper::new(faults, u64::from(id) * 2 + 2);
    let mut shape_tick = tokio::time::interval(Duration::from_millis(10));
    loop {
        tokio::select! {
            _ = shape_tick.tick(), if faults.is_some() => {
                for b in shape_out.due() { offer(&session, b); }
                for b in shape_in.due() { let _ = events.send(NetEvent::Msg(id, b)).await; }
            }
            _ = watchdog.tick() => {
                // Both sides send something at least once a second on a healthy link (inventory
                // or Hello retries), so prolonged silence means the peer restarted or vanished.
                if last_rx.elapsed() > SILENCE_RECYCLE {
                    session.shutdown().await;
                    return Err("peer silent; recycling the link".into());
                }
            }
            out = rx.recv() => match out {
                Some(b) => if let Some(b) = shape_out.push(b) { offer(&session, b) },
                None => break,
            },
            inc = session.rx.recv() => match inc {
                Some(Incoming::Reliable(b)) | Some(Incoming::Stream(b)) => {
                    last_rx = Instant::now();
                    if let Some(b) = shape_in.push(b) { let _ = events.send(NetEvent::Msg(id, b)).await; }
                }
                Some(Incoming::Closed(why)) => { session.shutdown().await; return Err(format!("closed: {why}")); }
                None => break,
            },
        }
    }
    session.shutdown().await;
    Ok(())
}

fn now_ms(start: &Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ------------------------------------------------------------------- player hub

/// Input to the player-side hub from the (separate) accountability task.
pub enum HubIn {
    Auth(gv_edge::audit::Authenticator),
    Evidence(Vec<u8>),
    Package(Vec<u8>),
    Response(gv_edge::audit::Response),
}

/// Starts the player-side hub. `pipe_in` receives witness challenges for the local auditor.
pub fn spawn_player_hub(
    key: SigningKey,
    roster: [PlayerId; 2],
    match_id: MatchId,
    witness_ids: Vec<PlayerId>,
    specs: Vec<LinkSpec>,
    pipe_in: Sender<PipeMsg>,
) -> Sender<HubIn> {
    let (tx, rx) = mpsc::channel(HUB_IN_BOUND);
    tokio::spawn(hub_loop(
        key,
        roster,
        match_id,
        witness_ids,
        specs,
        rx,
        pipe_in,
    ));
    tx
}

async fn hub_loop(
    key: SigningKey,
    roster: [PlayerId; 2],
    match_id: MatchId,
    witness_ids: Vec<PlayerId>,
    specs: Vec<LinkSpec>,
    mut hub_rx: Receiver<HubIn>,
    pipe_in: Sender<PipeMsg>,
) {
    let rules = ArenaRules::new(roster);
    let mut node = WitnessNode::new(key, match_id, roster, &witness_ids, rules);
    let (ev_tx, mut ev_rx) = mpsc::channel(NET_EVENTS);
    let start = Instant::now();
    let mut senders: BTreeMap<u32, mpsc::Sender<Vec<u8>>> = BTreeMap::new();
    for (i, s) in specs.into_iter().enumerate() {
        let id = i as u32;
        node.open_link(id, Remote::AnyWitness, 0);
        senders.insert(id, spawn_link(id, s, false, match_id, ev_tx.clone()));
    }
    let mut route: BTreeMap<Digest, u32> = BTreeMap::new();
    // To the local pipeline: challenges are re-sent by their witness and anchors re-requested
    // by the auditor, so a refused one is deferred in a small holdback, never an unbounded queue.
    let mut to_pipe = crate::bounded::Outbox::new(pipe_in, PIPE_BOUND);
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    loop {
        tokio::select! {
            _ = tick.tick() => { node.tick(now_ms(&start)); to_pipe.flush(); }
            Some(ev) = ev_rx.recv() => match ev {
                NetEvent::Up(id) => node.open_link(id, Remote::AnyWitness, now_ms(&start)),
                NetEvent::Down(id) => node.link_down(id),
                NetEvent::Msg(id, b) => node.on_message(id, &b, now_ms(&start)),
            },
            Some(inp) = hub_rx.recv() => match inp {
                HubIn::Auth(a) => node.submit_auth(&a, None),
                HubIn::Evidence(b) => { if let Ok(e) = Evidence::decode(&b) { node.submit_evidence(&e, None) } }
                HubIn::Package(b) => node.submit_package(&b, None),
                HubIn::Response(r) => {
                    if let Some(link) = route.remove(&r.challenge_id) {
                        node.send_response(link, &r);
                    }
                }
            },
            else => break,
        }
        while let Some((link, bytes)) = node.poll_out() {
            if let Some(s) = senders.get(&link) {
                let _ = s.try_send(bytes); // bounded and non-blocking: a slow witness loses frames
            }
        }
        while let Some(e) = node.poll_event() {
            match e {
                Event::ChallengeForPlayer { link, challenge } => {
                    if route.len() < 256 {
                        route.insert(challenge.id(), link);
                    }
                    let _ = to_pipe.push(PipeMsg::Challenge(challenge)); // a refused challenge is re-sent by its witness
                }
                Event::OwnHead(a) => {
                    to_pipe.push_or_replace(PipeMsg::Anchor(Some(a)), |q, n| matches!((q, n), (PipeMsg::Anchor(Some(x)), PipeMsg::Anchor(Some(y))) if x.owner == y.owner && y.seq >= x.seq));
                }
                Event::Verified { id, accused, kind } => println!(
                    "WITNESS-HUB verified {kind} evidence {} against {}",
                    hex(&id),
                    hex(&accused)
                ),
                Event::Admitted { link, peer } => {
                    println!("WITNESS-HUB admitted witness {} on link {link}", hex(&peer));
                }
                Event::Rejected { link } => {
                    println!("WITNESS-HUB rejected an item from link {link}")
                }
                Event::Blocked { link } => {
                    println!("WITNESS-HUB blocked link {link} after repeated invalid input")
                }
                _ => {}
            }
        }
    }
}

// ----------------------------------------------------------------- witness process

pub struct WitnessConfig {
    pub name: String,
    pub key: SigningKey,
    pub roster: [PlayerId; 2],
    pub match_id: MatchId,
    pub links: Vec<(LinkSpec, PlayerId)>,
    pub out_dir: PathBuf,
    pub run_secs: u64,
    /// Adversary: periodically push forged and replayed evidence to every player link.
    pub malicious: bool,
    /// Ask each player for a log segment this often (ms); 0 disables auditing.
    pub audit_every_ms: u64,
}

/// Run a witness until `run_secs` elapse. Prints one line per independently verified item.
pub async fn run_witness(cfg: WitnessConfig) -> Result<(), String> {
    let rules = ArenaRules::new(cfg.roster);
    let me = cfg.key.id();
    let mut node = WitnessNode::new(cfg.key.clone(), cfg.match_id, cfg.roster, &[me], rules);
    let (ev_tx, mut ev_rx) = mpsc::channel(NET_EVENTS);
    let start = Instant::now();
    let mut senders: BTreeMap<u32, mpsc::Sender<Vec<u8>>> = BTreeMap::new();
    let mut players: BTreeMap<u32, PlayerId> = BTreeMap::new();
    for (i, (spec, player)) in cfg.links.iter().enumerate() {
        let id = i as u32;
        node.open_link(id, Remote::Player(*player), 0);
        players.insert(id, *player);
        senders.insert(
            id,
            spawn_link(id, spec.clone(), true, cfg.match_id, ev_tx.clone()),
        );
    }
    fs::create_dir_all(&cfg.out_dir).map_err(|e| e.to_string())?;
    let (mut ledger_file, recovered) =
        gv_edge::audit::store::RecordFile::open(&cfg.out_dir.join("witness.evidence"))
            .map_err(|e| e.to_string())?;
    for rec in &recovered {
        // Persisted items are re-verified on restart; nothing is trusted from disk.
        if let Ok(e) = Evidence::decode(rec) {
            node.submit_evidence(&e, None);
        }
    }
    println!(
        "WITNESS {} started; {} persisted item(s) re-verified",
        cfg.name,
        node.item_ids().len()
    );
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let mut last_audit = 0u64;
    let mut last_attack = 0u64;
    let mut stats_at = 0u64;
    let deadline = Instant::now() + Duration::from_secs(cfg.run_secs);
    while Instant::now() < deadline {
        tokio::select! {
            _ = tick.tick() => {
                let now = now_ms(&start);
                node.tick(now);
                if cfg.audit_every_ms > 0 && now >= last_audit + cfg.audit_every_ms {
                    last_audit = now;
                    for (link, player) in &players {
                        if node.is_admitted(*link) {
                            let _ = node.audit_player(*link, *player, now);
                        }
                    }
                }
                if cfg.malicious && now >= last_attack + 2000 {
                    last_attack = now;
                    attack(&mut node, &cfg, &players);
                }
                if now >= stats_at + 5000 {
                    stats_at = now;
                    let s = node.stats();
                    println!("WITNESS {} stats verified={} rejected={} dup={} auths={} dropped_unadmitted={} dropped_rate={}", cfg.name, s.verified, s.rejected, s.duplicates, s.auths_stored, s.dropped_unadmitted, s.dropped_rate);
                }
            }
            Some(ev) = ev_rx.recv() => {
                let now = now_ms(&start);
                match ev {
                    NetEvent::Up(id) => { println!("WITNESS {} link {id} up", cfg.name); node.open_link(id, Remote::Player(players[&id]), now) }
                    NetEvent::Down(id) => { println!("WITNESS {} link {id} down", cfg.name); node.link_down(id) }
                    NetEvent::Msg(id, b) => node.on_message(id, &b, now),
                }
            }
        }
        while let Some((link, bytes)) = node.poll_out() {
            if let Some(s) = senders.get(&link) {
                let _ = s.try_send(bytes);
            }
        }
        while let Some(e) = node.poll_event() {
            match e {
                Event::Verified { id, accused, kind } => {
                    println!(
                        "WITNESS {} VERIFIED {kind} evidence {} against {} at {} ms",
                        cfg.name,
                        hex(&id),
                        hex(&accused),
                        now_ms(&start)
                    );
                    if let Some(bytes) = node.item_bytes(&id) {
                        let _ = ledger_file.append(&bytes);
                        let _ = fs::write(cfg.out_dir.join(format!("{}.item", hex(&id))), bytes);
                    }
                }
                Event::Admitted { link, peer } => println!(
                    "WITNESS {} admitted by player {} on link {link}",
                    cfg.name,
                    hex(&peer)
                ),
                Event::Rejected { link } => {
                    println!("WITNESS {} rejected an item from link {link}", cfg.name)
                }
                Event::Blocked { link } => println!(
                    "WITNESS {} blocked link {link} after repeated invalid input",
                    cfg.name
                ),
                Event::Challenge { status, .. } => {
                    println!("WITNESS {} challenge status {}", cfg.name, status.name())
                }
                _ => {}
            }
        }
    }
    let s = node.stats();
    println!(
        "WITNESS {} done: verified={} proven_against={:?} rejected={} duplicates={}",
        cfg.name,
        s.verified,
        node.ledger().ids().len(),
        s.rejected,
        s.duplicates
    );
    Ok(())
}

/// A malicious witness: tamper with genuine evidence, relabel signatures, replay junk.
fn attack(
    node: &mut WitnessNode<ArenaRules>,
    cfg: &WitnessConfig,
    players: &BTreeMap<u32, PlayerId>,
) {
    let mut junk: VecDeque<Vec<u8>> = VecDeque::new();
    if let Some(a) = node.latest_auth(&cfg.roster[0]).cloned() {
        // A forged "conflicting" head under the victim's name: the signature cannot verify.
        let mut forged = a.clone();
        forged.head[0] ^= 1;
        let ev = Evidence::ConflictingAuthenticators(a, forged);
        junk.push_back(Msg::Evidence(Box::new(ev)).encode());
    }
    junk.push_back(b"GV-WITNESS/V1\0\x06\x04\0\0\0garbage".to_vec());
    // An oversized record (inside the transport cap, far beyond any legitimate message body).
    let mut big = b"GV-WITNESS/V1\0\x04".to_vec();
    big.resize(300_000, 0xAB);
    junk.push_back(big);
    for link in players.keys() {
        for j in &junk {
            node.inject_raw(*link, j);
        }
    }
}
