//! Third-party witness propagation (`GV-WITNESS/V1`), transport independent.
//!
//! A [`WitnessNode`] runs in a witness process (or beside a player). It owns *links* to
//! pinned peers (each link is an authenticated, encrypted `p2p-net` + Hydra channel provided by
//! the host) and implements: signed admission, authenticator distribution, evidence inventories,
//! missing-evidence retrieval, bounded anti-entropy, challenge routing and independent
//! verification. Witnesses are never gameplay authorities and are not trusted: every item is
//! verified from its own signatures, so relaying cannot frame anyone and a lying witness cannot
//! forge a verdict. Nothing here blocks: calls are bounded and return queued outputs.
use crate::audit::challenge::{ChallengeBook, Status, Timing};
use crate::audit::{
    Authenticator, Challenge, ChallengeKind, Evidence, Ledger, Outcome, Response, Segment,
};
use crate::export::{verify_package, Package, TrustAnchor, Verified};
use crate::quorum::QuorumMsg;
use crate::StateMachine;
use gv_core::{Digest, MatchId, ParticipantId, Session};
use gv_sig::{Signature, SigningKey, SIG_LEN};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

mod quorum;

const MAGIC: &[u8] = b"GV-WITNESS/V1\0";
const HELLO_LABEL: &str = "gv/witness/hello/v1";
const ADMIT_LABEL: &str = "gv/witness/admit/v1";
pub const MAX_MESSAGE: usize = 4 << 20;
pub const MAX_INVENTORY: usize = 64;
pub const MAX_WANT: usize = 16;
pub const MAX_ITEMS: usize = 1024;
pub const MAX_AUTHS_PER_OWNER: usize = 256;
/// Logical milliseconds between inventory broadcasts on an admitted link.
pub const INVENTORY_EVERY: u64 = 1000;
const MAX_STRIKES: u32 = 8;
/// Logical milliseconds between Hello retransmissions while unadmitted.
const HELLO_RETRY: u64 = 500;
/// Inbound messages accepted per link per second (token bucket).
const RATE_PER_SEC: u32 = 64;
/// Items up to this size travel as one message; larger ones are chunked so no single frame can
/// exceed the transport's packet bound or starve small control messages.
pub const INLINE_MAX: usize = 24 << 10;
pub const CHUNK_BYTES: usize = 16 << 10;
/// Largest item a witness will reassemble.
pub const MAX_ITEM_BYTES: usize = 4 << 20;
/// Chunks released per `tick` per link (paces large transfers behind control traffic).
const CHUNKS_PER_TICK: usize = 4;

#[derive(Clone, Debug)]
pub enum Msg {
    Hello {
        witness: ParticipantId,
        nonce: u64,
        sig: Signature,
    },
    Admit {
        player: ParticipantId,
        witness: ParticipantId,
        nonce: u64,
        sig: Signature,
    },
    Auth(Authenticator),
    Inventory {
        items: Vec<Digest>,
        heads: Vec<(ParticipantId, u64)>,
    },
    Want(Vec<Digest>),
    Evidence(Box<Evidence>),
    /// A `GV-EVIDENCE-PACKAGE/V1` (fraud witness) verified by replay.
    Package(Vec<u8>),
    /// One piece of a large item; `transfer` is the SHA-256 of the whole item.
    Chunk {
        transfer: Digest,
        index: u32,
        count: u32,
        data: Vec<u8>,
    },
    Challenge(Challenge),
    Response(Response),
    /// Head-register request or answer (see [`crate::quorum`]).
    Quorum(QuorumMsg),
}

struct W(Vec<u8>);
impl W {
    fn blob(&mut self, b: &[u8]) {
        self.0.extend_from_slice(&(b.len() as u32).to_le_bytes());
        self.0.extend_from_slice(b);
    }
}
struct Rd<'a>(&'a [u8]);
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn arr<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.arr()?))
    }
    fn blob(&mut self) -> Option<&'a [u8]> {
        let n = u32::from_le_bytes(self.arr()?) as usize;
        self.take(n)
    }
}

fn hello_body(m: &MatchId, w: &ParticipantId, to: &ParticipantId, nonce: u64) -> Vec<u8> {
    let mut b = m.to_vec();
    b.extend_from_slice(w);
    b.extend_from_slice(to);
    b.extend_from_slice(&nonce.to_le_bytes());
    b
}
fn admit_body(m: &MatchId, p: &ParticipantId, w: &ParticipantId, nonce: u64) -> Vec<u8> {
    hello_body(m, p, w, nonce)
}

impl Msg {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W(MAGIC.to_vec());
        match self {
            Msg::Hello {
                witness,
                nonce,
                sig,
            } => {
                w.0.push(1);
                w.0.extend_from_slice(witness);
                w.0.extend_from_slice(&nonce.to_le_bytes());
                w.0.extend_from_slice(sig.as_bytes());
            }
            Msg::Admit {
                player,
                witness,
                nonce,
                sig,
            } => {
                w.0.push(2);
                w.0.extend_from_slice(player);
                w.0.extend_from_slice(witness);
                w.0.extend_from_slice(&nonce.to_le_bytes());
                w.0.extend_from_slice(sig.as_bytes());
            }
            Msg::Auth(a) => {
                w.0.push(3);
                w.0.extend_from_slice(&a.encode());
            }
            Msg::Inventory { items, heads } => {
                w.0.push(4);
                w.0.push(items.len().min(MAX_INVENTORY) as u8);
                for i in items.iter().take(MAX_INVENTORY) {
                    w.0.extend_from_slice(i);
                }
                w.0.push(heads.len().min(4) as u8);
                for (o, s) in heads.iter().take(4) {
                    w.0.extend_from_slice(o);
                    w.0.extend_from_slice(&s.to_le_bytes());
                }
            }
            Msg::Want(ids) => {
                w.0.push(5);
                w.0.push(ids.len().min(MAX_WANT) as u8);
                for i in ids.iter().take(MAX_WANT) {
                    w.0.extend_from_slice(i);
                }
            }
            Msg::Evidence(e) => {
                w.0.push(6);
                if let Ok(b) = e.encode() {
                    w.blob(&b);
                } else {
                    w.blob(&[]);
                }
            }
            Msg::Package(p) => {
                w.0.push(7);
                w.blob(p);
            }
            Msg::Chunk {
                transfer,
                index,
                count,
                data,
            } => {
                w.0.push(10);
                w.0.extend_from_slice(transfer);
                w.0.extend_from_slice(&index.to_le_bytes());
                w.0.extend_from_slice(&count.to_le_bytes());
                w.blob(data);
            }
            Msg::Challenge(c) => {
                w.0.push(8);
                w.blob(&c.encode());
            }
            Msg::Response(r) => {
                w.0.push(9);
                w.blob(&r.encode());
            }
            Msg::Quorum(q) => {
                w.0.push(11);
                w.blob(&q.encode());
            }
        }
        w.0
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() > MAX_MESSAGE {
            return None;
        }
        let mut r = Rd(b.strip_prefix(MAGIC)?);
        let tag = r.take(1)?[0];
        let m = match tag {
            1 => Msg::Hello {
                witness: r.arr()?,
                nonce: r.u64()?,
                sig: Signature::from_slice(r.take(SIG_LEN)?).ok()?,
            },
            2 => Msg::Admit {
                player: r.arr()?,
                witness: r.arr()?,
                nonce: r.u64()?,
                sig: Signature::from_slice(r.take(SIG_LEN)?).ok()?,
            },
            3 => Msg::Auth(Authenticator::decode(r.take(Authenticator::WIRE_SIZE)?).ok()?),
            4 => {
                let n = r.take(1)?[0] as usize;
                if n > MAX_INVENTORY {
                    return None;
                }
                let items = (0..n).map(|_| r.arr()).collect::<Option<Vec<_>>>()?;
                let h = r.take(1)?[0] as usize;
                if h > 4 {
                    return None;
                }
                let heads = (0..h)
                    .map(|_| Some((r.arr()?, r.u64()?)))
                    .collect::<Option<Vec<_>>>()?;
                Msg::Inventory { items, heads }
            }
            5 => {
                let n = r.take(1)?[0] as usize;
                if n > MAX_WANT {
                    return None;
                }
                Msg::Want((0..n).map(|_| r.arr()).collect::<Option<Vec<_>>>()?)
            }
            6 => Msg::Evidence(Box::new(Evidence::decode(r.blob()?).ok()?)),
            7 => Msg::Package(r.blob()?.to_vec()),
            8 => Msg::Challenge(Challenge::decode(r.blob()?).ok()?),
            10 => Msg::Chunk {
                transfer: r.arr()?,
                index: u32::from_le_bytes(r.arr()?),
                count: u32::from_le_bytes(r.arr()?),
                data: r.blob()?.to_vec(),
            },
            9 => Msg::Response(Response::decode(r.blob()?).ok()?),
            11 => Msg::Quorum(QuorumMsg::decode(r.blob()?).ok()?),
            _ => return None,
        };
        r.0.is_empty().then_some(m)
    }
}

pub type LinkId = u32;

/// What a link's remote must be, fixed when the link is opened from the pinned manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Remote {
    /// The remote is this pinned player (I am a witness, or a peer witness).
    Player(ParticipantId),
    /// The remote is some witness from the pinned witness set (I am a player).
    AnyWitness,
}

#[derive(Debug)]
struct Link {
    remote: Remote,
    /// Authenticated identity of the remote once admitted.
    peer: Option<ParticipantId>,
    my_nonce: u64,
    last_hello: u64,
    last_inventory: u64,
    strikes: u32,
    tokens: u32,
    token_sec: u64,
    blocked: bool,
    sent_items: BTreeSet<Digest>,
    /// Encoded chunk messages awaiting paced release.
    pending_chunks: VecDeque<Vec<u8>>,
    /// Inbound reassembly of the single transfer in flight on this link.
    assembly: Option<Assembly>,
}

#[derive(Debug)]
struct Assembly {
    transfer: Digest,
    count: u32,
    next: u32,
    buf: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Admitted {
        link: LinkId,
        peer: ParticipantId,
    },
    /// New evidence verified independently; `accused` provably misbehaved.
    Verified {
        id: Digest,
        accused: ParticipantId,
        kind: &'static str,
    },
    /// Evidence/package that did not verify: proves nothing about anyone.
    Rejected {
        link: LinkId,
    },
    Duplicate {
        link: LinkId,
    },
    Blocked {
        link: LinkId,
    },
    /// A challenge I issued reached a final status. Timeout is never a verdict.
    Challenge {
        id: Digest,
        status: Status,
    },
    /// A peer returned a head signed by the local participant (recovery anchor).
    OwnHead(Authenticator),
    /// A challenge from a witness for the local player (host routes it to the auditor).
    ChallengeForPlayer {
        link: LinkId,
        challenge: Challenge,
    },
    /// A witness's register answer for the local player (host routes it to the auditor).
    Quorum {
        link: LinkId,
        from: ParticipantId,
        msg: QuorumMsg,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub verified: u64,
    pub rejected: u64,
    pub duplicates: u64,
    pub dropped_unadmitted: u64,
    pub dropped_rate: u64,
    pub dropped_full: u64,
    pub auths_stored: u64,
    pub bytes_in: u64,
}

pub struct WitnessNode<R: StateMachine + Clone> {
    key: SigningKey,
    me: ParticipantId,
    match_id: MatchId,
    ruleset: Digest,
    session: Session,
    /// Every roster member: heads are collected and served for all of them.
    roster: Vec<ParticipantId>,
    witnesses: BTreeSet<ParticipantId>,
    rules: R,
    ledger: Ledger,
    /// Encoded evidence/package by id for serving `Want`.
    items: BTreeMap<Digest, Vec<u8>>,
    auths: BTreeMap<ParticipantId, BTreeMap<u64, Authenticator>>,
    links: BTreeMap<LinkId, Link>,
    book: ChallengeBook,
    kinds: BTreeMap<Digest, (LinkId, ChallengeKind, Authenticator)>,
    out: VecDeque<(LinkId, Vec<u8>)>,
    events: VecDeque<Event>,
    stats: Stats,
    nonce: u64,
    register: Option<Box<dyn quorum::Responder>>,
}

impl<R: StateMachine + Clone> WitnessNode<R> {
    pub fn new(key: SigningKey, session: Session, witnesses: &[ParticipantId], rules: R) -> Self {
        let ruleset = rules.ruleset_hash();
        let match_id = session.match_id;
        let roster = session.roster.participants().iter().map(|p| p.id).collect();
        Self {
            me: key.id(),
            book: ChallengeBook::new(
                key.clone(),
                match_id,
                Timing {
                    timeout: 4000,
                    grace: 8000,
                },
            ),
            key,
            match_id,
            ruleset,
            roster,
            session,
            witnesses: witnesses.iter().copied().collect(),
            rules,
            ledger: Ledger::new(),
            items: BTreeMap::new(),
            auths: BTreeMap::new(),
            links: BTreeMap::new(),
            kinds: BTreeMap::new(),
            out: VecDeque::new(),
            events: VecDeque::new(),
            stats: Stats::default(),
            nonce: 0,
            register: None,
        }
    }
    pub fn stats(&self) -> Stats {
        self.stats
    }
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }
    pub fn item_ids(&self) -> Vec<Digest> {
        self.items.keys().copied().collect()
    }
    pub fn poll_out(&mut self) -> Option<(LinkId, Vec<u8>)> {
        self.out.pop_front()
    }
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }
    /// Encoded bytes of a verified item (evidence or package).
    pub fn item_bytes(&self, id: &Digest) -> Option<Vec<u8>> {
        self.items.get(id).cloned()
    }
    /// Queue an answer from the local player to a witness challenge on `link`.
    pub fn send_response(&mut self, link: LinkId, r: &Response) {
        self.send(link, &Msg::Response(r.clone()));
    }
    /// Test/adversary hook: queue raw bytes toward a link as if built by a hostile peer.
    pub fn inject_raw(&mut self, link: LinkId, bytes: &[u8]) {
        self.out.push_back((link, bytes.to_vec()));
    }
    pub fn latest_auth(&self, owner: &ParticipantId) -> Option<&Authenticator> {
        self.auths.get(owner).and_then(|m| m.values().next_back())
    }
    pub fn is_admitted(&self, link: LinkId) -> bool {
        self.links
            .get(&link)
            .is_some_and(|l| l.peer.is_some() && !l.blocked)
    }

    /// Open (or re-open after a reconnect) a link. A witness initiates admission; a player waits
    /// for the Hello. Re-opening resets admission so a reconnect re-authenticates.
    pub fn open_link(&mut self, link: LinkId, remote: Remote, now: u64) {
        let prior_strikes = self.links.get(&link).map_or(0, |l| l.strikes);
        self.nonce += 1;
        let nonce = self.nonce ^ (now << 20);
        self.links.insert(
            link,
            Link {
                remote,
                peer: None,
                my_nonce: nonce,
                last_hello: now,
                last_inventory: 0,
                strikes: prior_strikes,
                tokens: RATE_PER_SEC,
                token_sec: now / 1000,
                blocked: false,
                sent_items: BTreeSet::new(),
                pending_chunks: VecDeque::new(),
                assembly: None,
            },
        );
        if matches!(remote, Remote::Player(_)) && self.witnesses.contains(&self.me) {
            let Remote::Player(to) = remote else { return };
            let sig = self.key.sign(
                HELLO_LABEL,
                &hello_body(&self.match_id, &self.me, &to, nonce),
            );
            self.out.push_back((
                link,
                Msg::Hello {
                    witness: self.me,
                    nonce,
                    sig,
                }
                .encode(),
            ));
        }
    }
    pub fn link_down(&mut self, link: LinkId) {
        if let Some(l) = self.links.get_mut(&link) {
            l.peer = None;
            l.pending_chunks.clear();
            l.assembly = None;
        }
    }

    /// Send a stored item: whole when small, otherwise as paced chunks.
    fn send_item(&mut self, link: LinkId, bytes: &[u8]) {
        let is_pkg = bytes.starts_with(b"GV-EVIDENCE-PACKAGE/V1\0");
        if bytes.len() <= INLINE_MAX {
            let msg = if is_pkg {
                Msg::Package(bytes.to_vec())
            } else if let Ok(e) = Evidence::decode(bytes) {
                Msg::Evidence(Box::new(e))
            } else {
                return;
            };
            return self.send(link, &msg);
        }
        if !is_pkg || bytes.len() > MAX_ITEM_BYTES {
            return;
        }
        let transfer: Digest = Sha256::digest(bytes).into();
        let count = bytes.len().div_ceil(CHUNK_BYTES) as u32;
        let Some(l) = self.links.get_mut(&link) else {
            return;
        };
        if l.pending_chunks.len() > 4 * (MAX_ITEM_BYTES / CHUNK_BYTES) {
            return; // bounded queue: the peer will ask again via inventory
        }
        for (i, c) in bytes.chunks(CHUNK_BYTES).enumerate() {
            l.pending_chunks.push_back(
                Msg::Chunk {
                    transfer,
                    index: i as u32,
                    count,
                    data: c.to_vec(),
                }
                .encode(),
            );
        }
    }
    fn on_chunk(&mut self, link: LinkId, transfer: Digest, index: u32, count: u32, data: Vec<u8>) {
        let max_count = MAX_ITEM_BYTES.div_ceil(CHUNK_BYTES) as u32;
        let bad = count == 0 || count > max_count || index >= count || data.len() > CHUNK_BYTES;
        if bad {
            return self.strike_reject(link);
        }
        let Some(l) = self.links.get_mut(&link) else {
            return;
        };
        let fresh = match &l.assembly {
            Some(a) => a.transfer != transfer || a.count != count,
            None => true,
        };
        if fresh {
            if index != 0 {
                return; // a tail of something I dropped; the sender re-offers via inventory
            }
            l.assembly = Some(Assembly {
                transfer,
                count,
                next: 0,
                buf: Vec::new(),
            });
        }
        let Some(a) = l.assembly.as_mut() else { return };
        if index != a.next {
            return; // duplicate or reordered piece: reliable delivery makes this a retransmit
        }
        a.buf.extend_from_slice(&data);
        a.next += 1;
        if a.next < a.count {
            return;
        }
        let Some(done) = l.assembly.take() else {
            return;
        };
        let whole: Digest = Sha256::digest(&done.buf).into();
        if whole != done.transfer {
            return self.strike_reject(link);
        }
        self.submit_package(&done.buf, Some(link));
    }
    fn send(&mut self, link: LinkId, m: &Msg) {
        self.out.push_back((link, m.encode()));
    }
    fn strike(&mut self, link: LinkId) {
        if let Some(l) = self.links.get_mut(&link) {
            l.strikes += 1;
            if l.strikes >= MAX_STRIKES && !l.blocked {
                l.blocked = true;
                self.events.push_back(Event::Blocked { link });
            }
        }
    }

    /// Feed evidence found locally (a player's own auditor) or relayed. Verified before storing.
    pub fn submit_evidence(&mut self, e: &Evidence, from: Option<LinkId>) {
        let Ok(id) = e.id() else {
            return self.reject(from);
        };
        if self.items.contains_key(&id) {
            return self.dup(from);
        }
        if self.items.len() >= MAX_ITEMS {
            self.stats.dropped_full += 1;
            return;
        }
        match self.ledger.submit(e, &self.roster) {
            Outcome::Recorded(_) => {
                let Ok(bytes) = e.encode() else { return };
                self.items.insert(id, bytes);
                self.stats.verified += 1;
                self.events.push_back(Event::Verified {
                    id,
                    accused: e.accused(),
                    kind: "equivocation",
                });
                self.announce(id, from);
            }
            Outcome::Duplicate => self.dup(from),
            _ => self.reject(from),
        }
    }
    /// A `GV-EVIDENCE-PACKAGE/V1` fraud witness, verified by replay against the pinned context.
    pub fn submit_package(&mut self, bytes: &[u8], from: Option<LinkId>) {
        let anchor = TrustAnchor {
            match_id: self.match_id,
            ruleset: self.ruleset,
            session: self.session.digest(),
        };
        let Ok(pkg) = Package::decode(bytes) else {
            return self.reject(from);
        };
        let id = pkg.id();
        if self.items.contains_key(&id) {
            return self.dup(from);
        }
        if self.items.len() >= MAX_ITEMS {
            self.stats.dropped_full += 1;
            return;
        }
        match verify_package(bytes, &anchor, &self.rules) {
            Ok((_, Verified::Fraud { accused, .. })) => {
                self.items.insert(id, bytes.to_vec());
                self.stats.verified += 1;
                self.events.push_back(Event::Verified {
                    id,
                    accused,
                    kind: "fraud",
                });
                self.announce(id, from);
            }
            _ => self.reject(from),
        }
    }
    fn reject(&mut self, from: Option<LinkId>) {
        self.stats.rejected += 1;
        if let Some(l) = from {
            self.events.push_back(Event::Rejected { link: l });
            self.strike(l);
        }
    }
    fn dup(&mut self, from: Option<LinkId>) {
        self.stats.duplicates += 1;
        if let Some(l) = from {
            self.events.push_back(Event::Duplicate { link: l });
        }
    }
    /// Push a newly verified item to every admitted link except where it came from. Items are
    /// small relative to the budget; larger ones are pulled via inventory/want.
    fn announce(&mut self, id: Digest, from: Option<LinkId>) {
        let Some(bytes) = self.items.get(&id).cloned() else {
            return;
        };
        let targets: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(k, l)| {
                l.peer.is_some() && !l.blocked && Some(**k) != from && !l.sent_items.contains(&id)
            })
            .map(|(k, _)| *k)
            .collect();
        for t in targets {
            if let Some(l) = self.links.get_mut(&t) {
                if l.sent_items.len() < 4096 {
                    l.sent_items.insert(id);
                }
            }
            self.send_item(t, &bytes);
        }
    }
    /// Store (verified) and forward a signed authenticator. Contradicting stored heads are
    /// themselves evidence of equivocation.
    pub fn submit_auth(&mut self, a: &Authenticator, from: Option<LinkId>) {
        if a.match_id != self.match_id
            || a.ruleset != self.ruleset
            || !self.roster.contains(&a.owner)
            || a.verify().is_err()
        {
            return self.reject(from);
        }
        let per = self.auths.entry(a.owner).or_default();
        if let Some(prev) = per.get(&a.seq) {
            if prev.head == a.head {
                return self.dup(from);
            }
            let e = Evidence::ConflictingAuthenticators(prev.clone(), a.clone());
            return self.submit_evidence(&e, from);
        }
        if per.len() >= MAX_AUTHS_PER_OWNER {
            per.pop_first();
        }
        per.insert(a.seq, a.clone());
        self.stats.auths_stored += 1;
        if a.owner == self.me && from.is_some() {
            self.events.push_back(Event::OwnHead(a.clone()));
        }
        let targets: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(k, l)| l.peer.is_some() && !l.blocked && Some(**k) != from)
            .map(|(k, _)| *k)
            .collect();
        for t in targets {
            self.send(t, &Msg::Auth(a.clone()));
        }
    }

    /// Ask a player for the log segment between two authenticators I hold; the answer is checked
    /// against the signed heads. A silent target only ever becomes SUSPECTED/UNAVAILABLE.
    pub fn audit_player(
        &mut self,
        link: LinkId,
        player: ParticipantId,
        now: u64,
    ) -> Option<Digest> {
        let a = self.latest_auth(&player)?.clone();
        let base = self
            .auths
            .get(&player)?
            .values()
            .find(|x| x.seq < a.seq)?
            .clone();
        let kind = ChallengeKind::LogSegment {
            from: base.seq,
            to: a.seq,
        };
        let c = self.book.issue(player, kind, now).ok()?;
        if self.kinds.len() >= 128 {
            self.kinds.pop_first();
        }
        self.kinds.insert(c.id(), (link, kind, base));
        while let Some(c) = self.book.poll_outbox() {
            self.send(link, &Msg::Challenge(c));
        }
        // `to` is checked against `a` when the response arrives.
        Some(c.id())
    }

    pub fn tick(&mut self, now: u64) {
        self.book.poll(now);
        while let Some(c) = self.book.poll_outbox() {
            if let Some((link, ..)) = self.kinds.get(&c.id()) {
                let link = *link;
                self.send(link, &Msg::Challenge(c));
            }
        }
        while let Some((id, status)) = self.book.poll_change() {
            self.events.push_back(Event::Challenge { id, status });
        }
        self.book.gc();
        // Admission is retried until answered: Hello or Admit may be lost.
        let hellos: Vec<(LinkId, ParticipantId, u64)> = self
            .links
            .iter()
            .filter_map(|(k, l)| match l.remote {
                Remote::Player(p)
                    if l.peer.is_none() && !l.blocked && now >= l.last_hello + HELLO_RETRY =>
                {
                    Some((*k, p, l.my_nonce))
                }
                _ => None,
            })
            .collect();
        for (k, to, nonce) in hellos {
            if let Some(l) = self.links.get_mut(&k) {
                l.last_hello = now;
            }
            let sig = self.key.sign(
                HELLO_LABEL,
                &hello_body(&self.match_id, &self.me, &to, nonce),
            );
            self.send(
                k,
                &Msg::Hello {
                    witness: self.me,
                    nonce,
                    sig,
                },
            );
        }
        for k in self.links.keys().copied().collect::<Vec<_>>() {
            for _ in 0..CHUNKS_PER_TICK {
                let Some(c) = self
                    .links
                    .get_mut(&k)
                    .and_then(|l| l.pending_chunks.pop_front())
                else {
                    break;
                };
                self.out.push_back((k, c));
            }
        }
        let due: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(_, l)| {
                l.peer.is_some() && !l.blocked && now >= l.last_inventory + INVENTORY_EVERY
            })
            .map(|(k, _)| *k)
            .collect();
        for k in due {
            let items: Vec<Digest> = self.items.keys().copied().take(MAX_INVENTORY).collect();
            let heads: Vec<(ParticipantId, u64)> = self
                .roster
                .iter()
                .filter_map(|p| self.latest_auth(p).map(|a| (*p, a.seq)))
                .collect();
            if let Some(l) = self.links.get_mut(&k) {
                l.last_inventory = now;
            }
            self.send(k, &Msg::Inventory { items, heads });
        }
    }

    /// One inbound message from `link`. Everything unadmitted, malformed, over rate or invalid
    /// is dropped without a verdict.
    pub fn on_message(&mut self, link: LinkId, bytes: &[u8], now: u64) {
        let Some(l) = self.links.get_mut(&link) else {
            return;
        };
        if l.blocked {
            return;
        }
        if now / 1000 != l.token_sec {
            l.token_sec = now / 1000;
            l.tokens = RATE_PER_SEC;
        }
        if l.tokens == 0 {
            self.stats.dropped_rate += 1;
            return;
        }
        l.tokens -= 1;
        self.stats.bytes_in += bytes.len() as u64;
        let Some(msg) = Msg::decode(bytes) else {
            return self.strike(link);
        };
        let admitted = l.peer;
        match msg {
            Msg::Hello {
                witness,
                nonce,
                sig,
            } => self.on_hello(link, witness, nonce, &sig, now),
            Msg::Admit {
                player,
                witness,
                nonce,
                sig,
            } => {
                self.on_admit(link, player, witness, nonce, &sig, now);
            }
            _ if admitted.is_none() => self.stats.dropped_unadmitted += 1,
            Msg::Auth(a) => self.submit_auth(&a, Some(link)),
            Msg::Evidence(e) => self.submit_evidence(&e, Some(link)),
            Msg::Package(p) => self.submit_package(&p, Some(link)),
            Msg::Chunk {
                transfer,
                index,
                count,
                data,
            } => self.on_chunk(link, transfer, index, count, data),
            Msg::Inventory { items, heads } => self.on_inventory(link, &items, &heads),
            Msg::Want(ids) => self.on_want(link, &ids),
            Msg::Challenge(c) => {
                if admitted.is_some_and(|p| p == c.challenger) && c.verify() {
                    self.events
                        .push_back(Event::ChallengeForPlayer { link, challenge: c });
                } else {
                    self.reject(Some(link));
                }
            }
            Msg::Response(r) => self.on_response(link, &r),
            Msg::Quorum(q) => self.on_quorum(link, q),
        }
    }

    fn on_hello(
        &mut self,
        link: LinkId,
        witness: ParticipantId,
        nonce: u64,
        sig: &Signature,
        now: u64,
    ) {
        let Some(remote) = self.links.get(&link).map(|l| l.remote) else {
            return;
        };
        let ok = remote == Remote::AnyWitness
            && self.witnesses.contains(&witness)
            && gv_sig::verify(
                &witness,
                HELLO_LABEL,
                &hello_body(&self.match_id, &witness, &self.me, nonce),
                sig,
            )
            .is_ok();
        if !ok {
            return self.strike_reject(link);
        }
        let asig = self.key.sign(
            ADMIT_LABEL,
            &admit_body(&self.match_id, &self.me, &witness, nonce),
        );
        self.send(
            link,
            &Msg::Admit {
                player: self.me,
                witness,
                nonce,
                sig: asig,
            },
        );
        self.admit(link, witness, now);
    }
    fn on_admit(
        &mut self,
        link: LinkId,
        player: ParticipantId,
        witness: ParticipantId,
        nonce: u64,
        sig: &Signature,
        now: u64,
    ) {
        let Some((remote, my_nonce)) = self.links.get(&link).map(|l| (l.remote, l.my_nonce)) else {
            return;
        };
        let ok = remote == Remote::Player(player)
            && self.roster.contains(&player)
            && witness == self.me
            && nonce == my_nonce
            && gv_sig::verify(
                &player,
                ADMIT_LABEL,
                &admit_body(&self.match_id, &player, &witness, nonce),
                sig,
            )
            .is_ok();
        if !ok {
            // A well-addressed Admit answering an earlier Hello of this link (the link was
            // re-opened since) is stale, not hostile: ignore it without a strike.
            if remote == Remote::Player(player) && witness == self.me && nonce != my_nonce {
                return;
            }
            return self.strike_reject(link);
        }
        self.admit(link, player, now);
    }
    fn strike_reject(&mut self, link: LinkId) {
        self.stats.rejected += 1;
        self.events.push_back(Event::Rejected { link });
        self.strike(link);
    }
    fn admit(&mut self, link: LinkId, peer: ParticipantId, now: u64) {
        if let Some(l) = self.links.get_mut(&link) {
            l.peer = Some(peer);
            l.last_inventory = now.saturating_sub(INVENTORY_EVERY); // inventory goes out next tick
        }
        self.events.push_back(Event::Admitted { link, peer });
        // Reconnect recovery: hand the newcomer my latest signed heads right away.
        let heads: Vec<Authenticator> = self
            .roster
            .iter()
            .filter_map(|p| self.latest_auth(p).cloned())
            .collect();
        for a in heads {
            self.send(link, &Msg::Auth(a));
        }
    }
    fn on_inventory(&mut self, link: LinkId, items: &[Digest], heads: &[(ParticipantId, u64)]) {
        let want: Vec<Digest> = items
            .iter()
            .filter(|i| !self.items.contains_key(*i))
            .copied()
            .take(MAX_WANT)
            .collect();
        if !want.is_empty() {
            self.send(link, &Msg::Want(want));
        }
        // If the peer has newer heads than mine, its own announcements will carry them; if I have
        // newer ones, push the latest so a lagging peer converges without a full sync.
        for p in self.roster.clone() {
            let theirs = heads.iter().find(|(o, _)| *o == p).map_or(0, |(_, s)| *s);
            if let Some(a) = self.latest_auth(&p).filter(|a| a.seq > theirs).cloned() {
                self.send(link, &Msg::Auth(a));
            }
        }
    }
    fn on_want(&mut self, link: LinkId, ids: &[Digest]) {
        for id in ids.iter().take(MAX_WANT) {
            let Some(bytes) = self.items.get(id).cloned() else {
                continue;
            };
            self.send_item(link, &bytes);
        }
    }
    fn on_response(&mut self, link: LinkId, r: &Response) {
        let Some((l, kind, base)) = self.kinds.get(&r.challenge_id).cloned() else {
            return;
        };
        if l != link {
            return;
        }
        let newer = match kind {
            ChallengeKind::LogSegment { to, .. } => self
                .auths
                .get(&base.owner)
                .and_then(|m| m.get(&to))
                .cloned(),
            _ => None,
        };
        let fork: std::cell::RefCell<Option<Evidence>> = std::cell::RefCell::new(None);
        let res = self.book.on_response(r, |_, payload| {
            let (Ok(seg), Some(end)) = (Segment::decode(payload), newer.as_ref()) else {
                return false;
            };
            let ChallengeKind::LogSegment { from, to } = kind else {
                return false;
            };
            if seg.owner != base.owner
                || seg.start_seq != from
                || seg.end_seq() != to
                || seg.end_head().ok() != Some(end.head)
            {
                return false;
            }
            if seg.prev_head != base.head {
                *fork.borrow_mut() = Some(Evidence::Fork {
                    earlier: base.clone(),
                    later: end.clone(),
                    segment: seg,
                });
            }
            true
        });
        if let Ok(status) = res {
            self.events.push_back(Event::Challenge {
                id: r.challenge_id,
                status,
            });
        }
        if let Some(e) = fork.into_inner() {
            self.submit_evidence(&e, None);
        }
    }
}
