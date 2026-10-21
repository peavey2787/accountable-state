//! PeerReview-style tamper-evident log: an append-only hash chain whose heads are
//! committed to by signed authenticators. Pure data; no clocks, no I/O.
use gv_core::{Digest, MatchId, PlayerId};
use gv_sig::{Signature, SigningKey, SIG_LEN};
use sha2::{Digest as _, Sha256};

pub const MAX_ENTRY_PAYLOAD: usize = 64 * 1024;
pub const MAX_SEGMENT_ENTRIES: usize = 4096;
const CHAIN_DOMAIN: &[u8] = b"gv/audit/chain/v1\0";
const GENESIS_DOMAIN: &[u8] = b"gv/audit/genesis/v1\0";
const AUTH_LABEL: &str = "gv/audit/authenticator/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogError {
    Malformed,
    TooLarge,
    BrokenChain,
    OutOfRange,
    Pruned,
    BadSignature,
}

fn h(parts: &[&[u8]]) -> Digest {
    let mut s = Sha256::new();
    for p in parts {
        s.update(p);
    }
    s.finalize().into()
}

/// Head of the empty log; binds match and owner so heads never transplant.
pub fn genesis_head(match_id: &MatchId, owner: &PlayerId) -> Digest {
    h(&[GENESIS_DOMAIN, match_id, owner])
}

/// head_n = H(domain || match || owner || seq || prev || kind || H(payload)).
pub fn chain_head(
    match_id: &MatchId,
    owner: &PlayerId,
    seq: u64,
    prev: &Digest,
    kind: u8,
    payload: &[u8],
) -> Digest {
    h(&[
        CHAIN_DOMAIN,
        match_id,
        owner,
        &seq.to_le_bytes(),
        prev,
        &[kind],
        &h(&[payload]),
    ])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    pub kind: u8,
    pub payload: Vec<u8>,
}

/// A contiguous run of entries `start_seq+1 ..= start_seq+len` extending the
/// (claimed) head `prev_head` at `start_seq`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub match_id: MatchId,
    pub owner: PlayerId,
    pub start_seq: u64,
    pub prev_head: Digest,
    pub entries: Vec<LogEntry>,
}

impl Segment {
    /// Recompute the head after the last entry. Pure; the caller compares it with
    /// a signed authenticator.
    pub fn end_head(&self) -> Result<Digest, LogError> {
        if self.entries.len() > MAX_SEGMENT_ENTRIES {
            return Err(LogError::TooLarge);
        }
        let mut head = self.prev_head;
        for (i, e) in self.entries.iter().enumerate() {
            if e.payload.len() > MAX_ENTRY_PAYLOAD {
                return Err(LogError::TooLarge);
            }
            let seq = self
                .start_seq
                .checked_add(i as u64 + 1)
                .ok_or(LogError::Malformed)?;
            head = chain_head(&self.match_id, &self.owner, seq, &head, e.kind, &e.payload);
        }
        Ok(head)
    }
    pub fn end_seq(&self) -> u64 {
        self.start_seq.saturating_add(self.entries.len() as u64)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&self.match_id);
        o.extend_from_slice(&self.owner);
        o.extend_from_slice(&self.start_seq.to_le_bytes());
        o.extend_from_slice(&self.prev_head);
        o.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for e in &self.entries {
            o.push(e.kind);
            o.extend_from_slice(&(e.payload.len() as u32).to_le_bytes());
            o.extend_from_slice(&e.payload);
        }
        o
    }
    pub fn decode(b: &[u8]) -> Result<Self, LogError> {
        let mut r = Reader(b);
        let match_id = r.take::<32>()?;
        let owner = r.take::<32>()?;
        let start_seq = u64::from_le_bytes(r.take::<8>()?);
        let prev_head = r.take::<32>()?;
        let n = u32::from_le_bytes(r.take::<4>()?) as usize;
        if n > MAX_SEGMENT_ENTRIES {
            return Err(LogError::TooLarge);
        }
        let mut entries = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            let kind = r.take::<1>()?[0];
            let len = u32::from_le_bytes(r.take::<4>()?) as usize;
            if len > MAX_ENTRY_PAYLOAD {
                return Err(LogError::TooLarge);
            }
            entries.push(LogEntry {
                kind,
                payload: r.bytes(len)?.to_vec(),
            });
        }
        if !r.0.is_empty() {
            return Err(LogError::Malformed);
        }
        Ok(Self {
            match_id,
            owner,
            start_seq,
            prev_head,
            entries,
        })
    }
}

pub(crate) struct Reader<'a>(pub &'a [u8]);
impl<'a> Reader<'a> {
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], LogError> {
        if self.0.len() < n {
            return Err(LogError::Malformed);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    pub fn take<const N: usize>(&mut self) -> Result<[u8; N], LogError> {
        self.bytes(N)?.try_into().map_err(|_| LogError::Malformed)
    }
}

/// Owner's append-only log with bounded retention. Entries before `base_seq` may
/// be pruned; the chain head at the prune point is kept so the suffix still
/// verifies. Pruning never passes a pinned sequence.
#[derive(Clone, Debug)]
pub struct AuditLog {
    match_id: MatchId,
    owner: PlayerId,
    base_seq: u64,
    base_head: Digest,
    entries: Vec<LogEntry>,
    heads: Vec<Digest>,
    pins: Vec<u64>,
}

impl AuditLog {
    pub fn new(match_id: MatchId, owner: PlayerId) -> Self {
        Self {
            base_seq: 0,
            base_head: genesis_head(&match_id, &owner),
            match_id,
            owner,
            entries: Vec::new(),
            heads: Vec::new(),
            pins: Vec::new(),
        }
    }
    /// A log whose history before `seq` is unavailable but whose chain head there is known
    /// (taken from an authenticator the owner signed). New entries extend that head, so
    /// everything signed up to `seq` stays consistent; earlier entries can no longer be served
    /// (a challenge for them ends UNAVAILABLE, never as a verdict).
    pub fn rebased(match_id: MatchId, owner: PlayerId, seq: u64, head: Digest) -> Self {
        Self {
            base_seq: seq,
            base_head: head,
            match_id,
            owner,
            entries: Vec::new(),
            heads: Vec::new(),
            pins: Vec::new(),
        }
    }
    pub fn match_id(&self) -> MatchId {
        self.match_id
    }
    pub fn owner(&self) -> PlayerId {
        self.owner
    }
    pub fn len(&self) -> u64 {
        self.base_seq + self.entries.len() as u64
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn base_seq(&self) -> u64 {
        self.base_seq
    }
    pub fn retained(&self) -> usize {
        self.entries.len()
    }
    pub fn head(&self) -> Digest {
        self.heads.last().copied().unwrap_or(self.base_head)
    }
    /// Head after entry `seq` (0 is genesis) if still retained.
    pub fn head_at(&self, seq: u64) -> Option<Digest> {
        if seq == self.base_seq {
            return Some(self.base_head);
        }
        let i = seq.checked_sub(self.base_seq + 1)?;
        self.heads.get(usize::try_from(i).ok()?).copied()
    }
    pub fn append(&mut self, kind: u8, payload: Vec<u8>) -> Result<u64, LogError> {
        if payload.len() > MAX_ENTRY_PAYLOAD {
            return Err(LogError::TooLarge);
        }
        let seq = self.len() + 1;
        let head = chain_head(
            &self.match_id,
            &self.owner,
            seq,
            &self.head(),
            kind,
            &payload,
        );
        self.entries.push(LogEntry { kind, payload });
        self.heads.push(head);
        Ok(seq)
    }
    pub fn segment(&self, from: u64, to: u64) -> Result<Segment, LogError> {
        if from >= to || to > self.len() || to - from > MAX_SEGMENT_ENTRIES as u64 {
            return Err(LogError::OutOfRange);
        }
        if from < self.base_seq {
            return Err(LogError::Pruned);
        }
        let a = usize::try_from(from - self.base_seq).map_err(|_| LogError::OutOfRange)?;
        let b = usize::try_from(to - self.base_seq).map_err(|_| LogError::OutOfRange)?;
        Ok(Segment {
            match_id: self.match_id,
            owner: self.owner,
            start_seq: from,
            prev_head: self.head_at(from).ok_or(LogError::Pruned)?,
            entries: self.entries[a..b].to_vec(),
        })
    }
    /// Protect `seq` (and everything after it) from pruning, e.g. while a
    /// challenge that needs it is open.
    pub fn pin(&mut self, seq: u64) {
        if !self.pins.contains(&seq) && self.pins.len() < 1024 {
            self.pins.push(seq);
        }
    }
    pub fn unpin(&mut self, seq: u64) {
        self.pins.retain(|p| *p != seq);
    }
    /// Drop entries so that at most `keep` remain, never past the lowest pin.
    /// Returns the number of entries dropped.
    pub fn prune_to_keep(&mut self, keep: usize) -> usize {
        let want = self.entries.len().saturating_sub(keep);
        let limit = self
            .pins
            .iter()
            .map(|p| p.saturating_sub(self.base_seq + 1))
            .min()
            .map_or(want as u64, |m| m.min(want as u64)) as usize;
        if limit == 0 {
            return 0;
        }
        self.base_head = self.heads[limit - 1];
        self.base_seq += limit as u64;
        self.entries.drain(..limit);
        self.heads.drain(..limit);
        limit
    }
    pub fn sign_authenticator(&self, ruleset: Digest, key: &SigningKey) -> Authenticator {
        Authenticator::sign(self.match_id, ruleset, self.len(), self.head(), key)
    }
    /// Persistable snapshot: header + retained entries. Heads are recomputed on load,
    /// so a corrupted file cannot smuggle in a forged head.
    pub fn encode(&self) -> Vec<u8> {
        let seg = Segment {
            match_id: self.match_id,
            owner: self.owner,
            start_seq: self.base_seq,
            prev_head: self.base_head,
            entries: self.entries.clone(),
        };
        let mut o = b"GV-AUDIT-LOG/V1\0".to_vec();
        o.extend_from_slice(&seg.encode());
        o
    }
    /// Recover from a snapshot, optionally truncating a torn tail is the caller's
    /// job (see `store`); here any inconsistency is an error.
    pub fn decode(b: &[u8]) -> Result<Self, LogError> {
        let magic = b"GV-AUDIT-LOG/V1\0";
        let body = b
            .strip_prefix(magic.as_slice())
            .ok_or(LogError::Malformed)?;
        let seg = Segment::decode(body)?;
        let mut log = Self::new(seg.match_id, seg.owner);
        log.base_seq = seg.start_seq;
        log.base_head = seg.prev_head;
        for e in seg.entries {
            log.append(e.kind, e.payload)?;
        }
        Ok(log)
    }
}

/// Signed commitment to a log head: "my log at `seq` has head `head`".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authenticator {
    pub match_id: MatchId,
    pub ruleset: Digest,
    pub owner: PlayerId,
    pub seq: u64,
    pub head: Digest,
    pub signature: Signature,
}

impl Authenticator {
    pub const WIRE_SIZE: usize = 32 * 4 + 8 + SIG_LEN;
    fn body(m: &MatchId, r: &Digest, o: &PlayerId, seq: u64, head: &Digest) -> Vec<u8> {
        let mut b = Vec::with_capacity(32 * 4 + 8);
        b.extend_from_slice(m);
        b.extend_from_slice(r);
        b.extend_from_slice(o);
        b.extend_from_slice(&seq.to_le_bytes());
        b.extend_from_slice(head);
        b
    }
    pub fn sign(
        match_id: MatchId,
        ruleset: Digest,
        seq: u64,
        head: Digest,
        key: &SigningKey,
    ) -> Self {
        let owner = key.id();
        let signature = key.sign(
            AUTH_LABEL,
            &Self::body(&match_id, &ruleset, &owner, seq, &head),
        );
        Self {
            match_id,
            ruleset,
            owner,
            seq,
            head,
            signature,
        }
    }
    pub fn verify(&self) -> Result<(), LogError> {
        gv_sig::verify(
            &self.owner,
            AUTH_LABEL,
            &Self::body(
                &self.match_id,
                &self.ruleset,
                &self.owner,
                self.seq,
                &self.head,
            ),
            &self.signature,
        )
        .map_err(|_| LogError::BadSignature)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Self::body(
            &self.match_id,
            &self.ruleset,
            &self.owner,
            self.seq,
            &self.head,
        );
        o.extend_from_slice(self.signature.as_bytes());
        o
    }
    pub fn decode(b: &[u8]) -> Result<Self, LogError> {
        if b.len() != Self::WIRE_SIZE {
            return Err(LogError::Malformed);
        }
        let mut r = Reader(b);
        Ok(Self {
            match_id: r.take()?,
            ruleset: r.take()?,
            owner: r.take()?,
            seq: u64::from_le_bytes(r.take()?),
            head: r.take()?,
            signature: Signature::from_slice(r.bytes(SIG_LEN)?).map_err(|_| LogError::Malformed)?,
        })
    }
}
