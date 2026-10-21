//! Signed challenge/response with deadlines, bounded retransmission and replay
//! protection. A timeout only ever yields SUSPECTED_NONCOOPERATION (then
//! UNAVAILABLE): it is never a cryptographic cheating verdict, and a late valid
//! answer always clears it. All time is in caller-supplied logical ticks.
use super::log::{LogError, Reader};
use gv_core::{Digest, MatchId, PlayerId};
use gv_sig::{Signature, SigningKey, SIG_LEN};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, VecDeque};

pub const MAX_RESPONSE_PAYLOAD: usize = 1 << 20;
pub const MAX_PENDING_PER_TARGET: usize = 8;
pub const MAX_PENDING_TOTAL: usize = 64;
pub const MAX_RETRIES: u8 = 3;
/// Slow retransmissions while SUSPECTED, before the target is marked UNAVAILABLE.
pub const SUSPECT_ROUNDS: u8 = 3;
pub const MAX_SEEN: usize = 4096;
const CH_LABEL: &str = "gv/audit/challenge/v1";
const RS_LABEL: &str = "gv/audit/response/v1";

/// Public verdict vocabulary shared by challenges, evidence and the UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Pending,
    Cleared,
    Inconclusive,
    Unavailable,
    SuspectedNonCooperation,
    ProvenFraud,
    ProvenEquivocation,
}

impl Status {
    pub fn name(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Cleared => "CLEARED",
            Self::Inconclusive => "INCONCLUSIVE",
            Self::Unavailable => "UNAVAILABLE",
            Self::SuspectedNonCooperation => "SUSPECTED_NONCOOPERATION",
            Self::ProvenFraud => "PROVEN_FRAUD",
            Self::ProvenEquivocation => "PROVEN_EQUIVOCATION",
        }
    }
    /// Only cryptographic proof is a cheating verdict.
    pub fn is_proof(self) -> bool {
        matches!(self, Self::ProvenFraud | Self::ProvenEquivocation)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChallengeKind {
    MissingBatch { start_tick: u64 },
    Ack { seq: u64 },
    LogSegment { from: u64, to: u64 },
    MerkleWitness { epoch_start: u64 },
    HiddenReveal { start_tick: u64 },
    Replay { epoch_start: u64 },
}

impl ChallengeKind {
    fn encode(&self) -> [u8; 17] {
        let (t, a, b) = match *self {
            Self::MissingBatch { start_tick } => (1, start_tick, 0),
            Self::Ack { seq } => (2, seq, 0),
            Self::LogSegment { from, to } => (3, from, to),
            Self::MerkleWitness { epoch_start } => (4, epoch_start, 0),
            Self::HiddenReveal { start_tick } => (5, start_tick, 0),
            Self::Replay { epoch_start } => (6, epoch_start, 0),
        };
        let mut o = [0u8; 17];
        o[0] = t;
        o[1..9].copy_from_slice(&a.to_le_bytes());
        o[9..].copy_from_slice(&b.to_le_bytes());
        o
    }
    fn decode(b: [u8; 17]) -> Result<Self, LogError> {
        let a = u64::from_le_bytes(b[1..9].try_into().map_err(|_| LogError::Malformed)?);
        let c = u64::from_le_bytes(b[9..].try_into().map_err(|_| LogError::Malformed)?);
        Ok(match b[0] {
            1 => Self::MissingBatch { start_tick: a },
            2 => Self::Ack { seq: a },
            3 => Self::LogSegment { from: a, to: c },
            4 => Self::MerkleWitness { epoch_start: a },
            5 => Self::HiddenReveal { start_tick: a },
            6 => Self::Replay { epoch_start: a },
            _ => return Err(LogError::Malformed),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub match_id: MatchId,
    pub challenger: PlayerId,
    pub target: PlayerId,
    pub nonce: u64,
    pub kind: ChallengeKind,
    pub issued_tick: u64,
    pub deadline_tick: u64,
    pub signature: Signature,
}

impl Challenge {
    pub const WIRE_SIZE: usize = 32 * 3 + 8 + 17 + 16 + SIG_LEN;
    fn body(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(Self::WIRE_SIZE - SIG_LEN);
        o.extend_from_slice(&self.match_id);
        o.extend_from_slice(&self.challenger);
        o.extend_from_slice(&self.target);
        o.extend_from_slice(&self.nonce.to_le_bytes());
        o.extend_from_slice(&self.kind.encode());
        o.extend_from_slice(&self.issued_tick.to_le_bytes());
        o.extend_from_slice(&self.deadline_tick.to_le_bytes());
        o
    }
    pub fn id(&self) -> Digest {
        Sha256::digest(self.body()).into()
    }
    pub fn verify(&self) -> bool {
        gv_sig::verify(&self.challenger, CH_LABEL, &self.body(), &self.signature).is_ok()
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut o = self.body();
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
            challenger: r.take()?,
            target: r.take()?,
            nonce: u64::from_le_bytes(r.take()?),
            kind: ChallengeKind::decode(r.take()?)?,
            issued_tick: u64::from_le_bytes(r.take()?),
            deadline_tick: u64::from_le_bytes(r.take()?),
            signature: Signature::from_slice(r.bytes(SIG_LEN)?).map_err(|_| LogError::Malformed)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub challenge_id: Digest,
    pub responder: PlayerId,
    pub payload: Vec<u8>,
    pub signature: Signature,
}

impl Response {
    fn body(id: &Digest, responder: &PlayerId, payload: &[u8]) -> Vec<u8> {
        let mut o = Vec::with_capacity(64 + payload.len());
        o.extend_from_slice(id);
        o.extend_from_slice(responder);
        o.extend_from_slice(payload);
        o
    }
    pub fn sign(challenge: &Challenge, payload: Vec<u8>, key: &SigningKey) -> Self {
        let responder = key.id();
        let challenge_id = challenge.id();
        let signature = key.sign(RS_LABEL, &Self::body(&challenge_id, &responder, &payload));
        Self {
            challenge_id,
            responder,
            payload,
            signature,
        }
    }
    pub fn verify(&self) -> bool {
        self.payload.len() <= MAX_RESPONSE_PAYLOAD
            && gv_sig::verify(
                &self.responder,
                RS_LABEL,
                &Self::body(&self.challenge_id, &self.responder, &self.payload),
                &self.signature,
            )
            .is_ok()
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Self::body(&self.challenge_id, &self.responder, &self.payload);
        o.extend_from_slice(self.signature.as_bytes());
        o
    }
    pub fn decode(b: &[u8]) -> Result<Self, LogError> {
        if b.len() < 64 + SIG_LEN || b.len() > 64 + SIG_LEN + MAX_RESPONSE_PAYLOAD {
            return Err(LogError::Malformed);
        }
        let mut r = Reader(b);
        let challenge_id = r.take()?;
        let responder = r.take()?;
        let payload = r.bytes(b.len() - 64 - SIG_LEN)?.to_vec();
        Ok(Self {
            challenge_id,
            responder,
            payload,
            signature: Signature::from_slice(r.bytes(SIG_LEN)?).map_err(|_| LogError::Malformed)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    BadSignature,
    WrongMatch,
    NotForMe,
    BadDeadline,
    Replay,
    Flood,
    Unknown,
    WrongResponder,
}

#[derive(Clone, Debug)]
struct Pending {
    challenge: Challenge,
    retries: u8,
    /// Tick at which the next transition happens.
    due: u64,
    status: Status,
}

/// Retransmission/backoff parameters, in ticks.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    pub timeout: u64,
    pub grace: u64,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            timeout: 120,
            grace: 600,
        }
    }
}

/// Challenger-side state machine.
pub struct ChallengeBook {
    me: SigningKey,
    match_id: MatchId,
    timing: Timing,
    next_nonce: u64,
    pending: BTreeMap<Digest, Pending>,
    seen_responses: VecDeque<Digest>,
    /// Retransmissions and verdict changes to deliver to the caller.
    outbox: VecDeque<Challenge>,
    changes: VecDeque<(Digest, Status)>,
}

impl ChallengeBook {
    pub fn new(me: SigningKey, match_id: MatchId, timing: Timing) -> Self {
        Self {
            me,
            match_id,
            timing,
            next_nonce: 0,
            pending: BTreeMap::new(),
            seen_responses: VecDeque::new(),
            outbox: VecDeque::new(),
            changes: VecDeque::new(),
        }
    }
    #[cfg(test)]
    pub(crate) fn next_nonce_bump(&mut self) {
        self.next_nonce += 1;
    }
    pub fn open_count(&self) -> usize {
        self.pending
            .values()
            .filter(|p| p.status == Status::Pending)
            .count()
    }
    pub fn status(&self, id: &Digest) -> Option<Status> {
        self.pending.get(id).map(|p| p.status)
    }
    pub fn count(&self, s: Status) -> usize {
        self.pending.values().filter(|p| p.status == s).count()
    }
    pub fn poll_outbox(&mut self) -> Option<Challenge> {
        self.outbox.pop_front()
    }
    /// Challenges still awaiting a final answer (for persistence across restarts).
    pub fn open_challenges(&self) -> Vec<Challenge> {
        self.pending
            .values()
            .filter(|p| matches!(p.status, Status::Pending | Status::SuspectedNonCooperation))
            .map(|p| p.challenge.clone())
            .collect()
    }
    /// Reinstate a persisted challenge that I issued. It is re-sent with a fresh deadline so
    /// downtime is never held against the target; the original signed challenge is unchanged.
    pub fn resume(&mut self, c: &Challenge, now: u64) -> bool {
        if c.match_id != self.match_id
            || c.challenger != self.me.id()
            || !c.verify()
            || self.pending.contains_key(&c.id())
            || self.pending.len() >= MAX_PENDING_TOTAL
        {
            return false;
        }
        self.next_nonce = self.next_nonce.max(c.nonce.saturating_add(1));
        self.pending.insert(
            c.id(),
            Pending {
                challenge: c.clone(),
                retries: 0,
                due: now + self.timing.timeout,
                status: Status::Pending,
            },
        );
        self.outbox.push_back(c.clone());
        true
    }
    pub fn poll_change(&mut self) -> Option<(Digest, Status)> {
        self.changes.pop_front()
    }
    /// Issue a challenge. Bounded per target and in total.
    pub fn issue(
        &mut self,
        target: PlayerId,
        kind: ChallengeKind,
        now: u64,
    ) -> Result<Challenge, Reject> {
        let per_target = self
            .pending
            .values()
            .filter(|p| p.status == Status::Pending && p.challenge.target == target)
            .count();
        if per_target >= MAX_PENDING_PER_TARGET || self.pending.len() >= MAX_PENDING_TOTAL {
            return Err(Reject::Flood);
        }
        let mut c = Challenge {
            match_id: self.match_id,
            challenger: self.me.id(),
            target,
            nonce: self.next_nonce,
            kind,
            issued_tick: now,
            deadline_tick: now + self.timing.timeout,
            signature: Signature::zero(),
        };
        self.next_nonce += 1;
        c.signature = self.me.sign(CH_LABEL, &c.body());
        self.pending.insert(
            c.id(),
            Pending {
                challenge: c.clone(),
                retries: 0,
                due: c.deadline_tick,
                status: Status::Pending,
            },
        );
        self.outbox.push_back(c.clone());
        Ok(c)
    }
    /// Feed a response; `judge` decides whether the payload really answers the
    /// challenge kind (it has the application's data). A late but valid answer
    /// clears suspicion; an invalid one is INCONCLUSIVE, never proof.
    pub fn on_response<F: Fn(&Challenge, &[u8]) -> bool>(
        &mut self,
        r: &Response,
        judge: F,
    ) -> Result<Status, Reject> {
        if !r.verify() {
            return Err(Reject::BadSignature);
        }
        let key: Digest = Sha256::digest(r.encode()).into();
        if self.seen_responses.contains(&key) {
            return Err(Reject::Replay);
        }
        let p = self
            .pending
            .get_mut(&r.challenge_id)
            .ok_or(Reject::Unknown)?;
        if p.challenge.target != r.responder {
            return Err(Reject::WrongResponder);
        }
        if self.seen_responses.len() >= MAX_SEEN {
            self.seen_responses.pop_front();
        }
        self.seen_responses.push_back(key);
        if p.status == Status::Cleared {
            return Ok(Status::Cleared);
        }
        let s = if judge(&p.challenge, &r.payload) {
            Status::Cleared
        } else {
            Status::Inconclusive
        };
        p.status = s;
        self.changes.push_back((r.challenge_id, s));
        Ok(s)
    }
    /// Advance time: retransmit, then suspect, then mark unavailable.
    pub fn poll(&mut self, now: u64) {
        let (timing, mut resend, mut changed) = (self.timing, Vec::new(), Vec::new());
        for (id, p) in self.pending.iter_mut() {
            if now < p.due {
                continue;
            }
            match p.status {
                Status::Pending if p.retries < MAX_RETRIES => {
                    p.retries += 1;
                    p.due = now + (timing.timeout << p.retries.min(4));
                    resend.push(p.challenge.clone());
                }
                Status::Pending => {
                    p.status = Status::SuspectedNonCooperation;
                    p.due = now + timing.grace;
                    changed.push((*id, p.status));
                }
                // Keep asking at a slow, bounded rate so a late answer can still clear.
                Status::SuspectedNonCooperation if p.retries < MAX_RETRIES + SUSPECT_ROUNDS => {
                    p.retries += 1;
                    p.due = now + timing.grace;
                    resend.push(p.challenge.clone());
                }
                Status::SuspectedNonCooperation => {
                    p.status = Status::Unavailable;
                    p.due = u64::MAX;
                    changed.push((*id, p.status));
                }
                _ => {}
            }
        }
        self.outbox.extend(resend);
        self.changes.extend(changed);
    }
    /// Drop resolved challenges to bound memory.
    pub fn gc(&mut self) {
        self.pending
            .retain(|_, p| matches!(p.status, Status::Pending | Status::SuspectedNonCooperation));
    }
}

/// Responder-side admission control: authenticate, deduplicate, rate-limit.
#[derive(Debug)]
pub struct ChallengeGate {
    me: PlayerId,
    match_id: MatchId,
    seen: VecDeque<Digest>,
    seen_set: BTreeMap<Digest, u8>,
    per_challenger: BTreeMap<PlayerId, usize>,
}

impl ChallengeGate {
    pub const MAX_PER_CHALLENGER: usize = 256;
    /// A challenge is re-answered for its retransmissions, but only this many times.
    pub const MAX_ANSWERS_PER_CHALLENGE: u8 = 8;
    pub const MAX_WINDOW_TICKS: u64 = 3600;
    pub fn new(me: PlayerId, match_id: MatchId) -> Self {
        Self {
            me,
            match_id,
            seen: VecDeque::new(),
            seen_set: BTreeMap::new(),
            per_challenger: BTreeMap::new(),
        }
    }
    /// Ok(()) means: answer it exactly once.
    pub fn accept(&mut self, c: &Challenge, now: u64) -> Result<(), Reject> {
        if !c.verify() {
            return Err(Reject::BadSignature);
        }
        if c.match_id != self.match_id {
            return Err(Reject::WrongMatch);
        }
        if c.target != self.me || c.challenger == self.me {
            return Err(Reject::NotForMe);
        }
        if c.deadline_tick <= c.issued_tick
            || c.deadline_tick - c.issued_tick > Self::MAX_WINDOW_TICKS
            || c.issued_tick > now.saturating_add(Self::MAX_WINDOW_TICKS)
        {
            return Err(Reject::BadDeadline);
        }
        let id = c.id();
        if let Some(n) = self.seen_set.get_mut(&id) {
            // Retransmission of a challenge already admitted: answering again is
            // idempotent, but bounded so replay cannot be used to amplify.
            if *n >= Self::MAX_ANSWERS_PER_CHALLENGE {
                return Err(Reject::Replay);
            }
            *n += 1;
            return Ok(());
        }
        let n = self.per_challenger.entry(c.challenger).or_insert(0);
        if *n >= Self::MAX_PER_CHALLENGER {
            return Err(Reject::Flood);
        }
        *n += 1;
        if self.seen.len() >= MAX_SEEN {
            if let Some(old) = self.seen.pop_front() {
                self.seen_set.remove(&old);
            }
        }
        self.seen.push_back(id);
        self.seen_set.insert(id, 1);
        Ok(())
    }
}
