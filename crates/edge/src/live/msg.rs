//! Reliable pipeline messages exchanged between the participants of one session.
use crate::audit::{Authenticator, Challenge, Evidence, Response};
use crate::live::resume::ResumeMsg;
use crate::quorum::QuorumMsg;
use crate::{SignedBatchCommitment, SignedCheckpoint, SignedEpochLock};
use gv_codec::SignedEventBatch;
use gv_core::{MatchId, ParticipantId, MAX_PARTICIPANTS};
use gv_sig::{Signature, SigningKey, SIG_LEN};

const SEAL_LABEL: &str = "gv/live-seal/v2";

fn malformed<E>(_: E) -> PipeError {
    PipeError::Malformed
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PipeError {
    Malformed,
    BadSignature,
}

/// Where the transport delivers a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dest {
    /// Every other participant.
    All,
    /// One participant (a challenge, its answer, an anchor request).
    Peer(ParticipantId),
}

/// A message plus its destination. The transport authenticates the link, so the receiver learns
/// the sender from the connection and passes it to [`crate::live::Pipeline::on_message`].
#[derive(Clone, Debug)]
pub struct Outgoing {
    pub to: Dest,
    pub msg: PipeMsg,
}

impl Outgoing {
    pub fn all(msg: PipeMsg) -> Self {
        Self { to: Dest::All, msg }
    }
    pub fn to(peer: ParticipantId, msg: PipeMsg) -> Self {
        Self {
            to: Dest::Peer(peer),
            msg,
        }
    }
}

/// A participant announces that their inputs are sealed for a fixed window. Signed, so it
/// cannot be forged or silently shortened by anyone else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSeal {
    pub match_id: MatchId,
    pub owner: ParticipantId,
    pub start_tick: u64,
    pub ticks: u32,
    pub nonce: [u8; 16],
    pub signature: Signature,
}
impl SignedSeal {
    pub const SIZE: usize = 32 + 32 + 8 + 4 + 16 + SIG_LEN;
    fn message(&self) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&self.match_id);
        m.extend_from_slice(&self.owner);
        m.extend_from_slice(&self.start_tick.to_le_bytes());
        m.extend_from_slice(&self.ticks.to_le_bytes());
        m.extend_from_slice(&self.nonce);
        m
    }
    pub fn sign(
        match_id: MatchId,
        start_tick: u64,
        ticks: u32,
        nonce: [u8; 16],
        key: &SigningKey,
    ) -> Self {
        let mut s = Self {
            match_id,
            owner: key.id(),
            start_tick,
            ticks,
            nonce,
            signature: Signature::zero(),
        };
        s.signature = key.sign(SEAL_LABEL, &s.message());
        s
    }
    pub fn verify(&self) -> Result<(), PipeError> {
        gv_sig::verify(&self.owner, SEAL_LABEL, &self.message(), &self.signature)
            .map_err(|_| PipeError::BadSignature)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.message();
        b.extend_from_slice(self.signature.as_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, PipeError> {
        if b.len() != Self::SIZE {
            return Err(PipeError::Malformed);
        }
        let arr = |p: usize| -> [u8; 32] { b[p..p + 32].try_into().unwrap_or([0; 32]) };
        let s = Self {
            match_id: arr(0),
            owner: arr(32),
            start_tick: u64::from_le_bytes(b[64..72].try_into().unwrap_or([0; 8])),
            ticks: u32::from_le_bytes(b[72..76].try_into().unwrap_or([0; 4])),
            nonce: b[76..92].try_into().unwrap_or([0; 16]),
            signature: Signature::from_slice(&b[92..]).map_err(|_| PipeError::Malformed)?,
        };
        s.verify()?;
        Ok(s)
    }
}

/// Opening of a sealed-window commitment: the signed batch and its secret blind.
#[derive(Clone, Debug)]
pub struct Opening {
    pub batch: SignedEventBatch,
    pub blind: [u8; 32],
}

/// The coordinator's decision about which batches an epoch contains when some participants have
/// not answered in time. It carries the participants' own signed batches, so it cannot invent
/// input; it can only choose the subset, and a different choice yields a different checkpoint
/// that honest signers will not co-sign.
#[derive(Clone, Debug)]
pub struct Close {
    pub epoch_start: u64,
    pub tick_count: u32,
    /// Coordinator rotation step this decision belongs to.
    pub attempt: u8,
    pub batches: Vec<SignedEventBatch>,
}
impl Close {
    fn encode(&self) -> Result<Vec<u8>, PipeError> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.epoch_start.to_le_bytes());
        out.extend_from_slice(&self.tick_count.to_le_bytes());
        out.push(self.attempt);
        out.extend_from_slice(&(self.batches.len() as u16).to_le_bytes());
        for b in &self.batches {
            let bytes = b.encode().map_err(|_| PipeError::Malformed)?;
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&bytes);
        }
        Ok(out)
    }
    fn decode(b: &[u8]) -> Result<Self, PipeError> {
        let bad = || PipeError::Malformed;
        let head = b.get(..15).ok_or_else(bad)?;
        let epoch_start = u64::from_le_bytes(head[..8].try_into().map_err(|_| bad())?);
        let tick_count = u32::from_le_bytes(head[8..12].try_into().map_err(|_| bad())?);
        let attempt = head[12];
        let count = usize::from(u16::from_le_bytes([head[13], head[14]]));
        if count > MAX_PARTICIPANTS {
            return Err(bad());
        }
        let mut rest = &b[15..];
        let mut batches = Vec::with_capacity(count);
        for _ in 0..count {
            let len_bytes: [u8; 4] = rest
                .get(..4)
                .ok_or_else(bad)?
                .try_into()
                .map_err(|_| bad())?;
            let len = u32::from_le_bytes(len_bytes) as usize;
            let end = 4usize.checked_add(len).ok_or_else(bad)?;
            let body = rest.get(4..end).ok_or_else(bad)?;
            batches.push(SignedEventBatch::decode(body).map_err(|_| bad())?);
            rest = &rest[end..];
        }
        if !rest.is_empty() {
            return Err(bad());
        }
        Ok(Self {
            epoch_start,
            tick_count,
            attempt,
            batches,
        })
    }
}

#[derive(Clone, Debug)]
pub enum PipeMsg {
    /// Signed epoch input batch (public play).
    Batch(SignedEventBatch),
    Checkpoint(SignedCheckpoint),
    /// Sealed window: signed commitment to a batch that stays secret for now.
    Commit(SignedBatchCommitment),
    /// `start_tick` routes the lock to its cell; the lock's root binds the commitment set.
    Lock {
        start_tick: u64,
        lock: SignedEpochLock,
    },
    /// Opens a committed batch.
    Reveal(Opening),
    Seal(SignedSeal),
    Close(Close),
    /// Signed log head, once per epoch (accountability, never blocks play).
    Auth(Authenticator),
    Challenge(Challenge),
    Response(Response),
    /// Offline-verifiable misbehavior proof (relayed evidence).
    Evidence(Box<Evidence>),
    /// "Send me the highest signed head of mine you hold" (restart / reconnection recovery).
    AnchorReq,
    /// Answer: the requester's own signed head, or `None` when the responder holds none. The
    /// head is signed by the requester, so a responder can withhold or replay an old one but
    /// never forge a newer one.
    Anchor(Option<Authenticator>),
    /// Head-register traffic between a player and a pinned witness (never between players).
    Quorum(QuorumMsg),
    /// Reconnection: key-possession proof, incarnation fencing and certified-epoch catch-up.
    Resume(ResumeMsg),
}

impl PipeMsg {
    pub fn encode(&self) -> Result<Vec<u8>, PipeError> {
        let (tag, body) = match self {
            Self::Batch(b) => (1u8, b.encode().map_err(malformed)?),
            Self::Checkpoint(c) => (2, c.encode()),
            Self::Commit(c) => (3, c.encode()),
            Self::Lock { start_tick, lock } => {
                let mut body = start_tick.to_le_bytes().to_vec();
                body.extend_from_slice(&lock.encode());
                (4, body)
            }
            Self::Reveal(o) => {
                let mut body = o.blind.to_vec();
                body.extend_from_slice(&o.batch.encode().map_err(malformed)?);
                (5, body)
            }
            Self::Seal(h) => (6, h.encode()),
            Self::Close(c) => (7, c.encode()?),
            Self::Auth(a) => (8, a.encode()),
            Self::Challenge(c) => (9, c.encode()),
            Self::Response(r) => (10, r.encode()),
            Self::Evidence(e) => (11, e.encode().map_err(malformed)?),
            Self::AnchorReq => (12, Vec::new()),
            Self::Anchor(a) => (13, a.as_ref().map_or_else(Vec::new, Authenticator::encode)),
            Self::Quorum(q) => (14, q.encode()),
            Self::Resume(r) => (15, r.encode().map_err(malformed)?),
        };
        let mut out = Vec::with_capacity(body.len() + 1);
        out.push(tag);
        out.extend_from_slice(&body);
        Ok(out)
    }
    pub fn decode(b: &[u8]) -> Result<Self, PipeError> {
        let (tag, body) = b.split_first().ok_or(PipeError::Malformed)?;
        Ok(match tag {
            1 => Self::Batch(SignedEventBatch::decode(body).map_err(malformed)?),
            2 => Self::Checkpoint(SignedCheckpoint::decode(body).map_err(malformed)?),
            3 => Self::Commit(SignedBatchCommitment::decode(body).map_err(malformed)?),
            4 => {
                let (start, lock) = body.split_at_checked(8).ok_or(PipeError::Malformed)?;
                Self::Lock {
                    start_tick: u64::from_le_bytes(
                        start.try_into().map_err(|_| PipeError::Malformed)?,
                    ),
                    lock: SignedEpochLock::decode(lock).map_err(malformed)?,
                }
            }
            5 => {
                let (blind, batch) = body.split_at_checked(32).ok_or(PipeError::Malformed)?;
                Self::Reveal(Opening {
                    blind: blind.try_into().map_err(|_| PipeError::Malformed)?,
                    batch: SignedEventBatch::decode(batch).map_err(malformed)?,
                })
            }
            6 => Self::Seal(SignedSeal::decode(body)?),
            7 => Self::Close(Close::decode(body)?),
            8 => Self::Auth(Authenticator::decode(body).map_err(malformed)?),
            9 => Self::Challenge(Challenge::decode(body).map_err(malformed)?),
            10 => Self::Response(Response::decode(body).map_err(malformed)?),
            11 => Self::Evidence(Box::new(Evidence::decode(body).map_err(malformed)?)),
            12 if body.is_empty() => Self::AnchorReq,
            13 if body.is_empty() => Self::Anchor(None),
            13 => Self::Anchor(Some(Authenticator::decode(body).map_err(malformed)?)),
            14 => Self::Quorum(QuorumMsg::decode(body).map_err(malformed)?),
            15 => Self::Resume(ResumeMsg::decode(body).map_err(malformed)?),
            _ => return Err(PipeError::Malformed),
        })
    }
}
