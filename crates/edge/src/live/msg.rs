//! Reliable pipeline messages exchanged between the two players.
use crate::audit::{Authenticator, Challenge, Evidence, Response};
use crate::{SignedBatchCommitment, SignedCheckpoint, SignedEpochLock};
use gv_codec::SignedPackedControls;
use gv_core::{MatchId, PlayerId};
use gv_sig::{Signature, SigningKey, SIG_LEN};

const HIDE_LABEL: &str = "gv/live-hide/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PipeError {
    Malformed,
    BadSignature,
}

/// A player announces that their location is hidden for a fixed window.
/// Signed, so it cannot be forged or silently shortened by the opponent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHide {
    pub match_id: MatchId,
    pub player: PlayerId,
    pub start_tick: u64,
    pub ticks: u32,
    pub nonce: [u8; 16],
    pub signature: Signature,
}
impl SignedHide {
    pub const SIZE: usize = 32 + 32 + 8 + 4 + 16 + SIG_LEN;
    fn message(&self) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&self.match_id);
        m.extend_from_slice(&self.player);
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
            player: key.id(),
            start_tick,
            ticks,
            nonce,
            signature: Signature::zero(),
        };
        s.signature = key.sign(HIDE_LABEL, &s.message());
        s
    }
    pub fn verify(&self) -> Result<(), PipeError> {
        gv_sig::verify(&self.player, HIDE_LABEL, &self.message(), &self.signature)
            .map_err(|_| PipeError::BadSignature)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::SIZE);
        b.extend_from_slice(&self.match_id);
        b.extend_from_slice(&self.player);
        b.extend_from_slice(&self.start_tick.to_le_bytes());
        b.extend_from_slice(&self.ticks.to_le_bytes());
        b.extend_from_slice(&self.nonce);
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
            player: arr(32),
            start_tick: u64::from_le_bytes(b[64..72].try_into().unwrap_or([0; 8])),
            ticks: u32::from_le_bytes(b[72..76].try_into().unwrap_or([0; 4])),
            nonce: b[76..92].try_into().unwrap_or([0; 16]),
            signature: Signature::from_slice(&b[92..]).map_err(|_| PipeError::Malformed)?,
        };
        s.verify()?;
        Ok(s)
    }
}

/// Opening of a hidden-window commitment: the signed batch and its secret blind.
#[derive(Clone, Debug)]
pub struct Opening {
    pub batch: SignedPackedControls,
    pub blind: [u8; 32],
}

#[derive(Clone, Debug)]
pub enum PipeMsg {
    /// Signed epoch input batch (public play).
    Batch(SignedPackedControls),
    Checkpoint(SignedCheckpoint),
    /// Hidden window: signed commitment to a batch that stays secret for now.
    Commit(SignedBatchCommitment),
    Lock(SignedEpochLock),
    /// Opens a committed batch.
    Reveal(Opening),
    Hide(SignedHide),
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
}

impl PipeMsg {
    pub fn encode(&self) -> Result<Vec<u8>, PipeError> {
        let (tag, body) = match self {
            Self::Batch(b) => (1u8, b.encode().map_err(|_| PipeError::Malformed)?),
            Self::Checkpoint(c) => (2, c.encode()),
            Self::Commit(c) => (3, c.encode()),
            Self::Lock(l) => (4, l.encode()),
            Self::Reveal(o) => {
                let mut body = o.blind.to_vec();
                body.extend_from_slice(&o.batch.encode().map_err(|_| PipeError::Malformed)?);
                (5, body)
            }
            Self::Hide(h) => (6, h.encode()),
            Self::Auth(a) => (7, a.encode()),
            Self::Challenge(c) => (8, c.encode()),
            Self::Response(r) => (9, r.encode()),
            Self::Evidence(e) => (10, e.encode().map_err(|_| PipeError::Malformed)?),
            Self::AnchorReq => (11, Vec::new()),
            Self::Anchor(a) => (12, a.as_ref().map_or_else(Vec::new, Authenticator::encode)),
        };
        let mut out = Vec::with_capacity(body.len() + 1);
        out.push(tag);
        out.extend_from_slice(&body);
        Ok(out)
    }
    pub fn decode(b: &[u8]) -> Result<Self, PipeError> {
        let (tag, body) = b.split_first().ok_or(PipeError::Malformed)?;
        Ok(match tag {
            1 => Self::Batch(SignedPackedControls::decode(body).map_err(|_| PipeError::Malformed)?),
            2 => {
                Self::Checkpoint(SignedCheckpoint::decode(body).map_err(|_| PipeError::Malformed)?)
            }
            3 => {
                Self::Commit(SignedBatchCommitment::decode(body).map_err(|_| PipeError::Malformed)?)
            }
            4 => Self::Lock(SignedEpochLock::decode(body).map_err(|_| PipeError::Malformed)?),
            5 => {
                if body.len() < 32 {
                    return Err(PipeError::Malformed);
                }
                let (blind, batch) = body.split_at(32);
                Self::Reveal(Opening {
                    blind: blind.try_into().map_err(|_| PipeError::Malformed)?,
                    batch: SignedPackedControls::decode(batch).map_err(|_| PipeError::Malformed)?,
                })
            }
            6 => Self::Hide(SignedHide::decode(body)?),
            7 => Self::Auth(Authenticator::decode(body).map_err(|_| PipeError::Malformed)?),
            8 => Self::Challenge(Challenge::decode(body).map_err(|_| PipeError::Malformed)?),
            9 => Self::Response(Response::decode(body).map_err(|_| PipeError::Malformed)?),
            10 => Self::Evidence(Box::new(
                Evidence::decode(body).map_err(|_| PipeError::Malformed)?,
            )),
            11 if body.is_empty() => Self::AnchorReq,
            12 if body.is_empty() => Self::Anchor(None),
            12 => Self::Anchor(Some(
                Authenticator::decode(body).map_err(|_| PipeError::Malformed)?,
            )),
            _ => return Err(PipeError::Malformed),
        })
    }
}
