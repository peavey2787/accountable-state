//! Individual-peer resume: a participant that dropped (or restarted) proves it holds its key now,
//! announces a durable incarnation, and catches up from certified epochs. Everything it learns is
//! re-verified from signatures and replay; a peer that serves nothing useful costs only time.
use crate::CertifiedEpoch;
use gv_core::{MatchId, ParticipantId};
use gv_sig::{Signature, SigningKey, SIG_LEN};

const PROOF_LABEL: &str = "gv/resume-proof/v1";
/// Certified epochs in one `Epochs` message (a long gap is fetched in several rounds).
pub const MAX_EPOCHS_PER_MSG: usize = 8;
/// Largest encoded `Epochs` body accepted.
pub const MAX_EPOCHS_BYTES: usize = 8 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResumeError {
    Malformed,
    BadSignature,
}

/// The prover's answer to a [`ResumeMsg::Challenge`]. The verifier's fresh nonce makes it
/// single-use: a recorded proof cannot be replayed on a later connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedProof {
    pub match_id: MatchId,
    pub participant: ParticipantId,
    /// Durable per-storage counter, incremented at every open. A larger one supersedes.
    pub incarnation: u64,
    /// Random per process. Equal incarnations with different ids are duplicate processes.
    pub session_id: [u8; 16],
    /// The prover's verified tick (a hint for the verifier; never trusted).
    pub tip: u64,
    pub nonce: [u8; 16],
    pub signature: Signature,
}

impl SignedProof {
    pub const SIZE: usize = 32 + 32 + 8 + 16 + 8 + 16 + SIG_LEN;

    fn message(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(Self::SIZE - SIG_LEN);
        m.extend_from_slice(&self.match_id);
        m.extend_from_slice(&self.participant);
        m.extend_from_slice(&self.incarnation.to_le_bytes());
        m.extend_from_slice(&self.session_id);
        m.extend_from_slice(&self.tip.to_le_bytes());
        m.extend_from_slice(&self.nonce);
        m
    }

    pub fn sign(
        match_id: MatchId,
        incarnation: u64,
        session_id: [u8; 16],
        tip: u64,
        nonce: [u8; 16],
        key: &SigningKey,
    ) -> Self {
        let mut p = Self {
            match_id,
            participant: key.id(),
            incarnation,
            session_id,
            tip,
            nonce,
            signature: Signature::zero(),
        };
        p.signature = key.sign(PROOF_LABEL, &p.message());
        p
    }

    pub fn verify(&self) -> Result<(), ResumeError> {
        gv_sig::verify(
            &self.participant,
            PROOF_LABEL,
            &self.message(),
            &self.signature,
        )
        .map_err(|_| ResumeError::BadSignature)
    }

    /// Which of two live claims to the same identity wins; the same on every observer.
    pub fn outranks(&self, other: &Self) -> bool {
        (self.incarnation, std::cmp::Reverse(self.session_id))
            > (other.incarnation, std::cmp::Reverse(other.session_id))
    }

    fn encode(&self) -> Vec<u8> {
        let mut b = self.message();
        b.extend_from_slice(self.signature.as_bytes());
        b
    }

    fn decode(b: &[u8]) -> Result<Self, ResumeError> {
        if b.len() != Self::SIZE {
            return Err(ResumeError::Malformed);
        }
        let arr = |p: usize| -> [u8; 32] { b[p..p + 32].try_into().unwrap_or([0; 32]) };
        let word = |p: usize| u64::from_le_bytes(b[p..p + 8].try_into().unwrap_or([0; 8]));
        let p = Self {
            match_id: arr(0),
            participant: arr(32),
            incarnation: word(64),
            session_id: b[72..88].try_into().unwrap_or([0; 16]),
            tip: word(88),
            nonce: b[96..112].try_into().unwrap_or([0; 16]),
            signature: Signature::from_slice(&b[112..]).map_err(|_| ResumeError::Malformed)?,
        };
        p.verify()?;
        Ok(p)
    }
}

#[derive(Clone, Debug)]
pub enum ResumeMsg {
    /// "Prove you hold your key now": sent when a link comes up.
    Challenge {
        nonce: [u8; 16],
    },
    Proof(SignedProof),
    /// "Send me the certified epochs from `tip` on."
    Sync {
        tip: u64,
    },
    /// Certified epochs in order; `tip` is where the sender's own chain ends.
    Epochs {
        epochs: Vec<CertifiedEpoch>,
        tip: u64,
    },
    /// Your proof lost against a newer or winning claim to your identity.
    Superseded,
}

impl ResumeMsg {
    pub fn encode(&self) -> Result<Vec<u8>, ResumeError> {
        let mut out = Vec::new();
        match self {
            Self::Challenge { nonce } => {
                out.push(1);
                out.extend_from_slice(nonce);
            }
            Self::Proof(p) => {
                out.push(2);
                out.extend_from_slice(&p.encode());
            }
            Self::Sync { tip } => {
                out.push(3);
                out.extend_from_slice(&tip.to_le_bytes());
            }
            Self::Epochs { epochs, tip } => {
                out.push(4);
                out.extend_from_slice(&tip.to_le_bytes());
                out.push(u8::try_from(epochs.len()).map_err(|_| ResumeError::Malformed)?);
                for e in epochs {
                    let body = e.encode().map_err(|_| ResumeError::Malformed)?;
                    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
                    out.extend_from_slice(&body);
                }
            }
            Self::Superseded => out.push(5),
        }
        Ok(out)
    }

    pub fn decode(b: &[u8]) -> Result<Self, ResumeError> {
        let (tag, body) = b.split_first().ok_or(ResumeError::Malformed)?;
        match (tag, body.len()) {
            (1, 16) => Ok(Self::Challenge {
                nonce: body.try_into().map_err(|_| ResumeError::Malformed)?,
            }),
            (2, _) => SignedProof::decode(body).map(Self::Proof),
            (3, 8) => Ok(Self::Sync {
                tip: u64::from_le_bytes(body.try_into().map_err(|_| ResumeError::Malformed)?),
            }),
            (4, _) => Self::decode_epochs(body),
            (5, 0) => Ok(Self::Superseded),
            _ => Err(ResumeError::Malformed),
        }
    }

    fn decode_epochs(body: &[u8]) -> Result<Self, ResumeError> {
        if body.len() > MAX_EPOCHS_BYTES || body.len() < 9 {
            return Err(ResumeError::Malformed);
        }
        let tip = u64::from_le_bytes(body[..8].try_into().map_err(|_| ResumeError::Malformed)?);
        let count = usize::from(body[8]);
        if count > MAX_EPOCHS_PER_MSG {
            return Err(ResumeError::Malformed);
        }
        let mut rest = &body[9..];
        let mut epochs = Vec::with_capacity(count);
        for _ in 0..count {
            let (len, tail) = rest.split_at_checked(4).ok_or(ResumeError::Malformed)?;
            let len = u32::from_le_bytes(len.try_into().map_err(|_| ResumeError::Malformed)?);
            let (one, tail) = tail
                .split_at_checked(len as usize)
                .ok_or(ResumeError::Malformed)?;
            epochs.push(CertifiedEpoch::decode(one).map_err(|_| ResumeError::Malformed)?);
            rest = tail;
        }
        rest.is_empty()
            .then_some(Self::Epochs { epochs, tip })
            .ok_or(ResumeError::Malformed)
    }
}
