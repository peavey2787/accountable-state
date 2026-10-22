//! Self-contained, offline-verifiable proofs of misbehavior that need no trusted
//! third party: every one is checked from signatures and hashes alone.
use super::log::{Authenticator, LogError, Reader, Segment};
use crate::SignedCheckpoint;
use gv_codec::SignedEventBatch;
use gv_core::{Digest, ParticipantId};
use sha2::{Digest as _, Sha256};

pub const MAX_EVIDENCE_BYTES: usize = 1 << 20;
pub(super) const MAGIC: &[u8] = b"GV-ACCOUNTABILITY-EVIDENCE/V1\0";
const ID_DOMAIN: &[u8] = b"gv/audit/evidence-id/v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceError {
    Malformed,
    TooLarge,
    BadSignature,
    NotAViolation,
}

/// What a valid piece of evidence proves about its accused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proof {
    /// Two conflicting signed statements for the same slot.
    Equivocation(ParticipantId),
}

#[derive(Clone, Debug)]
pub enum Evidence {
    /// Same owner, match and seq; different heads.
    ConflictingAuthenticators(Authenticator, Authenticator),
    /// A later authenticator whose chain does not contain an earlier one (rollback
    /// or rewritten history). `segment` runs (earlier.seq, later.seq].
    Fork {
        earlier: Authenticator,
        later: Authenticator,
        segment: Segment,
    },
    /// Two signed event batches from one participant that disagree about a tick.
    ConflictingBatches(SignedEventBatch, SignedEventBatch),
    /// Two signed checkpoints for the same slot with different claims.
    ConflictingCheckpoints(SignedCheckpoint, SignedCheckpoint),
}

fn log_err(_: LogError) -> EvidenceError {
    EvidenceError::BadSignature
}

impl Evidence {
    /// Verify cryptographically and structurally. Ok(proof) means the accused
    /// provably signed contradictory statements; any failure proves nothing.
    pub fn verify(&self) -> Result<Proof, EvidenceError> {
        match self {
            Self::ConflictingAuthenticators(a, b) => {
                a.verify().map_err(log_err)?;
                b.verify().map_err(log_err)?;
                if a.owner != b.owner
                    || a.match_id != b.match_id
                    || a.ruleset != b.ruleset
                    || a.seq != b.seq
                    || a.head == b.head
                {
                    return Err(EvidenceError::NotAViolation);
                }
                Ok(Proof::Equivocation(a.owner))
            }
            Self::Fork {
                earlier,
                later,
                segment,
            } => {
                earlier.verify().map_err(log_err)?;
                later.verify().map_err(log_err)?;
                if earlier.owner != later.owner
                    || earlier.match_id != later.match_id
                    || earlier.ruleset != later.ruleset
                    || earlier.seq >= later.seq
                    || segment.owner != later.owner
                    || segment.match_id != later.match_id
                    || segment.start_seq != earlier.seq
                    || segment.end_seq() != later.seq
                    || segment.end_head().map_err(log_err)? != later.head
                    // The chain that `later` commits to passes through a head at
                    // `earlier.seq` different from the one `earlier` committed to.
                    || segment.prev_head == earlier.head
                {
                    return Err(EvidenceError::NotAViolation);
                }
                Ok(Proof::Equivocation(later.owner))
            }
            Self::ConflictingBatches(a, b) => {
                a.verify().map_err(|_| EvidenceError::BadSignature)?;
                b.verify().map_err(|_| EvidenceError::BadSignature)?;
                let (x, y) = (&a.record, &b.record);
                if x.participant != y.participant || x.match_id != y.match_id {
                    return Err(EvidenceError::NotAViolation);
                }
                let lo = x.start_tick.max(y.start_tick);
                let hi = (x.start_tick + u64::from(x.tick_count))
                    .min(y.start_tick + u64::from(y.tick_count));
                let mut t = lo;
                while t < hi {
                    let ex = x
                        .events_at((t - x.start_tick) as u32)
                        .map_err(|_| EvidenceError::Malformed)?;
                    let ey = y
                        .events_at((t - y.start_tick) as u32)
                        .map_err(|_| EvidenceError::Malformed)?;
                    if ex != ey {
                        return Ok(Proof::Equivocation(x.participant));
                    }
                    t += 1;
                }
                // Agreeing overlap (e.g. a re-signed prefix) is not equivocation.
                Err(EvidenceError::NotAViolation)
            }
            Self::ConflictingCheckpoints(a, b) => {
                a.verify().map_err(|_| EvidenceError::BadSignature)?;
                b.verify().map_err(|_| EvidenceError::BadSignature)?;
                let (x, y) = (&a.claim, &b.claim);
                if a.signer != b.signer
                    || x.match_id != y.match_id
                    || x.session != y.session
                    || x.ruleset != y.ruleset
                    || x.epoch_start != y.epoch_start
                    || x.epoch_length != y.epoch_length
                    || x.previous_checkpoint != y.previous_checkpoint
                    || x.digest() == y.digest()
                {
                    return Err(EvidenceError::NotAViolation);
                }
                Ok(Proof::Equivocation(a.signer))
            }
        }
    }

    pub fn accused(&self) -> ParticipantId {
        match self {
            Self::ConflictingAuthenticators(a, _) => a.owner,
            Self::Fork { later, .. } => later.owner,
            Self::ConflictingBatches(a, _) => a.record.participant,
            Self::ConflictingCheckpoints(a, _) => a.signer,
        }
    }

    pub fn match_id(&self) -> gv_core::MatchId {
        match self {
            Self::ConflictingAuthenticators(a, _) => a.match_id,
            Self::Fork { later, .. } => later.match_id,
            Self::ConflictingBatches(a, _) => a.record.match_id,
            Self::ConflictingCheckpoints(a, _) => a.claim.match_id,
        }
    }

    fn tag(&self) -> u8 {
        match self {
            Self::ConflictingAuthenticators(..) => 1,
            Self::Fork { .. } => 2,
            Self::ConflictingBatches(..) => 3,
            Self::ConflictingCheckpoints(..) => 4,
        }
    }

    fn parts(&self) -> Result<Vec<Vec<u8>>, EvidenceError> {
        let batch = |b: &SignedEventBatch| b.encode().map_err(|_| EvidenceError::Malformed);
        Ok(match self {
            Self::ConflictingAuthenticators(a, b) => vec![a.encode(), b.encode()],
            Self::Fork {
                earlier,
                later,
                segment,
            } => vec![earlier.encode(), later.encode(), segment.encode()],
            Self::ConflictingBatches(a, b) => vec![batch(a)?, batch(b)?],
            Self::ConflictingCheckpoints(a, b) => vec![a.encode(), b.encode()],
        })
    }

    /// Canonical id: order-independent for symmetric pairs, so the same proof found
    /// by different peers (in either order) dedupes to one ledger entry.
    pub fn id(&self) -> Result<Digest, EvidenceError> {
        let mut parts = self.parts()?;
        if !matches!(self, Self::Fork { .. }) {
            parts.sort();
        }
        let mut s = Sha256::new();
        s.update(ID_DOMAIN);
        s.update([self.tag()]);
        for p in &parts {
            s.update((p.len() as u64).to_le_bytes());
            s.update(Sha256::digest(p));
        }
        Ok(s.finalize().into())
    }

    pub fn encode(&self) -> Result<Vec<u8>, EvidenceError> {
        let mut o = MAGIC.to_vec();
        o.push(self.tag());
        for p in self.parts()? {
            o.extend_from_slice(&(p.len() as u32).to_le_bytes());
            o.extend_from_slice(&p);
        }
        if o.len() > MAX_EVIDENCE_BYTES {
            return Err(EvidenceError::TooLarge);
        }
        Ok(o)
    }

    pub fn decode(b: &[u8]) -> Result<Self, EvidenceError> {
        if b.len() > MAX_EVIDENCE_BYTES {
            return Err(EvidenceError::TooLarge);
        }
        let m = |_: LogError| EvidenceError::Malformed;
        let rest = b.strip_prefix(MAGIC).ok_or(EvidenceError::Malformed)?;
        let (tag, rest) = rest.split_first().ok_or(EvidenceError::Malformed)?;
        let n = if *tag == 2 { 3 } else { 2 };
        let mut r = Reader(rest);
        let mut parts: Vec<&[u8]> = Vec::new();
        for _ in 0..n {
            let len = u32::from_le_bytes(r.take().map_err(m)?) as usize;
            parts.push(r.bytes(len).map_err(m)?);
        }
        if !r.0.is_empty() {
            return Err(EvidenceError::Malformed);
        }
        let auth = |x: &[u8]| Authenticator::decode(x).map_err(m);
        let batch = |x: &[u8]| SignedEventBatch::decode(x).map_err(|_| EvidenceError::Malformed);
        let cp = |x: &[u8]| SignedCheckpoint::decode(x).map_err(|_| EvidenceError::Malformed);
        Ok(match tag {
            1 => Self::ConflictingAuthenticators(auth(parts[0])?, auth(parts[1])?),
            2 => Self::Fork {
                earlier: auth(parts[0])?,
                later: auth(parts[1])?,
                segment: Segment::decode(parts[2]).map_err(m)?,
            },
            3 => Self::ConflictingBatches(batch(parts[0])?, batch(parts[1])?),
            4 => Self::ConflictingCheckpoints(cp(parts[0])?, cp(parts[1])?),
            _ => return Err(EvidenceError::Malformed),
        })
    }
}

/// Detect a conflict between a newly seen authenticator and a remembered one.
pub fn compare_authenticators(
    known: &Authenticator,
    new: &Authenticator,
    segment: Option<Segment>,
) -> Option<Evidence> {
    if known.owner != new.owner || known.match_id != new.match_id {
        return None;
    }
    if known.seq == new.seq && known.head != new.head {
        return Some(Evidence::ConflictingAuthenticators(
            known.clone(),
            new.clone(),
        ));
    }
    let (earlier, later) = if known.seq < new.seq {
        (known, new)
    } else {
        (new, known)
    };
    segment
        .filter(|s| s.start_seq == earlier.seq && earlier.seq < later.seq)
        .map(|segment| Evidence::Fork {
            earlier: earlier.clone(),
            later: later.clone(),
            segment,
        })
}
