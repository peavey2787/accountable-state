//! Self-contained, offline-verifiable proofs of misbehavior that need no trusted
//! third party: every one is checked from signatures and hashes alone.
use super::log::{Authenticator, LogError, Reader, Segment};
use crate::quorum::{Certificate, WitnessSet};
use crate::SignedCheckpoint;
use gv_codec::SignedEventBatch;
use gv_core::{Digest, ParticipantId};
use sha2::{Digest as _, Sha256};

pub const MAX_EVIDENCE_BYTES: usize = 1 << 20;
pub(super) const MAGIC: &[u8] = b"GV-ACCOUNTABILITY-EVIDENCE/V1\0";
/// Evidence parts: an inner proof plus up to two certificates.
const MAX_PARTS: usize = 3;
const ID_DOMAIN: &[u8] = b"gv/audit/evidence-id/v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceError {
    Malformed,
    TooLarge,
    BadSignature,
    NotAViolation,
    /// Log-equivocation evidence whose heads are not committed by a witness quorum. Under a
    /// pinned witness set an unreleased (tentative) head proves nothing about its signer.
    Uncertified,
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
    /// Log-equivocation evidence plus a quorum certificate for every authenticator in it, so a
    /// head that was only ever tentative (never released) cannot convict its signer.
    Certified {
        inner: Box<Evidence>,
        certs: Vec<Certificate>,
    },
}

fn log_err(_: LogError) -> EvidenceError {
    EvidenceError::BadSignature
}

impl Evidence {
    /// Verify cryptographically and structurally. Ok(proof) means the accused
    /// provably signed contradictory statements; any failure proves nothing.
    pub fn verify(&self) -> Result<Proof, EvidenceError> {
        self.verify_under(None)
    }

    /// As [`Self::verify`], under a pinned witness set. With a set, log-equivocation evidence
    /// is accepted only as [`Evidence::Certified`]; without one, certified evidence cannot be
    /// checked and is refused.
    pub fn verify_under(&self, witnesses: Option<&WitnessSet>) -> Result<Proof, EvidenceError> {
        match (self, witnesses) {
            (Self::Certified { inner, certs }, Some(set)) => {
                return inner.verify_certified(certs, set)
            }
            (Self::Certified { .. }, None) => return Err(EvidenceError::Uncertified),
            (Self::ConflictingAuthenticators(..) | Self::Fork { .. }, Some(_)) => {
                return Err(EvidenceError::Uncertified)
            }
            _ => {}
        }
        self.verify_signed()
    }

    fn verify_certified(
        &self,
        certs: &[Certificate],
        set: &WitnessSet,
    ) -> Result<Proof, EvidenceError> {
        let heads: Vec<&Authenticator> = match self {
            Self::ConflictingAuthenticators(a, b) => vec![a, b],
            Self::Fork { earlier, later, .. } => vec![earlier, later],
            _ => return Err(EvidenceError::NotAViolation),
        };
        for a in heads {
            let committed = certs
                .iter()
                .any(|c| c.claim.auth == *a && c.verify(set).is_ok());
            if !committed {
                return Err(EvidenceError::Uncertified);
            }
        }
        self.verify_signed()
    }

    fn verify_signed(&self) -> Result<Proof, EvidenceError> {
        match self {
            Self::Certified { inner, .. } => inner.verify_signed(),
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
            Self::Certified { inner, .. } => inner.accused(),
        }
    }

    pub fn match_id(&self) -> gv_core::MatchId {
        match self {
            Self::ConflictingAuthenticators(a, _) => a.match_id,
            Self::Fork { later, .. } => later.match_id,
            Self::ConflictingBatches(a, _) => a.record.match_id,
            Self::ConflictingCheckpoints(a, _) => a.claim.match_id,
            Self::Certified { inner, .. } => inner.match_id(),
        }
    }

    fn tag(&self) -> u8 {
        match self {
            Self::ConflictingAuthenticators(..) => 1,
            Self::Fork { .. } => 2,
            Self::ConflictingBatches(..) => 3,
            Self::ConflictingCheckpoints(..) => 4,
            Self::Certified { .. } => 5,
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
            Self::Certified { inner, certs } => {
                let mut parts = vec![inner.encode()?];
                parts.extend(certs.iter().map(Certificate::encode));
                parts
            }
        })
    }

    /// Canonical id: order-independent for symmetric pairs, so the same proof found
    /// by different peers (in either order) dedupes to one ledger entry.
    pub fn id(&self) -> Result<Digest, EvidenceError> {
        if let Self::Certified { inner, .. } = self {
            return inner.id();
        }
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
        let mut r = Reader(rest);
        let mut parts: Vec<&[u8]> = Vec::new();
        let fixed = match tag {
            2 => Some(3),
            5 => None,
            _ => Some(2),
        };
        while fixed.map_or(!r.0.is_empty(), |n| parts.len() < n) {
            if parts.len() >= MAX_PARTS {
                return Err(EvidenceError::Malformed);
            }
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
            5 => Self::decode_certified(&parts)?,
            _ => return Err(EvidenceError::Malformed),
        })
    }
}

impl Evidence {
    fn decode_certified(parts: &[&[u8]]) -> Result<Self, EvidenceError> {
        let (first, rest) = parts.split_first().ok_or(EvidenceError::Malformed)?;
        let inner = Self::decode(first)?;
        if !matches!(
            inner,
            Self::ConflictingAuthenticators(..) | Self::Fork { .. }
        ) {
            return Err(EvidenceError::Malformed);
        }
        let certs = rest
            .iter()
            .map(|c| Certificate::decode(c).map_err(|_| EvidenceError::Malformed))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::Certified {
            inner: Box::new(inner),
            certs,
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
