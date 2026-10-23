//! The verifiers for the evidence this system produces. Each decodes the canonical encoding (which
//! re-checks signatures) and applies the same acceptance rules as the live protocol.
use super::pack::unpack;
use super::Verifier;
use crate::job::{Family, JobSpec, Outcome};
use gv_codec::SignedEventBatch;
use gv_core::Digest;
use gv_edge::audit::evidence::{Evidence, EvidenceError};
use gv_edge::quorum::{Certificate, QuorumError, WitnessSet};
use gv_edge::{CertifiedEpoch, EvidenceVerdict, SignedBatchCommitment, StateMachine};

/// Run `check` over every item of an aggregated payload: the first failure decides.
fn each_item(spec: &JobSpec, check: impl Fn(&[u8], usize) -> Result<(), Outcome>) -> Outcome {
    let Some(items) = unpack(&spec.payload) else {
        return Outcome::Invalid("payload is not a well-formed pack".into());
    };
    if items.is_empty() {
        return Outcome::Invalid("empty pack".into());
    }
    for (i, item) in items.iter().enumerate() {
        if let Err(o) = check(item, i) {
            return o;
        }
    }
    Outcome::Valid
}

fn invalid(i: usize, why: impl std::fmt::Debug) -> Outcome {
    Outcome::Invalid(format!("item {i}: {why:?}"))
}

/// Signed input batches of one match: every signature is genuine and every batch is for the match.
pub struct SignedInputs;

impl Verifier for SignedInputs {
    fn family(&self) -> Family {
        Family::SIGNED_INPUTS
    }
    fn verify(&self, spec: &JobSpec) -> Outcome {
        each_item(spec, |item, i| {
            let b = SignedEventBatch::decode(item).map_err(|e| invalid(i, e))?;
            (b.record.match_id == spec.match_id)
                .then_some(())
                .ok_or_else(|| invalid(i, "batch is for another match"))
        })
    }
}

/// Signed batch commitments of one match.
pub struct Commitments;

impl Verifier for Commitments {
    fn family(&self) -> Family {
        Family::COMMITMENT
    }
    fn verify(&self, spec: &JobSpec) -> Outcome {
        each_item(spec, |item, i| {
            let c = SignedBatchCommitment::decode(item).map_err(|e| invalid(i, e))?;
            (c.claim.match_id == spec.match_id)
                .then_some(())
                .ok_or_else(|| invalid(i, "commitment is for another match"))
        })
    }
}

/// Witness-quorum certificates (a recovery or a committed head), checked against the pinned set.
pub struct RecoveryCertificates {
    pub witnesses: WitnessSet,
}

impl Verifier for RecoveryCertificates {
    fn family(&self) -> Family {
        Family::RECOVERY_CERTIFICATE
    }
    fn verify(&self, spec: &JobSpec) -> Outcome {
        let Some(items) = unpack(&spec.payload).filter(|i| i.len() == 1) else {
            return Outcome::Invalid("expected exactly one certificate".into());
        };
        let cert = match Certificate::decode(items[0]) {
            Ok(c) => c,
            Err(e) => return invalid(0, e),
        };
        if cert.claim.auth.match_id != spec.match_id {
            return invalid(0, "certificate is for another match");
        }
        match cert.verify(&self.witnesses) {
            Ok(()) => Outcome::Certified,
            Err(QuorumError::Insufficient) => {
                Outcome::Inconclusive("fewer receipts than a quorum".into())
            }
            Err(e) => invalid(0, e),
        }
    }
}

/// Equivocation evidence. With a pinned witness set, log equivocation counts only when the heads
/// were committed by a quorum, so a head that was never released cannot convict its signer.
pub struct Equivocation {
    pub witnesses: Option<WitnessSet>,
}

impl Verifier for Equivocation {
    fn family(&self) -> Family {
        Family::EQUIVOCATION
    }
    fn verify(&self, spec: &JobSpec) -> Outcome {
        let Some(items) = unpack(&spec.payload).filter(|i| i.len() == 1) else {
            return Outcome::Invalid("expected exactly one piece of evidence".into());
        };
        let evidence = match Evidence::decode(items[0]) {
            Ok(e) => e,
            Err(e) => return invalid(0, e),
        };
        match evidence.verify_under(self.witnesses.as_ref()) {
            Ok(gv_edge::audit::evidence::Proof::Equivocation(accused)) => Outcome::Violation {
                accused,
                evidence: spec.payload.clone(),
            },
            Err(EvidenceError::Uncertified) => {
                Outcome::Inconclusive("heads are not committed by a witness quorum".into())
            }
            Err(e) => invalid(0, e),
        }
    }
}

/// Replays one certified epoch through the application's rules. Payload (as a one-item pack): the
/// previous checkpoint hash, the previous state commitment, then the encoded [`CertifiedEpoch`].
pub struct TransitionVerifier<R> {
    pub rules: R,
}

/// Build the payload of a transition job.
pub fn transition_payload(
    previous_checkpoint: Digest,
    previous_state: Digest,
    epoch: &CertifiedEpoch,
) -> Option<Vec<u8>> {
    let mut body = previous_checkpoint.to_vec();
    body.extend_from_slice(&previous_state);
    body.extend_from_slice(&epoch.encode().ok()?);
    Some(super::pack(&[body]))
}

impl<R: StateMachine + Send + Sync> Verifier for TransitionVerifier<R> {
    fn family(&self) -> Family {
        Family::TRANSITION
    }
    fn verify(&self, spec: &JobSpec) -> Outcome {
        let Some(items) = unpack(&spec.payload).filter(|i| i.len() == 1) else {
            return Outcome::Invalid("expected exactly one epoch".into());
        };
        let Some((heads, epoch)) = items[0].split_at_checked(64) else {
            return Outcome::Invalid("payload shorter than its two digests".into());
        };
        let epoch = match CertifiedEpoch::decode(epoch) {
            Ok(e) => e,
            Err(e) => return invalid(0, e),
        };
        if epoch.evidence.session.match_id != spec.match_id {
            return invalid(0, "epoch is for another match");
        }
        let (previous_checkpoint, previous_state) = heads.split_at(32);
        let (Ok(pc), Ok(ps)) = (previous_checkpoint.try_into(), previous_state.try_into()) else {
            return Outcome::Invalid("malformed digests".into());
        };
        match epoch.verify_with(&self.rules, pc, ps, false) {
            EvidenceVerdict::ValidClaim => Outcome::Certified,
            EvidenceVerdict::ProvenInvalidState => Outcome::Violation {
                accused: epoch.evidence.accused.signer,
                evidence: items[0].to_vec(),
            },
            EvidenceVerdict::ProvenInvalidAction(p) => Outcome::Violation {
                accused: p,
                evidence: items[0].to_vec(),
            },
            EvidenceVerdict::Inconclusive(e) => Outcome::Inconclusive(format!("{e:?}")),
        }
    }
}
