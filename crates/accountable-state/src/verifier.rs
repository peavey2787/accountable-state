use gv_core::PlayerId;
use gv_edge::export::{verify_package, Commitment, ExportError, FraudKind, TrustAnchor, Verified};
use gv_replay::StateMachine;

/// Why a package proves nothing either way (malformed, wrong context, failed verification, or
/// well formed but not a violation).
pub type Reason = ExportError;

/// A verified match archive or audit record that proves no misbehaviour.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRecord {
    pub commitment: Commitment,
    pub detail: Verified,
}

/// Independently checked proof that `accused` misbehaved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedProof {
    pub commitment: Commitment,
    /// `None` for an audit record that carries proven equivocation.
    pub kind: Option<FraudKind>,
    pub accused: Vec<PlayerId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationResult {
    Valid(VerifiedRecord),
    ProvenViolation(VerifiedProof),
    Inconclusive(Reason),
}

/// Checks `GV-EVIDENCE-PACKAGE/V1` bytes offline, against facts pinned out of band.
#[derive(Clone, Copy, Debug)]
pub struct Verifier {
    anchor: TrustAnchor,
}

impl Verifier {
    pub fn new(anchor: TrustAnchor) -> Self {
        Self { anchor }
    }

    pub fn verify_package<M: StateMachine + Clone>(
        &self,
        bytes: &[u8],
        machine: &M,
    ) -> VerificationResult {
        match verify_package(bytes, &self.anchor, machine) {
            Ok((commitment, detail)) => classify(commitment, detail),
            Err(reason) => VerificationResult::Inconclusive(reason),
        }
    }
}

fn classify(commitment: Commitment, detail: Verified) -> VerificationResult {
    let proof = |kind, accused| {
        VerificationResult::ProvenViolation(VerifiedProof {
            commitment,
            kind,
            accused,
        })
    };
    match detail {
        Verified::Fraud { kind, accused } => proof(Some(kind), vec![accused]),
        Verified::Audit { ref proven, .. } if !proven.is_empty() => proof(None, proven.clone()),
        detail => VerificationResult::Valid(VerifiedRecord { commitment, detail }),
    }
}
