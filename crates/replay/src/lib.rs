//! Deterministic game transition verification; the game supplies the rules.
#![forbid(unsafe_code)]
use gv_commitments::commit_state;
use gv_core::{Digest, StateOpening};

/// This typed distinction prevents a crashed/unsupported verifier being mistaken
/// for a cryptographically demonstrated illegal player action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    InvalidAction(String),
    EngineFailure(String),
}

/// Implementations MUST be pure and deterministic on canonical byte strings.
pub trait GameRules {
    fn ruleset_hash(&self) -> Digest;
    fn apply(&self, previous: &[u8], authenticated_input: &[u8]) -> Result<Vec<u8>, String>;

    /// Default preserves safety: unclassified errors are NOT proof of cheating.
    /// Games must override this to identify deterministically invalid actions.
    fn apply_for_verification(
        &self,
        previous: &[u8],
        authenticated_input: &[u8],
    ) -> Result<Vec<u8>, RuleError> {
        self.apply(previous, authenticated_input)
            .map_err(RuleError::EngineFailure)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayVerdict {
    Valid,
    InvalidTransition,
    InvalidAction(String),
    InvalidOpening,
    ExecutionError(String),
}

pub fn verify_transition<R: GameRules>(
    rules: &R,
    previous: &StateOpening,
    next: &StateOpening,
    previous_commitment: &Digest,
    claimed_next_commitment: &Digest,
    authenticated_input: &[u8],
) -> ReplayVerdict {
    if &commit_state(previous) != previous_commitment
        || &commit_state(next) != claimed_next_commitment
    {
        return ReplayVerdict::InvalidOpening;
    }
    match rules.apply_for_verification(&previous.bytes, authenticated_input) {
        Ok(correct) if correct == next.bytes => ReplayVerdict::Valid,
        Ok(_) => ReplayVerdict::InvalidTransition,
        Err(RuleError::InvalidAction(e)) => ReplayVerdict::InvalidAction(e),
        Err(RuleError::EngineFailure(e)) => ReplayVerdict::ExecutionError(e),
    }
}
