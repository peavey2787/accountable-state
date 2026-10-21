//! The deterministic state machine an application supplies, and transition verification.
#![forbid(unsafe_code)]
use gv_commitments::commit_state;
use gv_core::{Digest, PlayerId, StateOpening};

/// Stable, machine-readable reason a rule rejected an action. Codes are part of the ruleset:
/// every honest replica and verifier must derive the same code for the same input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ViolationCode(pub u16);

/// Only `InvalidAction` is a deterministic verdict about the action and may become fraud
/// evidence. `ExecutionFailure` (a crash, unsupported ruleset, missing or malformed data) is a
/// fault of the verifier or its inputs and never proves anything about a participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    InvalidAction(ViolationCode),
    ExecutionFailure(String),
}

/// Whether concurrent actions can be merged by deterministic replay alone.
///
/// `RequiresExternalOrdering` marks actions whose outcome depends on a global order the two
/// participants cannot agree on by themselves (for example two transfers spending the same
/// balance). Such actions need external ordering or consensus: the absence of a fraud proof
/// never makes them final.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionOrdering {
    MergeSafe,
    RequiresExternalOrdering,
}

/// The application's rules. Implementations MUST be pure and deterministic on canonical bytes:
/// the same `(state, input)` yields the same result on every machine and every run.
pub trait StateMachine {
    /// Versioned ruleset identity; every signed artifact binds it.
    fn ruleset_hash(&self) -> Digest;
    /// Canonical initial state for a roster.
    fn genesis(&self, roster: &[PlayerId; 2]) -> Vec<u8>;
    /// One step: `input` is `player (32) || tick (u64 LE) || control (u16 LE)`.
    fn apply(&self, state: &[u8], input: &[u8]) -> Result<Vec<u8>, RuleError>;
    /// Ordering class of a control word. Defaults to merge-safe.
    fn ordering(&self, _control: u16) -> ActionOrdering {
        ActionOrdering::MergeSafe
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayVerdict {
    Valid,
    InvalidTransition,
    InvalidAction(ViolationCode),
    InvalidOpening,
    ExecutionError(String),
}

pub fn verify_transition<M: StateMachine>(
    machine: &M,
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
    match machine.apply(&previous.bytes, authenticated_input) {
        Ok(correct) if correct == next.bytes => ReplayVerdict::Valid,
        Ok(_) => ReplayVerdict::InvalidTransition,
        Err(RuleError::InvalidAction(code)) => ReplayVerdict::InvalidAction(code),
        Err(RuleError::ExecutionFailure(e)) => ReplayVerdict::ExecutionError(e),
    }
}
