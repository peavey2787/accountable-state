use crate::machine::{RuleError, StateMachine, ViolationCode};
use gv_commitments::commit_state;
use gv_core::{Digest, StateOpening};

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
