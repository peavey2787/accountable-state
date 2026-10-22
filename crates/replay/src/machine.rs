use gv_core::{Digest, Session};

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
/// `RequiresExternalOrdering` marks actions whose outcome depends on a global order the
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
    /// Canonical initial state for a session (roster, teams, parameters).
    fn genesis(&self, session: &Session) -> Vec<u8>;
    /// One authenticated event: `input` is `participant (32) || tick (u64 LE) || payload`
    /// (see [`gv_core::Event`]); the payload is application-defined.
    fn apply(&self, state: &[u8], input: &[u8]) -> Result<Vec<u8>, RuleError>;
    /// World update after every event of `tick` has applied (movement integration, timers).
    /// `None` leaves the state unchanged.
    fn advance(&self, _state: &[u8], _tick: u64) -> Result<Option<Vec<u8>>, RuleError> {
        Ok(None)
    }
    /// The harmless replacement for an input `apply` rejected, used by live (sanitized) play so
    /// one illegal event cannot stall an epoch. `None` drops the event. Honest replayers and
    /// verifiers substitute identically.
    fn neutralize(&self, _input: &[u8]) -> Option<Vec<u8>> {
        None
    }
    /// Ordering class of an event payload. Defaults to merge-safe.
    fn ordering(&self, _payload: &[u8]) -> ActionOrdering {
        ActionOrdering::MergeSafe
    }
}
