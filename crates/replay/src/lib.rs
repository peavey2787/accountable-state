//! The deterministic state machine an application supplies, and the one replay engine every
//! node, witness and offline verifier shares.
#![forbid(unsafe_code)]

mod machine;
mod step;
mod transition;

pub use machine::{ActionOrdering, RuleError, StateMachine, ViolationCode};
pub use step::{replay_epoch, step_tick, InputViolation, ReplayError, Replayed, MAX_STATE_BYTES};
pub use transition::{verify_transition, ReplayVerdict};
