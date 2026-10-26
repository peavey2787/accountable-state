//! Zero-knowledge proofs for never-reveal state: a hidden state moves to a new hidden state under
//! rules the verifier pins, and the proof reveals only the two commitment lists.
//!
//! Each step carries a context slot (the last field of both states). The new state's slot is
//! proven equal to a tag derived from the whole public claim, so a proof made for one match,
//! ruleset, checkpoint or input root cannot be presented for another. The claim's `prior_root` and
//! `next_root` are digests of the two commitment lists, checked by the verifier.
#![forbid(unsafe_code)]

mod binding;
mod program;
mod prover;
mod state;
mod verifier;
mod wire;

pub use binding::Context;
pub use program::Program;
pub use prover::{advance, Step, StepError};
pub use state::State;
pub use verifier::PrivateTransitionVerifier;
pub use zk_sdk::predicate::{IntType, Number, Op, Rule};
