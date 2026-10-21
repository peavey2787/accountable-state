//! PeerReview-grade accountability: tamper-evident logs, signed authenticators,
//! offline-verifiable evidence, challenge/response and a deterministic ledger.
//! Nothing here is on the 60 Hz gameplay path; it runs beside it and never blocks it.
pub mod challenge;
pub mod durable;
pub mod evidence;
pub mod failpoint;
pub mod fsync;
pub mod journal;
pub mod ledger;
pub mod log;
pub mod store;
pub mod trust;

pub use challenge::{
    Challenge, ChallengeBook, ChallengeGate, ChallengeKind, Reject, Response, Status, Timing,
};
pub use evidence::{compare_authenticators, Evidence, EvidenceError, Proof};
pub use ledger::{assign_witnesses, missing_ids, Ledger, Outcome};
pub use log::{AuditLog, Authenticator, LogEntry, LogError, Segment};

#[cfg(test)]
mod tests;
