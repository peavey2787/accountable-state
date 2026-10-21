//! Independently replayable, public-state two-player verification, without validators.
//! Checkpoint co-signing is bilateral admission, not Byzantine consensus or finality.
#![forbid(unsafe_code)]
mod admission;
pub mod arena;
pub mod audit;
mod checkpoint;
pub mod export;
#[cfg(test)]
mod export_tests;
pub mod feed;
mod fraud_bundle;
mod history;
pub mod live;
mod recovery;
mod replica;
pub mod witness;
#[cfg(test)]
mod witness_tests;
pub use checkpoint::{
    evidence_violations, verify_checkpoint_evidence, verify_checkpoint_evidence_with, Checkpoint,
    CheckpointError, CheckpointEvidence, EvidenceVerdict, SignedCheckpoint,
};
pub use history::CertifiedEpoch;
pub use replica::{apply_tick, EdgeError, Epoch, InputViolation, MatchReplica, PublicRules};
#[cfg(test)]
mod tests;

pub use admission::{
    verify_equivocation, AdmissionError, BatchCommitment, BilateralAdmission,
    SignedBatchCommitment, SignedEpochLock,
};
pub use recovery::{ArchiveBuilder, CertifiedMatch, Dispute};

pub use arena::{ArenaRules, ArenaState, Fighter};

pub use fraud_bundle::FraudBundle;

#[cfg(test)]
mod protocol_tests;
