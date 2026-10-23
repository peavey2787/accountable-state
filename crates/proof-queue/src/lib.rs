//! Durable, crash-safe background verification queue.
//!
//! Gameplay never waits on proof processing: evidence is submitted to a persistent queue, verified
//! later by workers, and the outcome (verified, certified, violation proven, or no verdict) is
//! published as a notification. A missing or late proof is never a conviction and a timeout is
//! never a certification.
pub mod config;
pub mod job;
pub mod journal;
pub mod metrics;
pub mod queue;
pub mod record;

pub use config::Config;
pub use job::{Event, Family, Job, JobId, JobSpec, JobState, Outcome, Priority};
pub use journal::{FileJournal, Journal, MemJournal, Opened};
pub use metrics::Metrics;
pub use queue::{Leased, OpenError, Page, Queue, Stats, SubmitError, Submitted};
