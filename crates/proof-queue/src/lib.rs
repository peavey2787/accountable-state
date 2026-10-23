//! Durable, crash-safe background verification queue.
//!
//! Gameplay never waits on proof processing: evidence is submitted to a persistent queue, verified
//! later by workers, and the outcome (verified, certified, violation proven, or no verdict) is
//! published as a notification. A missing or late proof is never a conviction and a timeout is
//! never a certification.
pub mod config;
pub mod host;
pub mod job;
pub mod journal;
pub mod metrics;
pub mod queue;
pub mod record;
pub mod result;
pub mod service;
pub mod verify;

pub use config::Config;
pub use job::{Event, Family, Job, JobId, JobSpec, JobState, Outcome, Priority};
pub use journal::{FileJournal, Journal, MemJournal, Opened, OutboxJournal, Write};
pub use metrics::Metrics;
pub use queue::{Leased, OpenError, Page, Queue, Stats, SubmitError, Submitted};
pub use result::{decide, match_status, Action, Ledger, MatchStatus, Settlement};
#[cfg(not(target_arch = "wasm32"))]
pub use service::WorkerPool;
pub use service::{Clock, ManualClock, Service, ServiceConfig, SystemClock};
