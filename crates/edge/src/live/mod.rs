//! Real-time layer: a 60 Hz deterministic simulation decoupled from the
//! asynchronous cryptographic pipeline that finalizes it.
pub mod auditor;
pub mod msg;
pub mod pipeline;
pub mod stream;
pub mod timeline;
pub use auditor::{Answers, AuditEvent, AuditStats, Auditor, NoAnswers};
pub use msg::{Opening, PipeError, PipeMsg, SignedHide};
pub use pipeline::{
    HideError, OwnInputs, PipeEvent, Pipeline, PipelineConfig, Violation, ViolationKind,
};
pub use stream::{StreamError, StreamFrame, StreamSender};
pub use timeline::{AdvanceError, Timeline, TimelineStats, TICK_HZ};

#[cfg(test)]
mod anchor_tests;
#[cfg(test)]
mod pipeline_tests;
#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod writeahead_tests;
