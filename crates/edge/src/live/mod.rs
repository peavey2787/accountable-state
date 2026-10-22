//! Real-time layer: a deterministic simulation decoupled from the asynchronous cryptographic
//! pipeline that finalizes it.
pub mod auditor;
pub(crate) mod gate;
pub mod msg;
pub mod pipeline;
pub mod stream;
pub mod timeline;
pub use auditor::{Answers, AuditEvent, AuditStats, Auditor, NoAnswers};
pub use msg::{Close, Dest, Opening, Outgoing, PipeError, PipeMsg, SignedSeal};
pub use pipeline::{
    OwnInputs, PipeEvent, Pipeline, PipelineConfig, SealError, SealPolicy, Suspicion,
    SuspicionKind, Violation, ViolationKind,
};
pub use stream::{StreamError, StreamFrame, StreamSender};
pub use timeline::{AdvanceError, Prediction, Timeline, TimelineStats};

#[cfg(test)]
mod anchor_tests;
#[cfg(test)]
mod netsim;
#[cfg(test)]
mod pipeline_tests;
#[cfg(test)]
mod quorum_tests;
#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod writeahead_tests;
