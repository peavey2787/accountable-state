//! Authenticated, event-driven participant streams. Canonical wire format v2.
//!
//! A batch carries application-defined event payloads for one participant and a tick range, in
//! one of two canonical shapes (held state or discrete events). The codec does NOT replace input
//! admission, BFT ordering, or physics replay, and never interprets a payload.
#![forbid(unsafe_code)]

mod aggregate;
mod batch;
pub mod chunks;
mod signed;
#[cfg(test)]
mod size_vectors;
mod wire;

pub use aggregate::{Aggregate, MAX_AGGREGATE_BYTES, MAX_AGGREGATE_RECORDS};
pub use batch::{
    EventBatch, EventBody, HeldChange, TickEvent, MAX_CHANGES, MAX_HELD_WIDTH, MAX_RECORD_BYTES,
    MAX_TICKS,
};
pub use signed::SignedEventBatch;
pub use wire::CodecError;
