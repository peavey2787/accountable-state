//! The queue as a native host drives it, in safe Rust. The host supplies the clock and stores the
//! journal itself: it persists the blobs [`take_writes`] returns (in order) before acknowledging
//! anything, and hands them back to [`open`] after a restart.
use gv_proof_queue::host::HostQueue;
use gv_proof_queue::verify::{pack, unpack};

/// Result of an exported call. The numeric values are part of the ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Status {
    Ok = 0,
    /// A required pointer was null.
    NullArgument = 1,
    /// The input was rejected; see `gv_last_error`.
    Invalid = 2,
    /// No such job.
    NotFound = 3,
    /// An internal fault was contained at the boundary; the handle should be discarded.
    Panicked = 4,
}

pub type Failure = (Status, String);

fn invalid<T>(why: impl Into<String>) -> Result<T, Failure> {
    Err((Status::Invalid, why.into()))
}

/// `stored`: a pack of the blobs from earlier [`take_writes`] calls, oldest first (empty for a
/// fresh queue). `witnesses`: the pinned witness ids, concatenated 32-byte values (none: empty).
pub fn open(
    stored: &[u8],
    witnesses: &[u8],
    now: u64,
    outbox_limit: u64,
) -> Result<HostQueue, Failure> {
    let blobs: Vec<Vec<u8>> = if stored.is_empty() {
        Vec::new()
    } else {
        let Some(items) = unpack(stored) else {
            return invalid("stored writes are not a well-formed pack");
        };
        items.into_iter().map(<[u8]>::to_vec).collect()
    };
    if witnesses.len() % 32 != 0 {
        return invalid("witnesses must be a multiple of 32 bytes");
    }
    let ids: Vec<[u8; 32]> = witnesses
        .chunks_exact(32)
        .filter_map(|c| c.try_into().ok())
        .collect();
    HostQueue::open(&blobs, &ids, now, outbox_limit).map_err(|e| (Status::Invalid, e))
}

/// Everything the host must store, as one pack of blobs (oldest first).
pub fn take_writes(q: &HostQueue) -> Vec<u8> {
    pack(&q.take_writes())
}

/// The job's state code, or `NotFound`.
pub fn job_state(q: &HostQueue, id: &[u8]) -> Result<u8, Failure> {
    q.state(id)
        .ok_or_else(|| (Status::NotFound, "no such job".into()))
}

/// Required evidence families, as little-endian `u16` values.
pub fn match_status(q: &HostQueue, match_id: &[u8], required: &[u8]) -> Result<String, Failure> {
    if required.len() % 2 != 0 {
        return invalid("required families must be little-endian u16 values");
    }
    let families: Vec<u16> = required
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    q.match_status(match_id, &families)
        .map_err(|e| (Status::Invalid, e))
}
