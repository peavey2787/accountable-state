//! The exported C symbols. Every function contains panics at the boundary (unwinding into a game
//! engine would be undefined behavior) and reports through [`Status`]; details of the last failure
//! on the calling thread are available from `gv_last_error`.
#![allow(unsafe_code)]
use crate::api::{self, Failure, Status};
use gv_proof_queue::host::HostQueue;
use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Opaque handle to a queue.
pub struct GvQueue(HostQueue);

/// Bytes allocated by this library. Release with `gv_buffer_free`.
#[repr(C)]
pub struct GvBuffer {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl GvBuffer {
    fn from_vec(mut v: Vec<u8>) -> Self {
        let out = Self {
            ptr: v.as_mut_ptr(),
            len: v.len(),
            cap: v.capacity(),
        };
        std::mem::forget(v);
        out
    }
}

fn fail((status, why): Failure) -> Status {
    LAST_ERROR.with(|e| *e.borrow_mut() = why);
    status
}

/// Run `f`, turning errors and panics into a status.
fn guard(f: impl FnOnce() -> Result<(), Failure>) -> Status {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => Status::Ok,
        Ok(Err(e)) => fail(e),
        Err(_) => fail((Status::Panicked, "internal fault".into())),
    }
}

fn null() -> Failure {
    (Status::NullArgument, "required pointer is null".into())
}

/// A byte span from the host. A null pointer is a valid empty span only when `len` is zero.
///
/// # Safety
/// A non-null `ptr` must address `len` readable bytes.
unsafe fn span<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], Failure> {
    match (ptr.is_null(), len) {
        (_, 0) => Ok(&[]),
        (true, _) => Err(null()),
        // SAFETY: the caller promises `ptr` addresses `len` readable bytes.
        (false, _) => Ok(unsafe { std::slice::from_raw_parts(ptr, len) }),
    }
}

/// # Safety
/// `q` must be null or a live handle from `gv_queue_open`.
unsafe fn queue<'a>(q: *const GvQueue) -> Result<&'a HostQueue, Failure> {
    // SAFETY: the caller promises a live handle from `gv_queue_open`, or null.
    unsafe { q.as_ref() }.map(|q| &q.0).ok_or_else(null)
}

/// # Safety
/// A non-null `out` must be writable.
unsafe fn put<T>(out: *mut T, value: T) -> Result<(), Failure> {
    if out.is_null() {
        return Err(null());
    }
    // SAFETY: `out` is non-null and the caller promises it is writable.
    unsafe { out.write(value) };
    Ok(())
}

/// # Safety
/// As for `put`.
unsafe fn put_bytes(out: *mut GvBuffer, bytes: Vec<u8>) -> Result<(), Failure> {
    // SAFETY: forwarded; same contract as `put`.
    unsafe { put(out, GvBuffer::from_vec(bytes)) }
}

/// Open a queue. See `gv_proofs.h` for the argument contract.
///
/// # Safety
/// Each pointer must be null (only with a zero length) or address that many valid bytes, and `out`
/// must be writable.
#[no_mangle]
pub unsafe extern "C" fn gv_queue_open(
    stored: *const u8,
    stored_len: usize,
    witnesses: *const u8,
    witnesses_len: usize,
    now: u64,
    outbox_limit: u64,
    out: *mut *mut GvQueue,
) -> Status {
    guard(|| unsafe {
        let q = api::open(
            span(stored, stored_len)?,
            span(witnesses, witnesses_len)?,
            now,
            outbox_limit,
        )?;
        put(out, Box::into_raw(Box::new(GvQueue(q))))
    })
}

/// Destroy a queue. Null is ignored.
///
/// # Safety
/// `q` must come from `gv_queue_open` and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn gv_queue_free(q: *mut GvQueue) {
    if !q.is_null() {
        // SAFETY: the caller owns the handle.
        drop(unsafe { Box::from_raw(q) });
    }
}

/// Queue evidence. `deadline` is absolute time, or `u64::MAX` for none. Writes the 32-byte job id
/// to `job_out`.
///
/// # Safety
/// Pointers as for `gv_queue_open`; `match_id` addresses 32 bytes and `job_out` is 32 writable bytes.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn gv_queue_submit(
    q: *const GvQueue,
    family: u16,
    match_id: *const u8,
    payload: *const u8,
    payload_len: usize,
    priority: u8,
    deadline: u64,
    now: u64,
    job_out: *mut u8,
) -> Status {
    guard(|| unsafe {
        let deadline = (deadline != u64::MAX).then_some(deadline);
        let id = queue(q)?
            .submit(
                family,
                span(match_id, 32)?,
                span(payload, payload_len)?.to_vec(),
                priority,
                deadline,
                now,
            )
            .map_err(|e| (Status::Invalid, e))?;
        put(job_out.cast::<[u8; 32]>(), id)
    })
}

/// Verify one batch of ready jobs; `done` receives how many were processed.
///
/// # Safety
/// `q` is a live handle and `done` is writable.
#[no_mangle]
pub unsafe extern "C" fn gv_queue_step(q: *const GvQueue, now: u64, done: *mut usize) -> Status {
    guard(|| unsafe {
        let n = queue(q)?.step(now).map_err(|e| (Status::Invalid, e))?;
        put(done, n)
    })
}

/// The state code of a job.
///
/// # Safety
/// `job` addresses 32 bytes; `state` is writable.
#[no_mangle]
pub unsafe extern "C" fn gv_queue_job_state(
    q: *const GvQueue,
    job: *const u8,
    state: *mut u8,
) -> Status {
    guard(|| unsafe {
        let s = api::job_state(queue(q)?, span(job, 32)?)?;
        put(state, s)
    })
}

/// A match's aggregate status as UTF-8 text. `required` is little-endian `u16` family numbers.
///
/// # Safety
/// Pointers as for `gv_queue_open`; `out` is writable and the result is freed with `gv_buffer_free`.
#[no_mangle]
pub unsafe extern "C" fn gv_queue_match_status(
    q: *const GvQueue,
    match_id: *const u8,
    required: *const u8,
    required_len: usize,
    out: *mut GvBuffer,
) -> Status {
    guard(|| unsafe {
        let text = api::match_status(
            queue(q)?,
            span(match_id, 32)?,
            span(required, required_len)?,
        )?;
        put_bytes(out, text.into_bytes())
    })
}

/// Notifications after `cursor` as UTF-8 JSON.
///
/// # Safety
/// `q` is a live handle; `out` is writable and the result is freed with `gv_buffer_free`.
#[no_mangle]
pub unsafe extern "C" fn gv_queue_events_after(
    q: *const GvQueue,
    cursor: u64,
    limit: usize,
    out: *mut GvBuffer,
) -> Status {
    guard(|| unsafe {
        let json = queue(q)?.events_after(cursor, limit);
        put_bytes(out, json.into_bytes())
    })
}

/// Everything the host must store before acknowledging, as one pack of blobs.
///
/// # Safety
/// `q` is a live handle; `out` is writable and the result is freed with `gv_buffer_free`.
#[no_mangle]
pub unsafe extern "C" fn gv_queue_take_writes(q: *const GvQueue, out: *mut GvBuffer) -> Status {
    guard(|| unsafe { put_bytes(out, api::take_writes(queue(q)?)) })
}

/// The message of the last failure on this thread, as UTF-8 text.
///
/// # Safety
/// `out` is writable and the result is freed with `gv_buffer_free`.
#[no_mangle]
pub unsafe extern "C" fn gv_last_error(out: *mut GvBuffer) -> Status {
    guard(|| unsafe {
        let message = LAST_ERROR.with(|e| e.borrow().clone());
        put_bytes(out, message.into_bytes())
    })
}

/// Release a buffer returned by this library. An empty buffer is ignored.
///
/// # Safety
/// `buf` must be exactly as this library returned it, and not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn gv_buffer_free(buf: GvBuffer) {
    if !buf.ptr.is_null() {
        // SAFETY: the buffer came from `GvBuffer::from_vec`, so these are a Vec's parts.
        drop(unsafe { Vec::from_raw_parts(buf.ptr, buf.len, buf.cap) });
    }
}
