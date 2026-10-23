//! Drives the exported symbols exactly as a native host would: raw pointers in, status codes and
//! library-owned buffers out.
#![allow(unsafe_code)]
use gv_capi::api::Status;
use gv_capi::ffi::*;
use gv_codec::{EventBatch, EventBody, SignedEventBatch};
use gv_proof_queue::verify::{pack, unpack};
use gv_proof_queue::Family;
use gv_sig::SigningKey;
use std::ptr::{null, null_mut};

const M: [u8; 32] = [7; 32];

fn evidence() -> Vec<u8> {
    let k = SigningKey::from_seed([1; 32]);
    let batch = SignedEventBatch::sign(
        EventBatch {
            match_id: M,
            participant: k.id(),
            previous_batch_hash: [0; 32],
            start_tick: 0,
            tick_count: 20,
            body: EventBody::Held {
                initial: vec![1, 0],
                changes: vec![],
            },
        },
        &k,
    )
    .unwrap();
    pack(&[batch.encode().unwrap()])
}

fn take(buf: GvBuffer) -> Vec<u8> {
    let bytes = if buf.ptr.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(buf.ptr, buf.len) }.to_vec()
    };
    unsafe { gv_buffer_free(buf) };
    bytes
}

fn empty() -> GvBuffer {
    GvBuffer {
        ptr: null_mut(),
        len: 0,
        cap: 0,
    }
}

fn last_error() -> String {
    let mut buf = empty();
    assert_eq!(unsafe { gv_last_error(&mut buf) }, Status::Ok);
    String::from_utf8(take(buf)).unwrap()
}

fn open(stored: &[u8]) -> *mut GvQueue {
    let mut q = null_mut();
    let status = unsafe {
        gv_queue_open(
            stored.as_ptr(),
            stored.len(),
            null(),
            0,
            1_000,
            1 << 20,
            &mut q,
        )
    };
    assert_eq!(status, Status::Ok);
    assert!(!q.is_null());
    q
}

fn submit(q: *mut GvQueue, payload: &[u8]) -> ([u8; 32], Status) {
    let mut job = [0u8; 32];
    let status = unsafe {
        gv_queue_submit(
            q,
            Family::SIGNED_INPUTS.0,
            M.as_ptr(),
            payload.as_ptr(),
            payload.len(),
            1,
            u64::MAX,
            1_000,
            job.as_mut_ptr(),
        )
    };
    (job, status)
}

fn writes(q: *mut GvQueue) -> Vec<u8> {
    let mut buf = empty();
    assert_eq!(unsafe { gv_queue_take_writes(q, &mut buf) }, Status::Ok);
    take(buf)
}

fn state(q: *mut GvQueue, job: &[u8; 32]) -> (Status, u8) {
    let mut s = 0u8;
    (unsafe { gv_queue_job_state(q, job.as_ptr(), &mut s) }, s)
}

#[test]
fn evidence_goes_through_the_queue_and_the_host_stores_what_it_is_told_to() {
    let q = open(&[]);
    let (job, status) = submit(q, &evidence());
    assert_eq!(status, Status::Ok);
    assert_eq!(state(q, &job), (Status::Ok, 0), "pending");

    let mut done = 0usize;
    assert_eq!(unsafe { gv_queue_step(q, 1_001, &mut done) }, Status::Ok);
    assert_eq!(done, 1);
    assert_eq!(state(q, &job), (Status::Ok, 2), "verified");

    let required = Family::SIGNED_INPUTS.0.to_le_bytes();
    let mut buf = empty();
    let status = unsafe {
        gv_queue_match_status(q, M.as_ptr(), required.as_ptr(), required.len(), &mut buf)
    };
    assert_eq!(status, Status::Ok);
    assert_eq!(take(buf), b"certified");

    let mut buf = empty();
    assert_eq!(
        unsafe { gv_queue_events_after(q, 0, 10, &mut buf) },
        Status::Ok
    );
    let json = String::from_utf8(take(buf)).unwrap();
    assert!(
        json.contains("\"gap\":false") && json.contains("\"state\":2"),
        "{json}"
    );

    let stored = writes(q);
    assert!(unpack(&stored).is_some_and(|blobs| !blobs.is_empty()));
    assert!(
        unpack(&writes(q)).is_some_and(|blobs| blobs.is_empty()),
        "drained once"
    );
    unsafe { gv_queue_free(q) };

    let again = open(&stored);
    assert_eq!(
        state(again, &job),
        (Status::Ok, 2),
        "the verdict survived a restart"
    );
    unsafe { gv_queue_free(again) };
}

#[test]
fn bad_input_is_a_status_and_a_message_never_a_crash() {
    let q = open(&[]);
    assert_eq!(state(q, &[0xee; 32]).0, Status::NotFound);
    let short = [1u8, 2];
    let mut s = 0u8;
    let _ = unsafe { gv_queue_job_state(q, short.as_ptr(), &mut s) };
    let (_, status) = submit(q, &[]);
    assert_eq!(
        status,
        Status::Ok,
        "an empty payload is queued and later judged invalid"
    );

    let mut buf = empty();
    let odd = [1u8, 2, 3];
    let status = unsafe { gv_queue_match_status(q, M.as_ptr(), odd.as_ptr(), odd.len(), &mut buf) };
    assert_eq!(status, Status::Invalid);
    assert!(last_error().contains("u16"));

    for (stored, witnesses) in [(&[0u8, 1, 2][..], &[][..]), (&[][..], &[1u8; 33][..])] {
        let mut out = null_mut();
        let status = unsafe {
            gv_queue_open(
                stored.as_ptr(),
                stored.len(),
                witnesses.as_ptr(),
                witnesses.len(),
                0,
                1 << 20,
                &mut out,
            )
        };
        assert_eq!(status, Status::Invalid);
        assert!(out.is_null());
    }
    unsafe { gv_queue_free(q) };
}

#[test]
fn null_pointers_are_refused_not_dereferenced() {
    let mut done = 0usize;
    assert_eq!(
        unsafe { gv_queue_step(null(), 0, &mut done) },
        Status::NullArgument
    );
    let q = open(&[]);
    assert_eq!(
        unsafe { gv_queue_step(q, 0, null_mut()) },
        Status::NullArgument
    );
    assert_eq!(
        unsafe { gv_queue_take_writes(q, null_mut()) },
        Status::NullArgument
    );
    assert_eq!(
        unsafe { gv_queue_job_state(q, null(), &mut 0u8) },
        Status::NullArgument
    );
    let status = unsafe {
        gv_queue_submit(
            q,
            1,
            null(),
            null(),
            0,
            1,
            u64::MAX,
            0,
            [0u8; 32].as_mut_ptr(),
        )
    };
    assert_eq!(status, Status::NullArgument);
    assert_eq!(
        unsafe { gv_queue_open(null(), 4, null(), 0, 0, 0, &mut null_mut()) },
        Status::NullArgument
    );
    unsafe { gv_queue_free(q) };
    unsafe { gv_queue_free(null_mut()) };
    unsafe { gv_buffer_free(empty()) };
}

#[test]
fn a_host_that_never_stores_makes_the_queue_refuse_work() {
    let mut q = null_mut();
    assert_eq!(
        unsafe { gv_queue_open(null(), 0, null(), 0, 1_000, 400, &mut q) },
        Status::Ok
    );
    let refused = (0..50u8).any(|n| submit(q, &pack(&[vec![n; 64]])).1 != Status::Ok);
    assert!(refused, "outbox backpressure reaches the host as a status");
    unsafe { gv_queue_free(q) };
}

#[test]
fn the_header_declares_every_exported_symbol() {
    let header = include_str!("../include/gv_proofs.h");
    let source = include_str!("../src/ffi.rs");
    let exported: Vec<&str> = source
        .lines()
        .filter_map(|l| l.strip_prefix("pub unsafe extern \"C\" fn "))
        .filter_map(|l| l.split('(').next())
        .collect();
    assert!(exported.len() >= 9, "{exported:?}");
    for name in exported {
        assert!(
            header.contains(&format!("{name}(")),
            "{name} is not declared in the header"
        );
    }
}
