//! Runs the JavaScript-facing class inside a real WebAssembly runtime (`wasm-pack test --node`).
#![cfg(target_arch = "wasm32")]
use gv_codec::{EventBatch, EventBody, SignedEventBatch};
use gv_proof_queue::verify::pack;
use gv_sig::SigningKey;
use gv_wasm::ProofQueue;
use js_sys::{Array, Uint8Array};
use wasm_bindgen_test::wasm_bindgen_test;

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

fn open(stored: &Array) -> ProofQueue {
    ProofQueue::new(stored, &[], 1_000.0, 1_048_576.0).unwrap_or_else(|_| panic!("open"))
}

#[wasm_bindgen_test]
fn evidence_is_verified_stored_and_restored_across_a_page_reload() {
    let q = open(&Array::new());
    let id = q
        .submit(1, &M, evidence(), 1, None, 1_000.0)
        .unwrap_or_else(|_| panic!("submit"));
    assert_eq!(q.step(1_001.0).ok(), Some(1));
    assert_eq!(q.job_state(&id), Some(2));
    assert_eq!(q.match_status(&M, &[1]).ok().as_deref(), Some("certified"));

    let stored = q.take_writes();
    assert!(stored.length() > 0);
    let reloaded = open(&stored);
    assert_eq!(reloaded.job_state(&id), Some(2));
    assert!(reloaded.events_after(0.0, 10).contains("\"state\":2"));
}

#[wasm_bindgen_test]
fn corrupt_stored_data_is_a_javascript_error_not_a_trap() {
    let stored = Array::new();
    stored.push(&Uint8Array::from(&[9u8, 1, 2][..]));
    assert!(ProofQueue::new(&stored, &[], 0.0, 1024.0).is_err());
}
