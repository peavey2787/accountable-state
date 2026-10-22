//! Offline illustration of input packing and chunking, NOT a complete game verifier.
use gv_codec::chunks::{plan, ChunkPlan, Limits};
use gv_codec::{Aggregate, EventBatch, EventBody, HeldChange, SignedEventBatch};
use gv_sig::SigningKey;
fn main() {
    let mut records = Vec::new();
    for (i, seed) in [7u8, 8u8].into_iter().enumerate() {
        let key = SigningKey::from_seed([seed; 32]);
        let held = |offset, state| HeldChange {
            offset,
            payload: vec![state],
        };
        let batch = EventBatch {
            match_id: [1; 32],
            participant: key.id(),
            previous_batch_hash: [0; 32], // demo only: production pins match genesis here
            start_tick: 0,
            tick_count: 216_000,
            body: EventBody::Held {
                initial: vec![1],
                changes: vec![held(18_000, 0), held(36_000, 1), held(215_999, 0)],
            },
        };
        let signed = SignedEventBatch::sign(batch, &key).expect("sign");
        println!(
            "player {i}: {} signed bytes",
            signed.encode().expect("encode").len()
        );
        records.push(signed);
    }
    records.sort_by_key(|r| r.record.participant);
    let aggregate = Aggregate { records };
    println!(
        "total authenticated aggregate: {} bytes",
        aggregate.encode().expect("encode").len()
    );
    match plan(&aggregate, Limits::default()).expect("plan") {
        ChunkPlan::Chunked { chunks, .. } => {
            println!("{} chunks fit the carrier budget", chunks.len())
        }
        ChunkPlan::HashOnly {
            bytes,
            required_chunks,
            ..
        } => println!("{bytes} bytes would need {required_chunks} chunks; carry only the hash"),
    }
}
