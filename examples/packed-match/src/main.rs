//! Offline illustration of input packing and chunking, NOT a complete game verifier.
use gv_codec::chunks::{plan, ChunkPlan, Limits};
use gv_codec::{Aggregate, ControlChange, PackedControls, SignedPackedControls};
use gv_sig::SigningKey;
fn main() {
    let mut records = Vec::new();
    for (i, seed) in [7u8, 8u8].into_iter().enumerate() {
        let key = SigningKey::from_seed([seed; 32]);
        let controls = PackedControls {
            match_id: [1; 32],
            player: key.id(),
            previous_batch_hash: [0; 32], // demo only: production pins match genesis here
            start_tick: 0,
            tick_count: 216_000,
            control_bytes: 1,
            initial_state: 1,
            changes: vec![
                ControlChange {
                    offset: 18_000,
                    state: 0,
                },
                ControlChange {
                    offset: 36_000,
                    state: 1,
                },
                ControlChange {
                    offset: 215_999,
                    state: 0,
                },
            ],
        };
        let signed = SignedPackedControls::sign(controls, &key).expect("sign");
        println!(
            "player {i}: {} signed bytes",
            signed.encode().expect("encode").len()
        );
        records.push(signed);
    }
    records.sort_by_key(|r| r.record.player);
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
