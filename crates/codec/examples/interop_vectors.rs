//! Regenerates the committed ML-DSA-65 interoperability vectors:
//! `cargo run -p gv-codec --example interop_vectors -- tests/interoperability`.
use gv_codec::{Aggregate, EventBatch, EventBody, HeldChange, SignedEventBatch};
use gv_sig::SigningKey;
use std::fs;
use std::path::Path;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Regenerates the committed ML-DSA-65 interoperability vectors. Signing is
/// hedged, so each run produces a different (equally valid) signature; the
/// independent verifiers check whatever is committed.
fn write_vectors(dir: &str) -> Result<(), String> {
    let key = SigningKey::from_seed([7; 32]);
    let label = "gv/test/vector/v1";
    let body = b"gv interoperability vector".to_vec();
    let sig = key.sign(label, &body);
    let digest = gv_sig::envelope_digest(label, &key.id(), &body);
    let signed_vector = format!(
        "{{\n  \"format\": \"GV-SIG-ML-DSA-65-V1\",\n  \"seed_hex\": \"{}\",\n  \"verifying_key_hex\": \"{}\",\n  \"player_id_hex\": \"{}\",\n  \"label\": \"{label}\",\n  \"body_hex\": \"{}\",\n  \"envelope_digest_hex\": \"{}\",\n  \"signature_hex\": \"{}\"\n}}\n",
        hex(&[7; 32]),
        hex(key.public_key()),
        hex(&key.id()),
        hex(&body),
        hex(&digest),
        hex(sig.as_bytes())
    );
    let record = EventBatch {
        match_id: [1; 32],
        participant: key.id(),
        previous_batch_hash: [2; 32],
        start_tick: 500,
        tick_count: 180,
        body: EventBody::Held {
            initial: vec![1],
            changes: vec![HeldChange {
                offset: 179,
                payload: vec![0],
            }],
        },
    };
    let signed = SignedEventBatch::sign(record.clone(), &key).map_err(|e| format!("{e:?}"))?;
    let aggregate = Aggregate {
        records: vec![signed.clone()],
    };
    let agg_bytes = aggregate.encode().map_err(|e| format!("{e:?}"))?;
    let packed_vector = format!(
        "{{\n  \"format\": \"GVEC-GVAG-v2\",\n  \"verifying_key_hex\": \"{}\",\n  \"player_id_hex\": \"{}\",\n  \"record_hex\": \"{}\",\n  \"signature_hex\": \"{}\",\n  \"signed_record_hash\": \"{}\",\n  \"aggregate_hash\": \"{}\",\n  \"aggregate_length\": {}\n}}\n",
        hex(key.public_key()),
        hex(&key.id()),
        hex(&record.encode().map_err(|e| format!("{e:?}"))?),
        hex(signed.signature.as_bytes()),
        hex(&signed.digest().map_err(|e| format!("{e:?}"))?),
        hex(&aggregate.digest().map_err(|e| format!("{e:?}"))?),
        agg_bytes.len()
    );
    fs::write(Path::new(dir).join("signed_mldsa65_v1.json"), signed_vector)
        .map_err(|e| e.to_string())?;
    fs::write(Path::new(dir).join("event_batch_v2.json"), packed_vector)
        .map_err(|e| e.to_string())?;
    println!("wrote ML-DSA-65 vectors to {dir}");
    Ok(())
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/interoperability".into());
    if let Err(e) = write_vectors(&dir) {
        eprintln!("FAIL: {e}");
        std::process::exit(1);
    }
}
