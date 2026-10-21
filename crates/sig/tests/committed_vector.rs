//! Verifies the committed cross-implementation vector with the Rust verifier.
//! `scripts/verify-vectors.mjs` checks the same file with OpenSSL.

use gv_sig::{envelope_digest, player_id_of, register_key, verify, Signature};

fn field(json: &str, name: &str) -> String {
    let key = format!("\"{name}\": \"");
    let start = json.find(&key).expect("field present") + key.len();
    let end = json[start..].find('"').expect("closing quote") + start;
    json[start..end].to_string()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn committed_mldsa65_vector_verifies_and_rejects_tampering() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/interoperability/signed_mldsa65_v1.json"
    );
    let json = std::fs::read_to_string(path).expect("vector file");
    let vk = unhex(&field(&json, "verifying_key_hex"));
    let body = unhex(&field(&json, "body_hex"));
    let label = field(&json, "label");
    let sig = Signature::from_slice(&unhex(&field(&json, "signature_hex"))).expect("sig length");

    let id = register_key(&vk).expect("register");
    assert_eq!(id, player_id_of(&vk));
    assert_eq!(id.to_vec(), unhex(&field(&json, "player_id_hex")));
    assert_eq!(
        envelope_digest(&label, &id, &body).to_vec(),
        unhex(&field(&json, "envelope_digest_hex"))
    );
    verify(&id, &label, &body, &sig).expect("committed signature verifies");
    assert!(verify(&id, &label, b"other", &sig).is_err());
    assert!(verify(&id, "gv/test/other/v1", &body, &sig).is_err());
    assert!(verify(&id, &label, &body, &sig.with_bit_flipped(9)).is_err());
}
