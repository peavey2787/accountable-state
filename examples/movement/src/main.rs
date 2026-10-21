//! Signed inputs + Merkle inclusion + deterministic replay. No network finality.
use gv_commitments::{commit_state, verify_membership, MerkleLog};
use gv_core::{Digest, StateOpening};
use gv_replay::{verify_transition, GameRules};
use gv_sig::SigningKey;
use gv_transcript::SignedInput;

struct ToyMovement;
impl GameRules for ToyMovement {
    fn ruleset_hash(&self) -> Digest {
        [9; 32]
    }
    fn apply(&self, previous: &[u8], input: &[u8]) -> Result<Vec<u8>, String> {
        if previous.len() != 8 || input.len() != 8 {
            return Err("noncanonical coordinate".into());
        }
        let x = i64::from_le_bytes(previous.try_into().map_err(|_| "state")?);
        let delta = i64::from_le_bytes(input.try_into().map_err(|_| "input")?);
        if !(-5..=5).contains(&delta) {
            return Err("movement outside accepted input domain".into());
        }
        Ok(x.checked_add(delta)
            .ok_or("overflow")?
            .to_le_bytes()
            .to_vec())
    }
}
fn main() {
    let key = SigningKey::from_seed([5; 32]);
    let signed =
        SignedInput::new(&key, [1; 32], 1, 0, 2i64.to_le_bytes().to_vec()).expect("signed");
    signed.verify().expect("signature");
    let mut log = MerkleLog::new();
    log.append(&signed.leaf_bytes().expect("bytes"))
        .expect("bounded log");
    assert!(verify_membership(
        &log.root(),
        &signed.leaf_bytes().unwrap(),
        &log.proof(0).unwrap()
    ));
    let old = StateOpening {
        bytes: 4i64.to_le_bytes().to_vec(),
        nonce: [1; 32],
    };
    let legal = StateOpening {
        bytes: 6i64.to_le_bytes().to_vec(),
        nonce: [2; 32],
    };
    let illegal = StateOpening {
        bytes: 99i64.to_le_bytes().to_vec(),
        nonce: [3; 32],
    };
    for candidate in [&legal, &illegal] {
        let verdict = verify_transition(
            &ToyMovement,
            &old,
            candidate,
            &commit_state(&old),
            &commit_state(candidate),
            &signed.payload,
        );
        println!(
            "candidate {:?}: {:?}",
            i64::from_le_bytes(candidate.bytes.as_slice().try_into().unwrap()),
            verdict
        );
    }
}
