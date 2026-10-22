//! Signed inputs + Merkle inclusion + deterministic replay. No network finality.
use gv_commitments::{commit_state, verify_membership, MerkleLog};
use gv_core::{Digest, Session, StateOpening};
use gv_replay::{verify_transition, RuleError, StateMachine, ViolationCode};
use gv_sig::SigningKey;
use gv_transcript::SignedInput;

struct ToyMovement;
/// The state or input is not an 8-byte coordinate.
const NONCANONICAL: ViolationCode = ViolationCode(1);
/// A step larger than the input domain allows.
const OUT_OF_DOMAIN: ViolationCode = ViolationCode(2);
/// The coordinate would overflow.
const OVERFLOW: ViolationCode = ViolationCode(3);

impl StateMachine for ToyMovement {
    fn ruleset_hash(&self) -> Digest {
        [9; 32]
    }
    fn genesis(&self, _: &Session) -> Vec<u8> {
        0i64.to_le_bytes().to_vec()
    }
    fn apply(&self, previous: &[u8], input: &[u8]) -> Result<Vec<u8>, RuleError> {
        let coordinate = |b: &[u8]| {
            b.try_into()
                .map(i64::from_le_bytes)
                .map_err(|_| RuleError::InvalidAction(NONCANONICAL))
        };
        let x = coordinate(previous)?;
        let delta = coordinate(input)?;
        if !(-5..=5).contains(&delta) {
            return Err(RuleError::InvalidAction(OUT_OF_DOMAIN));
        }
        let next = x
            .checked_add(delta)
            .ok_or(RuleError::InvalidAction(OVERFLOW))?;
        Ok(next.to_le_bytes().to_vec())
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
