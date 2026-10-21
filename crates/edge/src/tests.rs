use super::*;
use gv_codec::{ControlChange, PackedControls, SignedPackedControls};
use gv_core::{Digest, PlayerId};
use gv_replay::{RuleError, StateMachine, ViolationCode};
use gv_sig::SigningKey;

#[derive(Clone)]
struct MoveRules {
    roster: [PlayerId; 2],
}
impl StateMachine for MoveRules {
    fn ruleset_hash(&self) -> Digest {
        [7; 32]
    }
    fn genesis(&self, _: &[PlayerId; 2]) -> Vec<u8> {
        vec![0; 16]
    }
    fn apply(&self, s: &[u8], i: &[u8]) -> Result<Vec<u8>, RuleError> {
        let invalid = || RuleError::InvalidAction(ViolationCode(1));
        if s.len() != 16 || i.len() != 42 {
            return Err(invalid());
        }
        let idx = self
            .roster
            .iter()
            .position(|p| p[..] == i[..32])
            .ok_or_else(invalid)?;
        let control = u16::from_le_bytes([i[40], i[41]]);
        if control & !3 != 0 || control == 3 {
            return Err(invalid());
        }
        let mut out = s.to_vec();
        let mut xy = [0u8; 8];
        xy.copy_from_slice(&out[idx * 8..idx * 8 + 8]);
        let x = i64::from_le_bytes(xy);
        let dx = match control {
            1 => 1,
            2 => -1,
            _ => 0,
        };
        let new = x.checked_add(dx).ok_or_else(invalid)?;
        out[idx * 8..idx * 8 + 8].copy_from_slice(&new.to_le_bytes());
        Ok(out)
    }
}
fn signed(
    key: &SigningKey,
    match_id: [u8; 32],
    start: u64,
    previous: [u8; 32],
    first: u16,
    changes: Vec<ControlChange>,
) -> SignedPackedControls {
    SignedPackedControls::sign(
        PackedControls {
            match_id,
            player: key.id(),
            previous_batch_hash: previous,
            start_tick: start,
            tick_count: 4,
            control_bytes: 1,
            initial_state: first,
            changes,
        },
        key,
    )
    .unwrap()
}
#[test]
fn independent_replicas_and_fraud() {
    let alice = SigningKey::from_seed([9; 32]);
    let bob = SigningKey::from_seed([11; 32]);
    let mut roster = [alice.id(), bob.id()];
    roster.sort();
    let rules = MoveRules { roster };
    let mut a = MatchReplica::new([4; 32], roster, rules.clone()).unwrap();
    let mut b = MatchReplica::new([4; 32], roster, rules.clone()).unwrap();
    let batch_a = signed(
        &alice,
        [4; 32],
        0,
        [0; 32],
        1,
        vec![ControlChange {
            offset: 2,
            state: 0,
        }],
    );
    let batch_b = signed(&bob, [4; 32], 0, [0; 32], 2, vec![]);
    a.admit(batch_a.clone()).unwrap();
    a.admit(batch_b.clone()).unwrap();
    b.admit(batch_b.clone()).unwrap();
    b.admit(batch_a.clone()).unwrap();
    assert_eq!(
        a.candidate().unwrap().checkpoint,
        b.candidate().unwrap().checkpoint
    );
    let expected = a.candidate().unwrap();
    let sig_alice = a.sign_candidate(&alice).unwrap();
    let sig_bob = b.sign_candidate(&bob).unwrap();
    let mut signatures = [sig_alice.clone(), sig_bob];
    signatures.sort_by_key(|s| s.player);
    assert_eq!(
        a.finalize(signatures.clone()).unwrap(),
        b.finalize(signatures).unwrap()
    );
    assert_eq!(a.state(), b.state());
    assert_eq!(a.next_tick(), 4);
    let cert = CertifiedEpoch::from_accepted(&a.accepted()[0], roster).unwrap();
    assert_eq!(
        cert.verify(&rules, [0; 32], expected.checkpoint.previous_state),
        EvidenceVerdict::ValidClaim
    );
    let serialized = cert.encode().unwrap();
    let recovered = CertifiedEpoch::decode(&serialized).unwrap();
    assert_eq!(
        recovered.verify(&rules, [0; 32], expected.checkpoint.previous_state),
        EvidenceVerdict::ValidClaim
    );
    let mut corrupted = serialized;
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    assert!(CertifiedEpoch::decode(&corrupted).is_err());
    let opening = vec![0; 16];
    let order = if batch_a.record.player < batch_b.record.player {
        [batch_a, batch_b]
    } else {
        [batch_b, batch_a]
    };
    let valid = CheckpointEvidence {
        trusted_previous_checkpoint: [0; 32],
        trusted_previous_state: expected.checkpoint.previous_state,
        accused: sig_alice,
        previous_state: opening,
        player_batches: order.clone(),
        roster,
    };
    assert_eq!(
        verify_checkpoint_evidence(&rules, &valid),
        EvidenceVerdict::ValidClaim
    );
    let mut false_checkpoint = expected.checkpoint.clone();
    false_checkpoint.next_state = [0xa5; 32];
    let fake = CheckpointEvidence {
        accused: SignedCheckpoint::sign(false_checkpoint, &alice),
        ..valid
    };
    assert_eq!(
        verify_checkpoint_evidence(&rules, &fake),
        EvidenceVerdict::ProvenInvalidState
    );
    let mut tampered = fake.clone();
    tampered.player_batches[0].record.initial_state ^= 1;
    assert!(matches!(
        verify_checkpoint_evidence(&rules, &tampered),
        EvidenceVerdict::Inconclusive(_)
    ));
    let mut fabricated = fake;
    fabricated.trusted_previous_checkpoint = [1; 32];
    assert_eq!(
        verify_checkpoint_evidence(&rules, &fabricated),
        EvidenceVerdict::Inconclusive(CheckpointError::InvalidHistory)
    );
}
