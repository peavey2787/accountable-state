use super::*;
use crate::testkit::{GridRules, GridState, LEFT, RIGHT};
use gv_codec::{EventBatch, EventBody, HeldChange, SignedEventBatch};
use gv_core::{Certification, Ordering, Participant, Roster, Session};
use gv_sig::SigningKey;

const MATCH: [u8; 32] = [4; 32];

fn controls(c: u16) -> Vec<u8> {
    c.to_le_bytes().to_vec()
}

fn signed(key: &SigningKey, initial: u16, changes: Vec<HeldChange>) -> SignedEventBatch {
    SignedEventBatch::sign(
        EventBatch {
            match_id: MATCH,
            participant: key.id(),
            previous_batch_hash: [0; 32],
            start_tick: 0,
            tick_count: 4,
            body: EventBody::Held {
                initial: controls(initial),
                changes,
            },
        },
        key,
    )
    .unwrap()
}

fn keys() -> [SigningKey; 3] {
    [9u8, 11, 13].map(|s| SigningKey::from_seed([s; 32]))
}

fn session(keys: &[SigningKey; 3]) -> Session {
    let roster = Roster::new(
        keys.iter()
            .map(|k| Participant::player(k.id(), 0))
            .collect(),
    )
    .unwrap();
    Session::new(
        MATCH,
        roster,
        Certification::Unanimous,
        Ordering::Roster,
        Vec::new(),
    )
    .unwrap()
}

/// Batches in roster order, with a real change in the first one.
fn batches(keys: &[SigningKey; 3], session: &Session) -> Vec<Option<SignedEventBatch>> {
    let change = vec![HeldChange {
        offset: 2,
        payload: controls(0),
    }];
    session
        .roster
        .participants()
        .iter()
        .enumerate()
        .map(|(slot, p)| {
            let key = keys.iter().find(|k| k.id() == p.id).unwrap();
            Some(match slot {
                0 => signed(key, LEFT, change.clone()),
                1 => signed(key, RIGHT, vec![]),
                _ => signed(key, 0, vec![]),
            })
        })
        .collect()
}

#[test]
fn independent_replicas_and_fraud() {
    let keys = keys();
    let session = session(&keys);
    let rules = GridRules;
    let mut replicas: Vec<_> = (0..3)
        .map(|_| MatchReplica::new(session.clone(), rules).unwrap())
        .collect();
    let inputs = batches(&keys, &session);
    for (n, r) in replicas.iter_mut().enumerate() {
        // Admission order must not matter.
        let mut order: Vec<_> = inputs.iter().flatten().cloned().collect();
        order.rotate_left(n);
        for b in order {
            r.admit(b).unwrap();
        }
    }
    let expected = replicas[0].candidate().unwrap();
    assert!(replicas
        .iter()
        .all(|r| r.candidate().unwrap().checkpoint == expected.checkpoint));
    let sigs: Vec<_> = replicas
        .iter()
        .zip(&keys_in_roster_order(&keys, &session))
        .map(|(r, k)| r.sign_candidate(k).unwrap())
        .collect();
    let heads: Vec<_> = replicas
        .iter_mut()
        .map(|r| r.finalize(sigs.clone()).unwrap())
        .collect();
    assert!(heads.windows(2).all(|w| w[0] == w[1]));
    assert_eq!(replicas[0].state(), replicas[1].state());
    assert_eq!(replicas[0].next_tick(), 4);
    let state = GridState::decode(replicas[0].state()).unwrap();
    assert_eq!(state.walkers.len(), 3);

    let cert = CertifiedEpoch::from_accepted(&replicas[0].accepted()[0], &session).unwrap();
    let prev_state = expected.checkpoint.previous_state;
    assert_eq!(
        cert.verify(&rules, [0; 32], prev_state),
        EvidenceVerdict::ValidClaim
    );
    let serialized = cert.encode().unwrap();
    let recovered = CertifiedEpoch::decode(&serialized).unwrap();
    assert_eq!(
        recovered.verify(&rules, [0; 32], prev_state),
        EvidenceVerdict::ValidClaim
    );
    let mut corrupted = serialized;
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    assert!(CertifiedEpoch::decode(&corrupted).is_err());

    let genesis = rules.genesis(&session);
    let accused_key = &keys[0];
    let valid = CheckpointEvidence {
        trusted_previous_checkpoint: [0; 32],
        trusted_previous_state: prev_state,
        accused: sigs
            .iter()
            .find(|s| s.signer == accused_key.id())
            .unwrap()
            .clone(),
        previous_state: genesis,
        session: session.clone(),
        inputs,
    };
    assert_eq!(
        verify_checkpoint_evidence(&rules, &valid),
        EvidenceVerdict::ValidClaim
    );
    let mut false_checkpoint = expected.checkpoint.clone();
    false_checkpoint.next_state = [0xa5; 32];
    let fake = CheckpointEvidence {
        accused: SignedCheckpoint::sign(false_checkpoint, accused_key),
        ..valid
    };
    assert_eq!(
        verify_checkpoint_evidence(&rules, &fake),
        EvidenceVerdict::ProvenInvalidState
    );
    let mut tampered = fake.clone();
    if let Some(Some(b)) = tampered.inputs.first_mut() {
        if let EventBody::Held { initial, .. } = &mut b.record.body {
            initial[0] ^= 1;
        }
    }
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

fn keys_in_roster_order(keys: &[SigningKey; 3], session: &Session) -> Vec<SigningKey> {
    session
        .roster
        .participants()
        .iter()
        .map(|p| keys.iter().find(|k| k.id() == p.id).unwrap().clone())
        .collect()
}
