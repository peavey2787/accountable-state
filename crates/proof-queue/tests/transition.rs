use gv_codec::{EventBatch, EventBody, HeldChange, SignedEventBatch};
use gv_core::{Certification, Digest, Ordering, Participant, Roster, Session};
use gv_edge::testkit::GridRules;
use gv_edge::{CertifiedEpoch, MatchReplica};
use gv_proof_queue::verify::{transition_payload, TransitionVerifier, Verifier};
use gv_proof_queue::{Family, JobSpec, Outcome, Priority};
use gv_sig::SigningKey;

const M: [u8; 32] = [5; 32];
const TICKS: u32 = 4;

fn controls(c: u16) -> Vec<u8> {
    c.to_le_bytes().to_vec()
}

fn played_epoch() -> (CertifiedEpoch, Digest, Digest) {
    let mut keys: Vec<SigningKey> = (0..3u8)
        .map(|i| SigningKey::from_seed([31 + i * 10; 32]))
        .collect();
    keys.sort_by_key(SigningKey::id);
    let roster = Roster::new(
        keys.iter()
            .map(|k| Participant::player(k.id(), 0))
            .collect(),
    )
    .unwrap();
    let session = Session::new(
        M,
        roster,
        Certification::Unanimous,
        Ordering::Roster,
        vec![],
    )
    .unwrap();
    let mut replica = MatchReplica::new(session.clone(), GridRules).unwrap();
    for k in &keys {
        let batch = SignedEventBatch::sign(
            EventBatch {
                match_id: M,
                participant: k.id(),
                previous_batch_hash: replica.next_batch_head(k.id()).unwrap(),
                start_tick: replica.next_tick(),
                tick_count: TICKS,
                body: EventBody::Held {
                    initial: controls(0),
                    changes: vec![HeldChange {
                        offset: 1,
                        payload: controls(1),
                    }],
                },
            },
            k,
        )
        .unwrap();
        replica.admit(batch).unwrap();
    }
    let sigs: Vec<_> = keys
        .iter()
        .map(|k| replica.sign_candidate(k).unwrap())
        .collect();
    replica.finalize(sigs).unwrap();
    let accepted = replica.accepted().last().unwrap();
    let (pc, ps) = (
        accepted.checkpoint.previous_checkpoint,
        accepted.checkpoint.previous_state,
    );
    (
        CertifiedEpoch::from_accepted(accepted, &session).unwrap(),
        pc,
        ps,
    )
}

fn job(payload: Vec<u8>) -> JobSpec {
    JobSpec {
        family: Family::TRANSITION,
        match_id: M,
        payload,
        priority: Priority::Normal,
        deadline: None,
        deps: vec![],
    }
}

#[test]
fn an_honestly_played_epoch_replays_to_certified() {
    let (epoch, pc, ps) = played_epoch();
    let v = TransitionVerifier { rules: GridRules };
    let payload = transition_payload(pc, ps, &epoch).unwrap();
    assert_eq!(v.verify(&job(payload)), Outcome::Certified);
}

#[test]
fn an_epoch_replayed_from_the_wrong_starting_point_is_not_certified() {
    let (epoch, pc, _) = played_epoch();
    let v = TransitionVerifier { rules: GridRules };
    let payload = transition_payload(pc, [0xEE; 32], &epoch).unwrap();
    assert_ne!(v.verify(&job(payload)), Outcome::Certified);
}

#[test]
fn an_epoch_for_another_match_is_invalid() {
    let (epoch, pc, ps) = played_epoch();
    let v = TransitionVerifier { rules: GridRules };
    let mut other = job(transition_payload(pc, ps, &epoch).unwrap());
    other.match_id = [6; 32];
    assert!(matches!(v.verify(&other), Outcome::Invalid(_)));
}
