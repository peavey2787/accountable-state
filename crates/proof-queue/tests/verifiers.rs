use gv_codec::{EventBatch, EventBody, HeldChange, SignedEventBatch};
use gv_edge::audit::Authenticator;
use gv_edge::audit::{AuditLog, Evidence};
use gv_edge::quorum::{Ballot, Certificate, Claim, Receipt, WitnessSet};
use gv_edge::{BatchCommitment, SignedBatchCommitment};
use gv_proof_queue::verify::{
    pack, unpack, Commitments, Equivocation, RecoveryCertificates, Registry, SignedInputs,
    TransitionVerifier, Verifier, MAX_ITEMS,
};
use gv_proof_queue::{Family, JobSpec, Outcome, Priority};
use gv_sig::SigningKey;

const M: [u8; 32] = [7; 32];

fn key(n: u8) -> SigningKey {
    SigningKey::from_seed([n; 32])
}

fn batch(k: &SigningKey, m: [u8; 32], start: u64, init: u16) -> SignedEventBatch {
    SignedEventBatch::sign(
        EventBatch {
            match_id: m,
            participant: k.id(),
            previous_batch_hash: [0; 32],
            start_tick: start,
            tick_count: 20,
            body: EventBody::Held {
                initial: init.to_le_bytes().to_vec(),
                changes: vec![HeldChange {
                    offset: 1,
                    payload: 4u16.to_le_bytes().to_vec(),
                }],
            },
        },
        k,
    )
    .unwrap()
}

fn spec(family: Family, payload: Vec<u8>) -> JobSpec {
    JobSpec {
        family,
        match_id: M,
        payload,
        priority: Priority::Normal,
        deadline: None,
        deps: vec![],
    }
}

#[test]
fn pack_round_trips_and_rejects_anything_malformed() {
    let items = [vec![1u8, 2, 3], vec![], vec![9; 100]];
    let p = pack(&items);
    let back = unpack(&p).unwrap();
    assert_eq!(back, items.iter().map(Vec::as_slice).collect::<Vec<_>>());
    assert!(unpack(&p[..p.len() - 1]).is_none());
    let mut trailing = p.clone();
    trailing.push(0);
    assert!(unpack(&trailing).is_none());
    assert!(unpack(&[]).is_none());
    assert!(unpack(&u32::MAX.to_le_bytes()).is_none());
    let mut lying = pack(&[vec![1u8]]);
    lying[4] = 200; // item length beyond the payload
    assert!(unpack(&lying).is_none());
}

#[test]
fn signed_inputs_are_verified_and_one_bad_item_names_itself() {
    let k = key(1);
    let good: Vec<Vec<u8>> = (0..40)
        .map(|n| batch(&k, M, n * 20, n as u16 + 10).encode().unwrap())
        .collect();
    let v = SignedInputs;
    assert_eq!(
        v.verify(&spec(Family::SIGNED_INPUTS, pack(&good))),
        Outcome::Valid
    );

    let mut tampered = good.clone();
    let last = tampered[17].len() - 1;
    tampered[17][last] ^= 1;
    match v.verify(&spec(Family::SIGNED_INPUTS, pack(&tampered))) {
        Outcome::Invalid(why) => assert!(why.starts_with("item 17"), "{why}"),
        other => panic!("{other:?}"),
    }

    let elsewhere = batch(&k, [8; 32], 0, 1).encode().unwrap();
    assert!(matches!(
        v.verify(&spec(Family::SIGNED_INPUTS, pack(&[elsewhere]))),
        Outcome::Invalid(_)
    ));
    assert!(matches!(
        v.verify(&spec(Family::SIGNED_INPUTS, vec![1, 2, 3])),
        Outcome::Invalid(_)
    ));
    assert!(matches!(
        v.verify(&spec(Family::SIGNED_INPUTS, pack::<Vec<u8>>(&[]))),
        Outcome::Invalid(_)
    ));
}

#[test]
fn commitments_are_verified_against_the_match() {
    let k = key(2);
    let b = batch(&k, M, 0, 1);
    let claim = BatchCommitment::for_batch(&b, [1; 32], [2; 32], &[3; 32]).unwrap();
    let signed = SignedBatchCommitment::sign(claim, &k).unwrap();
    let v = Commitments;
    assert_eq!(
        v.verify(&spec(Family::COMMITMENT, pack(&[signed.encode()]))),
        Outcome::Valid
    );
    let mut forged = signed.encode();
    forged[40] ^= 1;
    assert!(matches!(
        v.verify(&spec(Family::COMMITMENT, pack(&[forged]))),
        Outcome::Invalid(_)
    ));
    let mut other = spec(Family::COMMITMENT, pack(&[signed.encode()]));
    other.match_id = [9; 32];
    assert!(matches!(v.verify(&other), Outcome::Invalid(_)));
}

#[test]
fn equivocation_is_proven_and_the_accused_named_but_agreement_is_not_a_violation() {
    let k = key(3);
    let honest = batch(&k, M, 0, 1);
    let lie = batch(&k, M, 5, 8);
    let ev = Evidence::ConflictingBatches(honest.clone(), lie);
    let payload = pack(&[ev.encode().unwrap()]);
    let v = Equivocation { witnesses: None };
    match v.verify(&spec(Family::EQUIVOCATION, payload.clone())) {
        Outcome::Violation { accused, evidence } => {
            assert_eq!(accused, k.id());
            assert_eq!(evidence, payload, "the evidence travels with the verdict");
        }
        other => panic!("{other:?}"),
    }
    let same = Evidence::ConflictingBatches(honest.clone(), honest);
    assert!(matches!(
        v.verify(&spec(Family::EQUIVOCATION, pack(&[same.encode().unwrap()]))),
        Outcome::Invalid(_)
    ));
}

#[test]
fn under_a_pinned_witness_set_a_tentative_log_head_does_not_convict() {
    let k = key(3);
    let ids = [key(10).id(), key(11).id(), key(12).id(), key(13).id()];
    let mut a = AuditLog::new(M, k.id());
    let mut b = AuditLog::new(M, k.id());
    a.append(1, vec![1]).unwrap();
    b.append(1, vec![2]).unwrap();
    let ev = Evidence::ConflictingAuthenticators(
        a.sign_authenticator([9; 32], &k),
        b.sign_authenticator([9; 32], &k),
    );
    let payload = pack(&[ev.encode().unwrap()]);
    let pinned = Equivocation {
        witnesses: WitnessSet::new(&ids),
    };
    let out = pinned.verify(&spec(Family::EQUIVOCATION, payload.clone()));
    assert!(matches!(out, Outcome::Inconclusive(_)), "{out:?}");
    // With no witness set the two signed heads are, on their own, a conviction.
    let unpinned = Equivocation { witnesses: None };
    let out = unpinned.verify(&spec(Family::EQUIVOCATION, payload));
    assert!(matches!(out, Outcome::Violation { .. }), "{out:?}");
}

#[test]
fn recovery_certificates_reject_garbage_without_accusing_anyone() {
    let ids = [key(10).id(), key(11).id(), key(12).id(), key(13).id()];
    let v = RecoveryCertificates {
        witnesses: WitnessSet::new(&ids).unwrap(),
    };
    for payload in [pack(&[vec![0u8; 10]]), pack(&[vec![1u8; 4000]]), vec![]] {
        assert!(matches!(
            v.verify(&spec(Family::RECOVERY_CERTIFICATE, payload)),
            Outcome::Invalid(_)
        ));
    }
}

#[test]
fn a_transition_with_a_malformed_payload_is_invalid_not_a_violation() {
    let v = TransitionVerifier {
        rules: gv_edge::testkit::GridRules,
    };
    for payload in [
        pack(&[vec![0u8; 10]]),
        pack(&[vec![0u8; 64]]),
        pack(&[vec![0u8; 5000]]),
    ] {
        assert!(matches!(
            v.verify(&spec(Family::TRANSITION, payload)),
            Outcome::Invalid(_)
        ));
    }
}

#[test]
fn a_pack_may_hold_exactly_the_maximum_number_of_items_and_no_more() {
    let at_max = pack(&vec![Vec::<u8>::new(); MAX_ITEMS]);
    assert_eq!(unpack(&at_max).map(|i| i.len()), Some(MAX_ITEMS));
    let mut over = pack(&vec![Vec::<u8>::new(); MAX_ITEMS + 1]);
    assert_eq!(over.len(), 4 + 4 * (MAX_ITEMS + 1));
    assert!(unpack(&over).is_none(), "one item past the maximum");
    over[..4].copy_from_slice(&(MAX_ITEMS as u32).to_le_bytes());
    assert!(
        unpack(&over).is_none(),
        "trailing bytes after the last item"
    );
}

struct ShortChanging;

impl Verifier for ShortChanging {
    fn family(&self) -> Family {
        Family::EQUIVOCATION
    }
    fn verify(&self, _: &JobSpec) -> Outcome {
        Outcome::Valid
    }
    fn verify_batch(&self, _: &[&JobSpec]) -> Vec<Outcome> {
        vec![Outcome::Valid]
    }
}

#[test]
fn a_verifier_that_answers_for_the_wrong_number_of_jobs_is_a_fault_not_a_verdict() {
    let registry = Registry::new().with(ShortChanging);
    let s = spec(Family::EQUIVOCATION, vec![]);
    let outcomes = registry.run(Family::EQUIVOCATION, &[&s, &s, &s]);
    assert_eq!(outcomes.len(), 3);
    assert!(outcomes.iter().all(|o| matches!(o, Outcome::Retry(_))));
    let outcomes = registry.run(Family::EQUIVOCATION, &[&s]);
    assert_eq!(outcomes, vec![Outcome::Valid]);
}

fn certificate(owner: &SigningKey, witnesses: &[SigningKey], m: [u8; 32]) -> Certificate {
    let auth = Authenticator::sign(m, [0; 32], 3, [4; 32], owner);
    let claim = Claim::sign(Ballot::default(), auth, 20, owner);
    let receipts = witnesses.iter().map(|w| Receipt::sign(&claim, w)).collect();
    Certificate { claim, receipts }
}

fn cert_spec(c: &Certificate, m: [u8; 32]) -> JobSpec {
    JobSpec {
        match_id: m,
        ..spec(Family::RECOVERY_CERTIFICATE, pack(&[c.encode()]))
    }
}

#[test]
fn a_recovery_certificate_is_certified_only_for_its_match_and_with_a_quorum() {
    let owner = key(20);
    let ws: Vec<SigningKey> = (30..34).map(key).collect();
    let ids: Vec<_> = ws.iter().map(SigningKey::id).collect();
    let v = RecoveryCertificates {
        witnesses: WitnessSet::new(&ids).unwrap(),
    };
    let full = certificate(&owner, &ws, M);
    assert_eq!(v.verify(&cert_spec(&full, M)), Outcome::Certified);
    match v.verify(&cert_spec(&full, [8; 32])) {
        Outcome::Invalid(why) => assert!(why.contains("another match"), "{why}"),
        other => panic!("{other:?}"),
    }
    let thin = certificate(&owner, &ws[..1], M);
    assert!(matches!(
        v.verify(&cert_spec(&thin, M)),
        Outcome::Inconclusive(_)
    ));
    let two_items = JobSpec {
        payload: pack(&[full.encode(), full.encode()]),
        ..cert_spec(&full, M)
    };
    assert!(matches!(v.verify(&two_items), Outcome::Invalid(_)));
}
