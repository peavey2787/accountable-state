use accountable_state::proofs::{
    Equivocation, Queue, QueueConfig, Registry, Service, ServiceConfig, SystemClock,
};
use accountable_state::{Dest, Outgoing, Output, ProofOffload, WitnessOut};
use gv_codec::{EventBatch, EventBody, HeldChange, SignedEventBatch};
use gv_edge::audit::Evidence;
use gv_proof_queue::{Family, MemJournal};
use gv_sig::SigningKey;
use std::sync::Arc;

const MATCH: [u8; 32] = [7; 32];

fn batch(k: &SigningKey, start: u64, init: u16) -> SignedEventBatch {
    SignedEventBatch::sign(
        EventBatch {
            match_id: MATCH,
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

fn conflicting(k: &SigningKey) -> Vec<u8> {
    Evidence::ConflictingBatches(batch(k, 0, 1), batch(k, 5, 8))
        .encode()
        .unwrap()
}

fn offload(max_events: usize) -> (Arc<Service>, ProofOffload) {
    let cfg = QueueConfig {
        max_events,
        ..QueueConfig::default()
    };
    let queue = Queue::open(MemJournal::new().open(), cfg, 0).unwrap();
    let service = Arc::new(Service::new(
        queue,
        Registry::new().with(Equivocation { witnesses: None }),
        Box::new(SystemClock),
        ServiceConfig::default(),
    ));
    let offload = ProofOffload::new(Arc::clone(&service), MATCH);
    (service, offload)
}

fn evidence_output(bytes: Vec<u8>) -> Output {
    Output::Send(Outgoing::Witness(WitnessOut::Evidence(bytes)))
}

#[test]
fn equivocation_evidence_becomes_a_finding_naming_the_accused() {
    let (service, mut offload) = offload(1000);
    let cheat = SigningKey::from_seed([3; 32]);
    assert!(offload
        .offer(&evidence_output(conflicting(&cheat)))
        .unwrap());
    assert!(offload.findings().proven.is_empty(), "nothing verified yet");
    service.step().unwrap();
    let found = offload.findings();
    assert!(!found.missed);
    assert_eq!(found.proven.len(), 1);
    assert_eq!(found.proven[0].accused, cheat.id());
    assert_eq!(found.proven[0].family, Family::EQUIVOCATION);
    assert!(
        offload.findings().proven.is_empty(),
        "a finding is reported once"
    );

    assert!(offload.acknowledge(&found.proven[0]).unwrap());
    assert!(service.job(&found.proven[0].job).is_none());
}

#[test]
fn the_same_evidence_twice_is_one_job() {
    let (_, offload) = offload(1000);
    let ev = conflicting(&SigningKey::from_seed([3; 32]));
    assert!(offload.offer(&evidence_output(ev.clone())).unwrap());
    assert!(!offload.offer(&evidence_output(ev)).unwrap());
}

#[test]
fn only_evidence_is_offered_and_unusable_evidence_proves_nothing() {
    let (service, mut offload) = offload(1000);
    let other = Output::Send(Outgoing::Member {
        to: Dest::All,
        bytes: vec![1, 2, 3],
    });
    assert!(!offload.offer(&other).unwrap());
    assert!(offload.offer(&evidence_output(vec![9; 40])).unwrap());
    service.step().unwrap();
    assert!(offload.findings().proven.is_empty());
}

#[test]
fn a_reader_that_fell_behind_is_told_it_may_have_missed_verdicts() {
    let (service, mut offload) = offload(4);
    for seed in 1..=6u8 {
        let k = SigningKey::from_seed([seed; 32]);
        offload.offer(&evidence_output(conflicting(&k))).unwrap();
    }
    while service.step().unwrap() > 0 {}
    let found = offload.findings();
    assert!(found.missed);
}

#[test]
fn a_match_hears_only_about_its_own_violations() {
    let (service, mut first) = offload(1000);
    let mut second = ProofOffload::new(Arc::clone(&service), [MATCH[0].wrapping_add(1); 32]);
    let cheat = SigningKey::from_seed([3; 32]);
    assert!(first.offer(&evidence_output(conflicting(&cheat))).unwrap());
    service.step().unwrap();
    assert!(
        second.findings().proven.is_empty(),
        "another match's proof is not mine"
    );
    assert_eq!(first.findings().proven.len(), 1);
}
