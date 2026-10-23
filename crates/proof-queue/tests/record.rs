use gv_proof_queue::record::Record;
use gv_proof_queue::{Event, Family, Job, JobSpec, JobState, Priority};

fn job() -> Job {
    let spec = JobSpec {
        family: Family::EQUIVOCATION,
        match_id: [3; 32],
        payload: vec![1, 2, 3],
        priority: Priority::High,
        deadline: Some(99),
        deps: vec![[4; 32]],
    };
    Job::new(spec, 7, 1)
}

fn every_kind() -> Vec<Record> {
    let mut accused = job();
    accused.state = JobState::ViolationProven;
    accused.accused = Some([9; 32]);
    accused.evidence = vec![5; 40];
    vec![
        Record::Job(Box::new(job())),
        Record::Job(Box::new(accused)),
        Record::Lease {
            id: [1; 32],
            until: 5,
        },
        Record::Retry {
            id: [1; 32],
            not_before: 8,
            reason: "later".into(),
        },
        Record::Requeue { id: [1; 32] },
        Record::Finish {
            id: [1; 32],
            state: JobState::ViolationProven,
            at: 6,
            reason: "proven".into(),
            accused: Some([2; 32]),
            evidence: vec![7; 9],
        },
        Record::Finish {
            id: [1; 32],
            state: JobState::Verified,
            at: 6,
            reason: String::new(),
            accused: None,
            evidence: vec![],
        },
        Record::Remove { id: [1; 32] },
        Record::Event(Event {
            seq: 3,
            at: 4,
            job: [1; 32],
            match_id: [2; 32],
            family: Family::TRANSITION,
            state: JobState::Certified,
        }),
    ]
}

#[test]
fn every_record_round_trips_including_who_was_accused() {
    for r in every_kind() {
        assert_eq!(Record::decode(&r.encode()).unwrap(), r);
    }
}

#[test]
fn a_record_with_anything_after_it_is_malformed() {
    for r in every_kind() {
        let mut bytes = r.encode();
        bytes.push(0);
        assert!(Record::decode(&bytes).is_err(), "{r:?}");
    }
}

#[test]
fn a_truncated_record_is_malformed() {
    for r in every_kind() {
        let bytes = r.encode();
        for cut in 0..bytes.len() {
            assert!(Record::decode(&bytes[..cut]).is_err(), "{r:?} cut at {cut}");
        }
    }
}
