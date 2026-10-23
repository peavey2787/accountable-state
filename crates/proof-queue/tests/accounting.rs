//! Counters, notifications and housekeeping arithmetic: every number the queue reports is checked
//! against what actually happened.
use gv_proof_queue::record::Record;
use gv_proof_queue::{
    Config, Family, Job, JobId, JobSpec, JobState, Journal, MemJournal, Outcome, Priority, Queue,
    SubmitError, Submitted,
};

const F: Family = Family::EQUIVOCATION;
const ALL: &[Family] = &[F];

fn spec(m: u8, n: u32) -> JobSpec {
    JobSpec {
        family: F,
        match_id: [m; 32],
        payload: n.to_le_bytes().to_vec(),
        priority: Priority::Normal,
        deadline: None,
        deps: vec![],
    }
}

fn queue(cfg: &Config) -> Queue {
    Queue::open(MemJournal::new().open(), cfg.clone(), 0).unwrap()
}

fn finish_next(q: &mut Queue, now: u64, outcome: Outcome) -> JobId {
    let l = q.lease(now, ALL).unwrap().expect("a ready job");
    assert!(q.complete(&l.id, outcome, now).unwrap());
    l.id
}

#[test]
fn submission_counters_count_each_kind_of_outcome() {
    let mut q = queue(&Config::default());
    let mut s = spec(1, 1);
    s.deadline = Some(5);
    q.submit(s.clone(), 0).unwrap();
    q.submit(spec(1, 2), 0).unwrap();
    assert!(matches!(
        q.submit(spec(1, 2), 0),
        Ok(Submitted::Duplicate(_))
    ));
    assert!(matches!(
        q.submit(spec(1, 2), 0),
        Ok(Submitted::Duplicate(_))
    ));
    q.maintain(5).unwrap();
    s.deadline = None;
    assert!(matches!(
        q.submit(s.clone(), 6),
        Ok(Submitted::Resubmitted(_))
    ));
    finish_next(&mut q, 7, Outcome::Valid);
    q.maintain(8).unwrap();
    assert!(matches!(q.submit(s, 9), Ok(Submitted::Duplicate(_))));
    let m = q.metrics();
    assert_eq!((m.submitted, m.duplicates, m.resubmitted), (2, 3, 1));
    assert_eq!(m.leased, 1);
}

#[test]
fn rejections_are_counted_by_reason() {
    let cfg = Config {
        max_payload: 4,
        max_live_per_match: 1,
        ..Config::default()
    };
    let mut q = queue(&cfg);
    q.submit(spec(1, 1), 0).unwrap();
    for n in 2..4 {
        assert!(matches!(
            q.submit(spec(1, n), 0),
            Err(SubmitError::MatchFull)
        ));
    }
    for n in 0..2 {
        let mut big = spec(2, n);
        big.payload = vec![0; 5];
        assert!(matches!(q.submit(big, 0), Err(SubmitError::TooLarge)));
    }
    let m = q.metrics();
    assert_eq!((m.rejected_full, m.rejected_invalid), (2, 2));
}

#[test]
fn a_payload_of_exactly_the_limit_is_accepted() {
    let mut q = queue(&Config {
        max_payload: 4,
        ..Config::default()
    });
    assert!(q.submit(spec(1, 1), 0).is_ok());
}

#[test]
fn leasing_counts_every_lease() {
    let mut q = queue(&Config::default());
    for n in 0..3 {
        q.submit(spec(1, n), 0).unwrap();
        q.lease(0, ALL).unwrap().unwrap();
    }
    assert_eq!(q.metrics().leased, 3);
}

#[test]
fn cancelling_ends_only_unfinished_jobs_and_says_whether_it_did() {
    let mut q = queue(&Config::default());
    let a = q.submit(spec(1, 1), 0).unwrap().id();
    let b = q.submit(spec(1, 2), 0).unwrap().id();
    let done = finish_next(&mut q, 0, Outcome::Valid);
    let open = if done == a { b } else { a };
    assert!(q.cancel(&open, 1).unwrap());
    assert_eq!(q.get(&open).unwrap().state, JobState::Uncertified);
    assert!(!q.cancel(&open, 2).unwrap());
    assert!(!q.cancel(&done, 2).unwrap());
    assert_eq!(q.get(&done).unwrap().state, JobState::Verified);
    assert!(!q.cancel(&[0xee; 32], 2).unwrap());
}

#[test]
fn notifications_are_numbered_without_gaps_and_the_newest_are_kept() {
    let cfg = Config {
        max_events: 4,
        ..Config::default()
    };
    let mut q = queue(&cfg);
    for n in 0..4 {
        q.submit(spec(1, n), 0).unwrap();
    }
    let seqs: Vec<u64> = q.events_after(0, 10).events.iter().map(|e| e.seq).collect();
    assert_eq!(
        seqs.len(),
        4,
        "a full retention window keeps every notification"
    );
    assert!(seqs.windows(2).all(|w| w[1] == w[0] + 1));
    q.submit(spec(1, 9), 0).unwrap();
    let seqs: Vec<u64> = q.events_after(0, 10).events.iter().map(|e| e.seq).collect();
    assert_eq!(seqs.len(), 4);
    assert_eq!(seqs.last().copied(), Some(q.last_event()));
}

#[test]
fn a_finished_job_frees_its_place_in_its_match() {
    let cfg = Config {
        max_live_per_match: 2,
        ..Config::default()
    };
    let mut q = queue(&cfg);
    q.submit(spec(1, 1), 0).unwrap();
    q.submit(spec(1, 2), 0).unwrap();
    assert!(matches!(
        q.submit(spec(1, 3), 0),
        Err(SubmitError::MatchFull)
    ));
    finish_next(&mut q, 1, Outcome::Valid);
    q.submit(spec(1, 3), 2).unwrap();
    assert!(matches!(
        q.submit(spec(1, 4), 2),
        Err(SubmitError::MatchFull)
    ));
    assert_eq!(q.stats().live, 2);
}

fn replayed(records: &[Record]) -> Queue {
    let mut mem = MemJournal::new();
    let raw: Vec<Vec<u8>> = records.iter().map(Record::encode).collect();
    mem.append(&raw).unwrap();
    Queue::open(mem.open(), Config::default(), 0).unwrap()
}

fn finish_record(id: JobId, state: JobState) -> Record {
    Record::Finish {
        id,
        state,
        at: 1,
        reason: String::new(),
        accused: None,
        evidence: vec![],
    }
}

#[test]
fn a_finish_record_for_a_finished_job_changes_nothing_when_replayed() {
    let job = Job::new(spec(1, 1), 0, 1);
    let q = replayed(&[
        Record::Job(Box::new(job.clone())),
        finish_record(job.id, JobState::Verified),
        finish_record(job.id, JobState::Failed),
        finish_record(job.id, JobState::Pending),
    ]);
    assert_eq!(q.get(&job.id).unwrap().state, JobState::Verified);
}

#[test]
fn a_finish_record_that_is_not_terminal_is_ignored_when_replayed() {
    let job = Job::new(spec(1, 1), 0, 1);
    let q = replayed(&[
        Record::Job(Box::new(job.clone())),
        finish_record(job.id, JobState::Processing),
    ]);
    assert_eq!(q.get(&job.id).unwrap().state, JobState::Pending);
    assert_eq!(q.stats().live, 1);
}

#[test]
fn housekeeping_reports_what_it_did() {
    let cfg = Config {
        lease_ticks: 10,
        retention: 5,
        ..Config::default()
    };
    let mut q = queue(&cfg);
    for n in 0..2 {
        q.submit(spec(1, n), 0).unwrap();
        q.lease(0, ALL).unwrap().unwrap();
    }
    q.maintain(10).unwrap();
    assert_eq!(q.metrics().lapsed_leases, 2);
    assert_eq!(q.metrics().gc_removed, 0);
    finish_next(&mut q, 11, Outcome::Valid);
    finish_next(&mut q, 11, Outcome::Valid);
    q.maintain(16).unwrap();
    assert_eq!(q.metrics().gc_removed, 2);
    assert_eq!(q.stats().retained, 0);
    q.maintain(17).unwrap();
    assert_eq!(q.metrics().gc_removed, 2);
}

fn dependent(dep: JobId, m: u8, n: u32) -> JobSpec {
    JobSpec {
        deps: vec![dep],
        ..spec(m, n)
    }
}

#[test]
fn a_dependent_waits_while_its_dependency_is_unfinished_or_verified() {
    let mut q = queue(&Config::default());
    let a = q.submit(spec(1, 1), 0).unwrap().id();
    let b = q.submit(dependent(a, 1, 2), 0).unwrap().id();
    q.maintain(1).unwrap();
    assert_eq!(
        q.get(&b).unwrap().state,
        JobState::Pending,
        "dependency pending"
    );
    finish_next(&mut q, 2, Outcome::Valid);
    q.maintain(3).unwrap();
    assert_eq!(
        q.get(&b).unwrap().state,
        JobState::Pending,
        "dependency verified"
    );
    finish_next(&mut q, 4, Outcome::Valid);
    assert_eq!(q.get(&b).unwrap().state, JobState::Verified);
}

#[test]
fn a_dependent_of_a_failed_job_ends_unverified_with_the_dependency_named() {
    let mut q = queue(&Config::default());
    let a = q.submit(spec(1, 1), 0).unwrap().id();
    let b = q.submit(dependent(a, 1, 2), 0).unwrap().id();
    finish_next(&mut q, 1, Outcome::Invalid("bad".into()));
    q.maintain(2).unwrap();
    let job = q.get(&b).unwrap();
    assert_eq!(job.state, JobState::Uncertified);
    let prefix: String = a.iter().take(4).map(|x| format!("{x:02x}")).collect();
    assert_eq!(job.reason, format!("dependency {prefix} did not verify"));
}

#[test]
fn a_job_that_expires_and_has_a_broken_dependency_finishes_once() {
    let mut q = queue(&Config::default());
    let a = q.submit(spec(1, 1), 0).unwrap().id();
    let mut s = dependent(a, 1, 2);
    s.deadline = Some(5);
    let b = q.submit(s, 0).unwrap().id();
    finish_next(&mut q, 1, Outcome::Invalid("bad".into()));
    let before = q.events_after(0, 100).events.len();
    q.maintain(5).unwrap();
    assert_eq!(q.get(&b).unwrap().state, JobState::Expired);
    let after = q.events_after(0, 100).events.len();
    assert_eq!(after - before, 1, "one notification for one ending");
}

#[test]
fn finished_work_is_collected_even_when_it_depended_on_other_finished_work() {
    let cfg = Config {
        retention: 5,
        ..Config::default()
    };
    let mut q = queue(&cfg);
    let a = q.submit(spec(1, 1), 0).unwrap().id();
    let b = q.submit(dependent(a, 1, 2), 0).unwrap().id();
    finish_next(&mut q, 1, Outcome::Valid);
    finish_next(&mut q, 1, Outcome::Valid);
    q.maintain(100).unwrap();
    assert!(q.get(&a).is_none() && q.get(&b).is_none());
}

#[test]
fn a_dependency_is_kept_while_something_unfinished_needs_it() {
    let cfg = Config {
        retention: 5,
        ..Config::default()
    };
    let mut q = queue(&cfg);
    let a = q.submit(spec(1, 1), 0).unwrap().id();
    finish_next(&mut q, 1, Outcome::Valid);
    let b = q.submit(dependent(a, 1, 2), 2).unwrap().id();
    q.maintain(100).unwrap();
    assert!(q.get(&a).is_some(), "needed by a pending job");
    finish_next(&mut q, 101, Outcome::Valid);
    q.maintain(200).unwrap();
    assert!(q.get(&a).is_none() && q.get(&b).is_none());
}

#[test]
fn compaction_waits_for_the_minimum_and_then_for_the_journal_to_double() {
    let probe = {
        let mut q = queue(&Config::default());
        q.submit(spec(1, 0), 0).unwrap();
        q.stats().journal_bytes
    };
    let cfg = Config {
        compact_min_bytes: 4 * probe,
        ..Config::default()
    };
    let mut q = queue(&cfg);
    let submit = |q: &mut Queue, n: u32| {
        q.submit(spec(1, n), 0).unwrap();
        q.maintain(0).unwrap();
    };
    for n in 0..3 {
        submit(&mut q, n);
    }
    assert_eq!(q.metrics().compactions, 0, "below the minimum");
    submit(&mut q, 3);
    assert_eq!(q.metrics().compactions, 1, "exactly at the minimum");
    assert_eq!(
        q.stats().journal_bytes,
        4 * probe,
        "a snapshot is as large as the live jobs"
    );
    for n in 4..7 {
        submit(&mut q, n);
    }
    assert_eq!(q.metrics().compactions, 1, "not yet doubled");
    submit(&mut q, 7);
    assert_eq!(q.metrics().compactions, 2, "exactly doubled");
}

#[test]
fn notifications_of_one_housekeeping_pass_are_numbered_one_after_another() {
    let mut q = queue(&Config::default());
    for n in 0..3 {
        let mut s = spec(1, n);
        s.deadline = Some(5);
        q.submit(s, 0).unwrap();
    }
    let before = q.last_event();
    q.maintain(10).unwrap();
    let seqs: Vec<u64> = q
        .events_after(before, 10)
        .events
        .iter()
        .map(|e| e.seq)
        .collect();
    assert_eq!(seqs, vec![before + 1, before + 2, before + 3]);
    assert_eq!(q.last_event(), before + 3);
}

#[test]
fn a_failed_compaction_is_counted_once_per_failure() {
    let mem = MemJournal::new();
    let cfg = Config {
        compact_min_bytes: 1,
        ..Config::default()
    };
    let mut q = Queue::open(mem.open(), cfg, 0).unwrap();
    q.submit(spec(1, 0), 0).unwrap();
    mem.set_failing(true);
    for failures in 1..=2 {
        assert!(q.maintain(0).is_err());
        assert_eq!(q.metrics().storage_errors, failures);
    }
    assert_eq!(q.metrics().compactions, 0);
}
