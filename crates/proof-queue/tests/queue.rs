use gv_proof_queue::{
    Config, Family, FileJournal, JobId, JobSpec, JobState, MemJournal, Outcome, Priority, Queue,
    SubmitError, Submitted,
};

const F: Family = Family::EQUIVOCATION;
const ALL: &[Family] = &[F];

fn spec(m: u8, n: u32, p: Priority) -> JobSpec {
    JobSpec {
        family: F,
        match_id: [m; 32],
        payload: n.to_le_bytes().to_vec(),
        priority: p,
        deadline: None,
        deps: vec![],
    }
}

fn open(mem: &MemJournal, cfg: &Config) -> Queue {
    Queue::open(mem.open(), cfg.clone(), 0).expect("open")
}

fn state(q: &Queue, id: &JobId) -> JobState {
    q.get(id).expect("job").state
}

fn run_one(q: &mut Queue, now: u64, outcome: Outcome) -> JobId {
    let l = q.lease(now, ALL).unwrap().expect("a ready job");
    assert!(q.complete(&l.id, outcome, now).unwrap());
    l.id
}

#[test]
fn a_job_goes_from_pending_to_verified_with_notifications() {
    let mem = MemJournal::new();
    let mut q = open(&mem, &Config::default());
    let id = q.submit(spec(1, 1, Priority::Normal), 10).unwrap().id();
    assert_eq!(state(&q, &id), JobState::Pending);
    run_one(&mut q, 20, Outcome::Valid);
    assert_eq!(state(&q, &id), JobState::Verified);
    let states: Vec<_> = q
        .events_after(0, 10)
        .events
        .iter()
        .map(|e| e.state)
        .collect();
    assert_eq!(
        states,
        [JobState::Pending, JobState::Processing, JobState::Verified]
    );
    assert_eq!(q.metrics().finished(JobState::Verified), 1);
}

#[test]
fn the_same_evidence_is_one_job() {
    let mut q = open(&MemJournal::new(), &Config::default());
    let a = q.submit(spec(1, 1, Priority::Normal), 0).unwrap();
    let b = q.submit(spec(1, 1, Priority::High), 0).unwrap();
    assert!(matches!(a, Submitted::New(_)));
    assert!(matches!(b, Submitted::Duplicate(_)));
    assert_eq!(q.stats().live, 1);
}

#[test]
fn a_restart_replays_to_the_same_state_and_requeues_interrupted_work() {
    let mem = MemJournal::new();
    let cfg = Config::default();
    let mut q = open(&mem, &cfg);
    let ids: Vec<JobId> = (0..500)
        .map(|n| {
            q.submit(spec((n % 7) as u8, n, Priority::Normal), 0)
                .unwrap()
                .id()
        })
        .collect();
    for _ in 0..200 {
        run_one(&mut q, 1, Outcome::Valid);
    }
    let in_flight = q.lease(2, ALL).unwrap().unwrap();
    let before: Vec<_> = ids.iter().map(|i| state(&q, i)).collect();
    drop(q); // crash with one job leased

    let mut q = open(&mem, &cfg);
    for (id, was) in ids.iter().zip(before) {
        let expect = if *id == in_flight.id {
            JobState::Pending
        } else {
            was
        };
        assert_eq!(state(&q, id), expect);
    }
    let again = q.lease(3, ALL).unwrap().unwrap();
    assert!(q.complete(&again.id, Outcome::Valid, 3).unwrap());
    assert_eq!(q.events_after(0, 10_000).events.len(), 500 + 400 + 1 + 2);
}

#[test]
fn a_crash_that_loses_the_journal_tail_still_opens_consistently() {
    let mem = MemJournal::new();
    let cfg = Config::default();
    let mut q = open(&mem, &cfg);
    for n in 0..50 {
        q.submit(spec(1, n, Priority::Normal), 0).unwrap();
        run_one(&mut q, 1, Outcome::Valid);
    }
    drop(q);
    let total = mem.records().len();
    for keep in (0..=total).step_by(7) {
        let copy = MemJournal::new();
        let mut j = copy.clone();
        gv_proof_queue::Journal::append(&mut j, &mem.records()[..keep]).unwrap();
        let q = open(&copy, &cfg);
        let s = q.stats();
        assert!(s.retained <= 50);
        assert!(s.live <= s.retained);
    }
}

#[test]
fn priorities_first_then_matches_take_turns() {
    let mut q = open(&MemJournal::new(), &Config::default());
    for m in 1..=3u8 {
        for n in 0..4 {
            q.submit(spec(m, n, Priority::Normal), 0).unwrap();
        }
    }
    let urgent = q.submit(spec(9, 99, Priority::High), 0).unwrap().id();
    assert_eq!(run_one(&mut q, 1, Outcome::Valid), urgent);
    let order: Vec<u8> = (0..6)
        .map(|_| {
            let l = q.lease(1, ALL).unwrap().unwrap();
            q.complete(&l.id, Outcome::Valid, 1).unwrap();
            l.spec.match_id[0]
        })
        .collect();
    assert_eq!(order, [1, 2, 3, 1, 2, 3]);
}

#[test]
fn one_flooded_match_does_not_starve_another() {
    let mut q = open(&MemJournal::new(), &Config::default());
    for n in 0..1000 {
        q.submit(spec(1, n, Priority::Normal), 0).unwrap();
    }
    let other = q.submit(spec(2, 0, Priority::Normal), 0).unwrap().id();
    let first = q.lease(1, ALL).unwrap().unwrap();
    let second = q.lease(1, ALL).unwrap().unwrap();
    assert_eq!(first.spec.match_id[0], 1);
    assert_eq!(second.id, other);
}

#[test]
fn retries_back_off_exponentially_then_fail() {
    let cfg = Config {
        retry_base: 100,
        retry_cap: 10_000,
        max_attempts: 4,
        ..Config::default()
    };
    let mut q = open(&MemJournal::new(), &cfg);
    let id = q.submit(spec(1, 1, Priority::Normal), 0).unwrap().id();
    let mut now = 0;
    for delay in [100, 200, 400] {
        let l = q.lease(now, ALL).unwrap().unwrap();
        q.complete(&l.id, Outcome::Retry("busy".into()), now)
            .unwrap();
        assert_eq!(q.get(&id).unwrap().not_before, now + delay);
        assert!(q.lease(now + delay - 1, ALL).unwrap().is_none());
        now += delay;
    }
    let l = q.lease(now, ALL).unwrap().unwrap();
    assert_eq!(l.attempt, 4);
    q.complete(&l.id, Outcome::Retry("busy".into()), now)
        .unwrap();
    assert_eq!(state(&q, &id), JobState::Failed);
    assert_eq!(q.metrics().retries, 3);
}

#[test]
fn a_deadline_expires_a_job_and_never_certifies_it() {
    let mut q = open(&MemJournal::new(), &Config::default());
    let mut s = spec(1, 1, Priority::Normal);
    s.deadline = Some(100);
    let id = q.submit(s, 0).unwrap().id();
    q.maintain(99).unwrap();
    assert_eq!(state(&q, &id), JobState::Pending);
    q.maintain(100).unwrap();
    assert_eq!(state(&q, &id), JobState::Expired);
    assert!(q.lease(101, ALL).unwrap().is_none());
}

#[test]
fn an_expired_job_can_be_submitted_again() {
    let mut q = open(&MemJournal::new(), &Config::default());
    let mut s = spec(1, 1, Priority::Normal);
    s.deadline = Some(10);
    let id = q.submit(s.clone(), 0).unwrap().id();
    q.maintain(10).unwrap();
    s.deadline = Some(1000);
    assert!(matches!(
        q.submit(s, 11).unwrap(),
        Submitted::Resubmitted(_)
    ));
    assert_eq!(state(&q, &id), JobState::Pending);
    run_one(&mut q, 12, Outcome::Valid);
    assert_eq!(state(&q, &id), JobState::Verified);
}

#[test]
fn a_lapsed_lease_goes_to_another_worker_and_the_stale_result_is_ignored() {
    let cfg = Config {
        lease_ticks: 50,
        ..Config::default()
    };
    let mut q = open(&MemJournal::new(), &cfg);
    let id = q.submit(spec(1, 1, Priority::Normal), 0).unwrap().id();
    let slow = q.lease(0, ALL).unwrap().unwrap();
    q.maintain(50).unwrap();
    assert_eq!(state(&q, &id), JobState::Pending);
    let fast = q.lease(51, ALL).unwrap().unwrap();
    assert!(q.complete(&fast.id, Outcome::Valid, 52).unwrap());
    assert!(!q
        .complete(&slow.id, Outcome::Invalid("late".into()), 53)
        .unwrap());
    assert_eq!(state(&q, &id), JobState::Verified);
    assert_eq!(q.metrics().lapsed_leases, 1);
}

#[test]
fn dependencies_gate_execution_and_a_failed_dependency_ends_dependents_unverified() {
    let mut q = open(&MemJournal::new(), &Config::default());
    let first = q.submit(spec(1, 1, Priority::Normal), 0).unwrap().id();
    let mut later = spec(1, 2, Priority::Normal);
    later.deps = vec![first];
    let second = q.submit(later, 0).unwrap().id();
    let l = q.lease(1, ALL).unwrap().unwrap();
    assert_eq!(l.id, first);
    assert!(q.lease(1, ALL).unwrap().is_none(), "dependent must wait");
    q.complete(&first, Outcome::Invalid("bad".into()), 2)
        .unwrap();
    q.maintain(3).unwrap();
    assert_eq!(state(&q, &second), JobState::Uncertified);
}

#[test]
fn an_unknown_dependency_is_refused() {
    let mut q = open(&MemJournal::new(), &Config::default());
    let mut s = spec(1, 1, Priority::Normal);
    s.deps = vec![[7; 32]];
    assert!(matches!(
        q.submit(s, 0),
        Err(SubmitError::UnknownDependency(_))
    ));
}

#[test]
fn overload_sheds_low_priority_first_and_keeps_room_for_high() {
    let cfg = Config {
        max_live: 100,
        high_reserve: 10,
        max_live_per_match: 1000,
        ..Config::default()
    };
    let mut q = open(&MemJournal::new(), &cfg);
    let mut n = 0;
    while q.submit(spec(1, n, Priority::Low), 0).is_ok() {
        n += 1;
    }
    assert_eq!(n, 80);
    assert!(q.submit(spec(1, 1000, Priority::Low), 0).is_err());
    for k in 0..10 {
        q.submit(spec(1, 2000 + k, Priority::Normal), 0).unwrap();
    }
    assert!(matches!(
        q.submit(spec(1, 2999, Priority::Normal), 0),
        Err(SubmitError::Full)
    ));
    for k in 0..10 {
        q.submit(spec(1, 3000 + k, Priority::High), 0).unwrap();
    }
    assert!(matches!(
        q.submit(spec(1, 3999, Priority::High), 0),
        Err(SubmitError::Full)
    ));
    assert!(q.metrics().rejected_full >= 3);
}

#[test]
fn a_single_match_cannot_take_the_whole_queue() {
    let cfg = Config {
        max_live_per_match: 5,
        ..Config::default()
    };
    let mut q = open(&MemJournal::new(), &cfg);
    for n in 0..5 {
        q.submit(spec(1, n, Priority::Normal), 0).unwrap();
    }
    assert!(matches!(
        q.submit(spec(1, 5, Priority::High), 0),
        Err(SubmitError::MatchFull)
    ));
    q.submit(spec(2, 0, Priority::Normal), 0).unwrap();
}

#[test]
fn oversized_payloads_are_refused() {
    let cfg = Config {
        max_payload: 8,
        ..Config::default()
    };
    let mut q = open(&MemJournal::new(), &cfg);
    let mut s = spec(1, 1, Priority::Normal);
    s.payload = vec![0; 9];
    assert!(matches!(q.submit(s, 0), Err(SubmitError::TooLarge)));
}

#[test]
fn a_full_disk_refuses_the_write_and_changes_nothing() {
    let mem = MemJournal::new();
    let mut q = open(&mem, &Config::default());
    let kept = q.submit(spec(1, 1, Priority::Normal), 0).unwrap().id();
    mem.set_capacity(Some(mem.records().len() as u64 * 12 + 1));
    let before = q.stats();
    let refused = q.submit(spec(1, 2, Priority::Normal), 0);
    assert!(matches!(refused, Err(SubmitError::Storage(_))));
    assert_eq!(q.stats().retained, before.retained);
    assert!(q.lease(1, ALL).is_err(), "even a lease must be journaled");
    assert_eq!(state(&q, &kept), JobState::Pending);
    mem.set_capacity(None);
    q.submit(spec(1, 2, Priority::Normal), 0).unwrap();
    assert!(q.metrics().storage_errors >= 2);
    drop(q);
    assert_eq!(open(&mem, &Config::default()).stats().retained, 2);
}

#[test]
fn finished_jobs_are_collected_but_proven_violations_are_kept_until_forgotten() {
    let cfg = Config {
        retention: 100,
        ..Config::default()
    };
    let mut q = open(&MemJournal::new(), &cfg);
    let ok = q.submit(spec(1, 1, Priority::Normal), 0).unwrap().id();
    let bad = q.submit(spec(1, 2, Priority::Normal), 0).unwrap().id();
    let l = q.lease(0, ALL).unwrap().unwrap();
    q.complete(&l.id, Outcome::Valid, 0).unwrap();
    let l = q.lease(0, ALL).unwrap().unwrap();
    q.complete(
        &l.id,
        Outcome::Violation {
            accused: [5; 32],
            evidence: vec![1, 2, 3],
        },
        0,
    )
    .unwrap();
    q.maintain(1000).unwrap();
    assert!(q.get(&ok).is_none());
    let kept = q.get(&bad).unwrap();
    assert_eq!(kept.state, JobState::ViolationProven);
    assert_eq!(kept.accused, Some([5; 32]));
    assert_eq!(kept.evidence, [1, 2, 3]);
    assert!(q.forget(&bad).unwrap());
    assert!(q.get(&bad).is_none());
}

#[test]
fn compaction_keeps_state_and_notifications() {
    let mem = MemJournal::new();
    let cfg = Config {
        compact_min_bytes: 1,
        retention: 10,
        ..Config::default()
    };
    let mut q = open(&mem, &cfg);
    for n in 0..300 {
        q.submit(spec(1, n, Priority::Normal), 0).unwrap();
        run_one(&mut q, 1, Outcome::Valid);
        q.maintain(1000 * u64::from(n)).unwrap();
    }
    let keep = q.submit(spec(2, 0, Priority::Normal), 0).unwrap().id();
    q.maintain(1_000_000).unwrap();
    assert!(q.metrics().compactions > 0);
    let events_before = q.events_after(0, 100_000).events;
    let (live, retained) = (q.stats().live, q.stats().retained);
    drop(q);
    let q = open(&mem, &cfg);
    assert_eq!(state(&q, &keep), JobState::Pending);
    assert_eq!((q.stats().live, q.stats().retained), (live, retained));
    assert_eq!(q.events_after(0, 100_000).events, events_before);
}

#[test]
fn a_subscriber_that_fell_behind_is_told_it_missed_notifications() {
    let cfg = Config {
        max_events: 10,
        ..Config::default()
    };
    let mut q = open(&MemJournal::new(), &cfg);
    for n in 0..20 {
        q.submit(spec(1, n, Priority::Normal), 0).unwrap();
    }
    assert!(q.events_after(0, 100).gap);
    let cursor = q.last_event() - 3;
    let page = q.events_after(cursor, 100);
    assert!(!page.gap);
    assert_eq!(page.events.len(), 3);
}

#[test]
fn cancelling_a_match_ends_its_jobs_without_a_verdict() {
    let mut q = open(&MemJournal::new(), &Config::default());
    let a = q.submit(spec(1, 1, Priority::Normal), 0).unwrap().id();
    let b = q.submit(spec(2, 1, Priority::Normal), 0).unwrap().id();
    assert_eq!(q.cancel_match(&[1; 32], 5).unwrap(), 1);
    assert_eq!(state(&q, &a), JobState::Uncertified);
    assert_eq!(state(&q, &b), JobState::Pending);
}

#[test]
fn only_the_requested_families_are_leased() {
    let mut q = open(&MemJournal::new(), &Config::default());
    q.submit(spec(1, 1, Priority::Normal), 0).unwrap();
    assert!(q.lease(0, &[Family::COMMITMENT]).unwrap().is_none());
    assert!(q.lease(0, ALL).unwrap().is_some());
}

#[test]
fn a_file_journal_survives_restart_torn_tails_and_bit_rot() {
    let dir = std::env::temp_dir().join(format!("gvq-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("queue.journal");
    let _ = std::fs::remove_file(&path);
    let cfg = Config::default();
    let ids: Vec<JobId> = {
        let mut q = Queue::open(FileJournal::open(&path).unwrap(), cfg.clone(), 0).unwrap();
        let ids = (0..20)
            .map(|n| q.submit(spec(1, n, Priority::Normal), 0).unwrap().id())
            .collect();
        run_one(&mut q, 1, Outcome::Valid);
        ids
    };
    let q = Queue::open(FileJournal::open(&path).unwrap(), cfg.clone(), 0).unwrap();
    assert_eq!(q.stats().retained, 20);
    assert_eq!(q.metrics().truncated_bytes, 0);
    drop(q);

    let len = std::fs::metadata(&path).unwrap().len();
    let mut data = std::fs::read(&path).unwrap();
    data.truncate(data.len() - 5); // torn final record
    std::fs::write(&path, &data).unwrap();
    let q = Queue::open(FileJournal::open(&path).unwrap(), cfg.clone(), 0).unwrap();
    assert!(q.metrics().truncated_bytes > 0);
    assert!(q.metrics().truncated_bytes < len);
    assert!(ids.iter().filter(|i| q.get(i).is_some()).count() >= 19);
    drop(q);

    let mut data = std::fs::read(&path).unwrap();
    let mid = data.len() / 2;
    data[mid] ^= 0xff; // bit rot in the middle
    std::fs::write(&path, &data).unwrap();
    let q = Queue::open(FileJournal::open(&path).unwrap(), cfg, 0).unwrap();
    assert!(
        q.metrics().truncated_bytes > 0,
        "corruption must be reported"
    );
    assert!(q.stats().retained < 20);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn thousands_of_jobs_with_restarts_keep_every_job_accounted_for() {
    let mem = MemJournal::new();
    let cfg = Config {
        lease_ticks: 10,
        compact_min_bytes: 64 << 10,
        ..Config::default()
    };
    let mut q = open(&mem, &cfg);
    let mut ids = Vec::new();
    for n in 0..5000u32 {
        ids.push(
            q.submit(spec((n % 11) as u8, n, Priority::Normal), 0)
                .unwrap()
                .id(),
        );
        if n % 997 == 0 {
            drop(q);
            q = open(&mem, &cfg);
        }
        if n % 3 == 0 {
            if let Some(l) = q.lease(u64::from(n), ALL).unwrap() {
                let out = if n % 5 == 0 {
                    Outcome::Retry("x".into())
                } else {
                    Outcome::Valid
                };
                q.complete(&l.id, out, u64::from(n)).unwrap();
            }
        }
    }
    let mut now = 100_000;
    while let Some(l) = q.lease(now, ALL).unwrap() {
        q.complete(&l.id, Outcome::Valid, now).unwrap();
        now += 1;
    }
    q.maintain(now + 10_000_000).unwrap();
    for id in &ids {
        let j = q.get(id);
        assert!(j.is_none_or(|j| j.state == JobState::Verified), "{j:?}");
    }
    assert_eq!(q.stats().live, 0);
}
