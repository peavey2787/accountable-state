use gv_codec::{EventBatch, EventBody, HeldChange, SignedEventBatch};
use gv_proof_queue::verify::{pack, Registry, SignedInputs, Verifier};
use gv_proof_queue::{
    decide, match_status, Action, Config, Family, FileJournal, JobSpec, JobState, Ledger,
    MatchStatus, MemJournal, Outcome, Priority, Queue, Service, ServiceConfig, Settlement,
    SubmitError, SystemClock, WorkerPool,
};
use gv_sig::SigningKey;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn batch(k: &SigningKey, m: [u8; 32], start: u64, init: u16) -> Vec<u8> {
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
    .encode()
    .unwrap()
}

fn inputs_job(m: u8, n: u64, bad: bool) -> JobSpec {
    let k = SigningKey::from_seed([m; 32]);
    let mut b = batch(&k, [m; 32], n * 20, (n % 1000) as u16 + 10);
    if bad {
        let last = b.len() - 1;
        b[last] ^= 1;
    }
    JobSpec {
        family: Family::SIGNED_INPUTS,
        match_id: [m; 32],
        payload: pack(&[b]),
        priority: Priority::Normal,
        deadline: None,
        deps: vec![],
    }
}

fn service(queue: Queue, registry: Registry) -> Arc<Service> {
    Arc::new(Service::new(
        queue,
        registry,
        Box::new(SystemClock),
        ServiceConfig::default(),
    ))
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "timed out: {what}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn mem_queue(mem: &MemJournal, cfg: Config) -> Queue {
    Queue::open(mem.open(), cfg, 0).unwrap()
}

#[test]
fn workers_verify_submitted_evidence_and_honest_and_forged_are_told_apart() {
    let svc = service(
        mem_queue(&MemJournal::new(), Config::default()),
        Registry::new().with(SignedInputs),
    );
    let pool = WorkerPool::start(Arc::clone(&svc), 4);
    let ids: Vec<_> = (0..120)
        .map(|n| {
            svc.submit(inputs_job(1 + (n % 5) as u8, n, n % 10 == 0))
                .unwrap()
                .id()
        })
        .collect();
    wait_until("all decided", || {
        ids.iter()
            .all(|i| svc.job(i).is_some_and(|j| j.state.is_terminal()))
    });
    pool.stop();
    for (n, id) in ids.iter().enumerate() {
        let want = if n % 10 == 0 {
            JobState::Failed
        } else {
            JobState::Verified
        };
        assert_eq!(svc.job(id).unwrap().state, want, "job {n}");
    }
    let m = svc.metrics();
    assert_eq!(m.finished(JobState::Verified), 108);
    assert_eq!(m.finished(JobState::Failed), 12);
    assert_eq!(svc.events_after(0, 10_000).events.len(), 120 * 3);
}

#[test]
fn a_subscriber_waits_for_notifications_instead_of_polling() {
    let svc = service(
        mem_queue(&MemJournal::new(), Config::default()),
        Registry::new().with(SignedInputs),
    );
    let waiter = {
        let svc = Arc::clone(&svc);
        std::thread::spawn(move || svc.wait_events(0, 10, Duration::from_secs(30)))
    };
    std::thread::sleep(Duration::from_millis(50));
    svc.submit(inputs_job(1, 0, false)).unwrap();
    let page = waiter.join().unwrap();
    assert_eq!(page.events[0].state, JobState::Pending);
}

#[test]
fn a_job_with_no_verifier_stays_pending_instead_of_being_guessed_at() {
    let svc = service(
        mem_queue(&MemJournal::new(), Config::default()),
        Registry::new().with(SignedInputs),
    );
    let mut s = inputs_job(1, 0, false);
    s.family = Family(Family::EXTENSION_BASE + 1);
    let id = svc.submit(s).unwrap().id();
    assert_eq!(svc.step().unwrap(), 0);
    assert_eq!(svc.job(&id).unwrap().state, JobState::Pending);
}

struct Panics(AtomicUsize);

impl Verifier for Panics {
    fn family(&self) -> Family {
        Family::SIGNED_INPUTS
    }
    fn verify(&self, _: &JobSpec) -> Outcome {
        if self.0.fetch_add(1, Ordering::SeqCst) < 2 {
            panic!("verifier bug");
        }
        Outcome::Valid
    }
}

#[test]
fn a_panicking_verifier_is_retried_and_never_becomes_a_verdict() {
    let cfg = Config {
        retry_base: 0,
        retry_cap: 0,
        ..Config::default()
    };
    let svc = service(
        mem_queue(&MemJournal::new(), cfg),
        Registry::new().with(Panics(AtomicUsize::new(0))),
    );
    let id = svc.submit(inputs_job(1, 0, false)).unwrap().id();
    for _ in 0..3 {
        svc.step().unwrap();
        assert_ne!(svc.job(&id).unwrap().state, JobState::ViolationProven);
    }
    let j = svc.job(&id).unwrap();
    assert_eq!(j.state, JobState::Verified);
    assert_eq!(j.attempts, 3);
}

#[test]
fn a_process_that_dies_mid_verification_loses_nothing() {
    let dir = std::env::temp_dir().join(format!("gvq-svc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("q.journal");
    let _ = std::fs::remove_file(&path);
    let open = || Queue::open(FileJournal::open(&path).unwrap(), Config::default(), 0).unwrap();
    let ids: Vec<_> = {
        let svc = service(open(), Registry::new().with(SignedInputs));
        let ids: Vec<_> = (0..60)
            .map(|n| svc.submit(inputs_job(1, n, false)).unwrap().id())
            .collect();
        svc.step().unwrap(); // some done, then the process "dies"
        ids
    };
    let svc = service(open(), Registry::new().with(SignedInputs));
    let pool = WorkerPool::start(Arc::clone(&svc), 2);
    wait_until("recovered", || {
        ids.iter()
            .all(|i| svc.job(i).is_some_and(|j| j.state == JobState::Verified))
    });
    pool.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn overload_refuses_new_evidence_loudly_and_what_was_accepted_still_completes() {
    let cfg = Config {
        max_live: 50,
        high_reserve: 0,
        ..Config::default()
    };
    let svc = service(
        mem_queue(&MemJournal::new(), cfg),
        Registry::new().with(SignedInputs),
    );
    let mut accepted = Vec::new();
    let mut refused = 0;
    for n in 0..200 {
        match svc.submit(inputs_job(1 + (n % 4) as u8, n, false)) {
            Ok(s) => accepted.push(s.id()),
            Err(SubmitError::Full | SubmitError::MatchFull) => refused += 1,
            Err(e) => panic!("{e}"),
        }
    }
    assert_eq!(accepted.len(), 50);
    assert_eq!(refused, 150);
    while svc.step().unwrap() > 0 {}
    assert!(accepted
        .iter()
        .all(|i| svc.job(i).unwrap().state == JobState::Verified));
    svc.submit(inputs_job(1, 999, false)).unwrap();
}

#[test]
fn match_status_follows_the_evidence_and_a_violation_outranks_pending_work() {
    let svc = service(
        mem_queue(&MemJournal::new(), Config::default()),
        Registry::new().with(SignedInputs),
    );
    let required = [Family::SIGNED_INPUTS];
    let m = [1u8; 32];
    assert_eq!(svc.match_status(&m, &required), MatchStatus::Unknown);
    svc.submit(inputs_job(1, 0, false)).unwrap();
    assert_eq!(svc.match_status(&m, &required), MatchStatus::Pending);
    svc.step().unwrap();
    assert_eq!(svc.match_status(&m, &required), MatchStatus::Certified);
    assert_eq!(
        svc.match_status(&m, &[Family::SIGNED_INPUTS, Family::TRANSITION]),
        MatchStatus::Verified
    );
    svc.submit(inputs_job(1, 1, true)).unwrap();
    svc.step().unwrap();
    assert_eq!(svc.match_status(&m, &required), MatchStatus::Failed);
}

fn job_in(state: JobState, accused: Option<[u8; 32]>) -> gv_proof_queue::Job {
    let mut j = gv_proof_queue::Job::new(inputs_job(1, 0, false), 0, 0);
    j.state = state;
    j.accused = accused;
    j
}

#[test]
fn a_violation_outranks_everything_else_in_the_match() {
    let jobs = [
        job_in(JobState::Pending, None),
        job_in(JobState::ViolationProven, Some([4; 32])),
        job_in(JobState::Expired, None),
    ];
    assert_eq!(
        match_status(jobs.iter(), &[]),
        MatchStatus::ViolationProven {
            accused: vec![[4; 32]]
        }
    );
}

#[test]
fn settlement_never_forfeits_for_missing_proof_and_corrects_a_late_violation() {
    let violation = MatchStatus::ViolationProven {
        accused: vec![[4; 32]],
    };
    for missing in [
        MatchStatus::Uncertified,
        MatchStatus::Expired,
        MatchStatus::Failed,
    ] {
        let (s, a) = decide(Settlement::Provisional, &missing);
        assert_eq!((s, a), (Settlement::Held, Action::HoldRewards));
        assert_eq!(decide(s, &missing).1, Action::Nothing);
    }
    // Held, then the evidence arrives: released.
    assert_eq!(
        decide(Settlement::Held, &MatchStatus::Certified),
        (Settlement::Final, Action::ReleaseRewards)
    );
    // A violation before release forfeits; after release it is a correction.
    assert_eq!(
        decide(Settlement::Provisional, &violation).0,
        Settlement::Forfeited
    );
    assert_eq!(
        decide(Settlement::Held, &violation).0,
        Settlement::Forfeited
    );
    let (s, a) = decide(Settlement::Final, &violation);
    assert_eq!(s, Settlement::Corrected);
    assert_eq!(
        a,
        Action::Correct {
            accused: vec![[4; 32]]
        }
    );
    // Final results are not undone by silence, and corrections happen once.
    assert_eq!(
        decide(Settlement::Final, &MatchStatus::Expired).1,
        Action::Nothing
    );
    assert_eq!(decide(Settlement::Corrected, &violation).1, Action::Nothing);
}

#[test]
fn the_ledger_survives_a_restart_so_a_late_violation_is_still_late() {
    let mut l = Ledger::default();
    let m = [3u8; 32];
    assert_eq!(l.update(m, &MatchStatus::Certified), Action::ReleaseRewards);
    let restored = Ledger::decode(&l.encode()).unwrap();
    let mut l = restored;
    let late = MatchStatus::ViolationProven {
        accused: vec![[9; 32]],
    };
    assert!(matches!(l.update(m, &late), Action::Correct { .. }));
    assert_eq!(l.get(&m), Settlement::Corrected);
    assert!(Ledger::decode(&[1, 2, 3]).is_none());
}

/// What gameplay does each frame is `submit`; it must not wait for proof processing.
#[test]
fn gameplay_frames_are_not_delayed_by_a_busy_verification_backlog() {
    fn frame_times(svc: &Service, base: u64) -> Vec<Duration> {
        (0..120)
            .map(|n| {
                let spec = inputs_job(1 + (n % 7) as u8, base + n, false);
                let t = Instant::now();
                svc.submit(spec).unwrap();
                let took = t.elapsed();
                std::thread::sleep(Duration::from_millis(8));
                took
            })
            .collect()
    }
    fn p99(mut v: Vec<Duration>) -> Duration {
        v.sort();
        v[v.len() * 99 / 100]
    }
    let cfg = Config {
        max_live_per_match: 100_000,
        ..Config::default()
    };
    let svc = service(
        mem_queue(&MemJournal::new(), cfg),
        Registry::new().with(SignedInputs),
    );
    // Prepare the evidence up front: signing it is the game's work, not the frame's.
    let idle = p99(frame_times(&svc, 0));
    for n in 0..400 {
        svc.submit(inputs_job(8, 10_000 + n, false)).unwrap();
    }
    let verified = |s: &Service| s.metrics().finished(JobState::Verified);
    let before = verified(&svc);
    let pool = WorkerPool::start(Arc::clone(&svc), 4);
    let busy = p99(frame_times(&svc, 1000));
    let during = verified(&svc) - before;
    pool.stop();
    assert!(
        during > 0,
        "the workers must have verified jobs while frames ran"
    );
    eprintln!(
        "submit p99: idle {idle:?}, with workers busy {busy:?} ({during} jobs verified meanwhile)"
    );
    assert!(
        busy < Duration::from_millis(100),
        "submit stalled: {busy:?}"
    );
}
