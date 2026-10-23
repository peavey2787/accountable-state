//! The service's own bookkeeping: clocks, batching, housekeeping cadence, subscriber waits and the
//! worker pool's lifecycle.
use gv_proof_queue::verify::{Registry, Verifier};
use gv_proof_queue::{
    Clock, Config, Family, JobSpec, JobState, ManualClock, MemJournal, Outcome, Priority, Queue,
    Service, ServiceConfig, SystemClock, WorkerPool,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const F: Family = Family::EQUIVOCATION;

struct AlwaysValid;

impl Verifier for AlwaysValid {
    fn family(&self) -> Family {
        F
    }
    fn verify(&self, _: &JobSpec) -> Outcome {
        Outcome::Valid
    }
}

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

fn service_with(clock: Box<dyn Clock>, cfg: ServiceConfig) -> Service {
    let queue = Queue::open(MemJournal::new().open(), Config::default(), 0).unwrap();
    Service::new(queue, Registry::new().with(AlwaysValid), clock, cfg)
}

fn manual(start: u64, cfg: ServiceConfig) -> (Arc<ManualClock>, Service) {
    let clock = Arc::new(ManualClock::new(start));
    struct Shared(Arc<ManualClock>);
    impl Clock for Shared {
        fn now(&self) -> u64 {
            self.0.now()
        }
    }
    (
        Arc::clone(&clock),
        service_with(Box::new(Shared(clock)), cfg),
    )
}

#[test]
fn the_system_clock_reads_unix_milliseconds() {
    let now = SystemClock.now();
    assert!(now > 1_600_000_000_000, "{now}");
    assert!(SystemClock.now() >= now);
}

#[test]
fn a_manual_clock_holds_the_time_it_is_given() {
    let c = ManualClock::new(5);
    assert_eq!(c.now(), 5);
    c.set(40);
    assert_eq!(c.now(), 40);
    c.advance(2);
    c.advance(3);
    assert_eq!(c.now(), 45);
}

#[test]
fn the_service_reports_its_clock() {
    let (clock, svc) = manual(7, ServiceConfig::default());
    assert_eq!(svc.now(), 7);
    clock.advance(10);
    assert_eq!(svc.now(), 17);
}

#[test]
fn a_step_verifies_at_most_one_batch() {
    let cfg = ServiceConfig {
        batch: 3,
        ..ServiceConfig::default()
    };
    let (_, svc) = manual(0, cfg);
    for n in 0..5 {
        svc.submit(spec(1, n)).unwrap();
    }
    assert_eq!(svc.step().unwrap(), 3);
    assert_eq!(svc.step().unwrap(), 2);
    assert_eq!(svc.step().unwrap(), 0);
    assert_eq!(svc.metrics().finished(JobState::Verified), 5);
}

#[test]
fn housekeeping_runs_once_its_interval_has_elapsed_and_not_before() {
    let cfg = ServiceConfig {
        maintain_every: 10,
        ..ServiceConfig::default()
    };
    let (clock, svc) = manual(0, cfg);
    let mut early = spec(1, 1);
    early.deadline = Some(5);
    let early = svc.submit(early).unwrap().id();
    clock.set(5);
    svc.step().unwrap();
    assert_eq!(
        svc.job(&early).unwrap().state,
        JobState::Verified,
        "no housekeeping yet, so the job ran before it could expire"
    );
    let mut late = spec(1, 2);
    late.deadline = Some(10);
    let late = svc.submit(late).unwrap().id();
    clock.set(10);
    svc.step().unwrap();
    assert_eq!(
        svc.job(&late).unwrap().state,
        JobState::Expired,
        "housekeeping runs exactly when the interval is up"
    );
}

#[test]
fn cancelling_a_match_and_forgetting_a_job_report_what_they_did() {
    let (_, svc) = manual(0, ServiceConfig::default());
    for n in 0..3 {
        svc.submit(spec(1, n)).unwrap();
    }
    let other = svc.submit(spec(2, 0)).unwrap().id();
    assert_eq!(svc.cancel_match(&[1; 32]).unwrap(), 3);
    assert_eq!(svc.cancel_match(&[1; 32]).unwrap(), 0);
    assert_eq!(svc.stats().live, 1);
    assert!(
        !svc.forget(&other).unwrap(),
        "unfinished work is not forgotten"
    );
    svc.step().unwrap();
    assert!(svc.forget(&other).unwrap());
    assert!(svc.job(&other).is_none());
    assert!(!svc.forget(&other).unwrap());
    let stats = svc.stats();
    assert_eq!((stats.live, stats.retained), (0, 3));
}

#[test]
fn waiting_for_notifications_returns_at_once_when_some_exist_and_times_out_when_none_do() {
    let (_, svc) = manual(0, ServiceConfig::default());
    svc.submit(spec(1, 1)).unwrap();
    let started = Instant::now();
    let page = svc.wait_events(0, 10, Duration::from_secs(10));
    assert_eq!(page.events.len(), 1);
    assert!(started.elapsed() < Duration::from_secs(5));

    let last = page.events[0].seq;
    let started = Instant::now();
    let page = svc.wait_events(last, 10, Duration::from_millis(150));
    assert!(page.events.is_empty());
    assert!(started.elapsed() >= Duration::from_millis(100));
}

struct CountingClock(Arc<AtomicU64>);

impl Clock for CountingClock {
    fn now(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed);
        0
    }
}

#[test]
fn an_idle_pool_sleeps_instead_of_spinning() {
    let reads = Arc::new(AtomicU64::new(0));
    let svc = Arc::new(service_with(
        Box::new(CountingClock(Arc::clone(&reads))),
        ServiceConfig::default(),
    ));
    let pool = WorkerPool::start(Arc::clone(&svc), 1);
    std::thread::sleep(Duration::from_millis(400));
    drop(pool);
    let n = reads.load(Ordering::Relaxed);
    assert!(n < 200, "an idle worker read the clock {n} times in 400 ms");
}

#[test]
fn a_busy_pool_does_not_sleep_between_batches() {
    let cfg = ServiceConfig {
        batch: 1,
        ..ServiceConfig::default()
    };
    let svc = Arc::new(service_with(Box::new(SystemClock), cfg));
    for n in 0..200 {
        svc.submit(spec(1, n)).unwrap();
    }
    let started = Instant::now();
    let pool = WorkerPool::start(Arc::clone(&svc), 1);
    while svc.stats().live > 0 {
        assert!(started.elapsed() < Duration::from_secs(60), "pool stalled");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "200 one-job batches took {:?}: the worker slept between them",
        started.elapsed()
    );
    drop(pool);
}

fn assert_no_work_after(svc: &Arc<Service>, what: &str) {
    svc.submit(spec(9, 9)).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(svc.stats().live, 1, "{what}: a stopped pool kept working");
}

#[test]
fn dropping_a_pool_stops_its_threads() {
    let svc = Arc::new(service_with(
        Box::new(SystemClock),
        ServiceConfig::default(),
    ));
    drop(WorkerPool::start(Arc::clone(&svc), 2));
    assert_no_work_after(&svc, "drop");
}
