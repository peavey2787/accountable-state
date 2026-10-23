//! The queue with verifiers and a clock: submit, query and subscribe from any thread, and run
//! verification either by calling [`Service::step`] (a Web Worker, a game's idle time) or on
//! background threads ([`WorkerPool`]). Verification runs outside the queue lock, so submitting
//! and querying never wait on a proof.
use crate::job::{Job, JobId, JobSpec};
use crate::metrics::Metrics;
use crate::queue::{Leased, Page, Queue, Stats, SubmitError, Submitted};
use crate::result::{match_status, MatchStatus};
use crate::verify::Registry;
use crate::{Family, Outcome};
use gv_core::MatchId;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

/// Wall-clock milliseconds since the Unix epoch, so deadlines survive restarts.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

/// A clock the host sets (tests, and browsers where the page supplies the time).
#[derive(Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn new(start: u64) -> Self {
        Self(AtomicU64::new(start))
    }
    pub fn set(&self, t: u64) {
        self.0.store(t, Ordering::SeqCst);
    }
    pub fn advance(&self, by: u64) {
        self.0.fetch_add(by, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    /// Jobs verified per `step` (and per lock round-trip).
    pub batch: usize,
    /// Housekeeping (expiry, collection, compaction) runs at most this often.
    pub maintain_every: u64,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            batch: 16,
            maintain_every: 1_000,
        }
    }
}

pub struct Service {
    queue: Mutex<Queue>,
    changed: Condvar,
    registry: Registry,
    clock: Box<dyn Clock>,
    cfg: ServiceConfig,
    last_maintain: AtomicU64,
}

impl Service {
    pub fn new(
        queue: Queue,
        registry: Registry,
        clock: Box<dyn Clock>,
        cfg: ServiceConfig,
    ) -> Self {
        Self {
            queue: Mutex::new(queue),
            changed: Condvar::new(),
            registry,
            clock,
            cfg,
            last_maintain: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn now(&self) -> u64 {
        self.clock.now()
    }

    /// Queue evidence for verification and return immediately. An error means it was not
    /// accepted (full, too large, storage): the caller still holds the evidence.
    pub fn submit(&self, spec: JobSpec) -> Result<Submitted, SubmitError> {
        let r = self.lock().submit(spec, self.clock.now());
        self.changed.notify_all();
        r
    }

    pub fn job(&self, id: &JobId) -> Option<Job> {
        self.lock().get(id).cloned()
    }

    /// The aggregate result of a match under the policy's required evidence.
    pub fn match_status(&self, m: &MatchId, required: &[Family]) -> MatchStatus {
        match_status(self.lock().jobs_of_match(m), required)
    }

    pub fn cancel_match(&self, m: &MatchId) -> io::Result<usize> {
        let n = self.lock().cancel_match(m, self.clock.now());
        self.changed.notify_all();
        n
    }

    /// The application has acted on a finished job; drop it.
    pub fn forget(&self, id: &JobId) -> io::Result<bool> {
        self.lock().forget(id)
    }

    pub fn metrics(&self) -> Metrics {
        self.lock().metrics().clone()
    }

    pub fn stats(&self) -> Stats {
        self.lock().stats()
    }

    /// Notifications after `cursor` (0 for all), without waiting.
    pub fn events_after(&self, cursor: u64, limit: usize) -> Page {
        self.lock().events_after(cursor, limit)
    }

    /// Notifications after `cursor`, waiting up to `timeout` for one to arrive.
    pub fn wait_events(&self, cursor: u64, limit: usize, timeout: Duration) -> Page {
        let guard = self.lock();
        let (guard, _) = self
            .changed
            .wait_timeout_while(guard, timeout, |q| q.last_event() <= cursor)
            .unwrap_or_else(|p| p.into_inner());
        guard.events_after(cursor, limit)
    }

    /// Verify one batch of ready jobs. Returns how many were processed (0: nothing was ready).
    pub fn step(&self) -> io::Result<usize> {
        let leased = self.lease_batch()?;
        if leased.is_empty() {
            return Ok(0);
        }
        let outcomes = self.verify(&leased);
        let mut q = self.lock();
        let now = self.clock.now();
        let mut result = Ok(leased.len());
        for (job, outcome) in leased.iter().zip(outcomes) {
            if let Err(e) = q.complete(&job.id, outcome, now) {
                result = Err(e); // the lease lapses and the job runs again
            }
        }
        drop(q);
        self.changed.notify_all();
        result
    }

    fn lease_batch(&self) -> io::Result<Vec<Leased>> {
        let now = self.clock.now();
        let mut q = self.lock();
        if now >= self.last_maintain.load(Ordering::Relaxed) + self.cfg.maintain_every {
            self.last_maintain.store(now, Ordering::Relaxed);
            q.maintain(now)?;
        }
        let Some(first) = q.lease(now, &self.registry.families())? else {
            return Ok(Vec::new());
        };
        let family = first.spec.family;
        let mut batch = vec![first];
        while batch.len() < self.cfg.batch {
            match q.lease(now, &[family])? {
                Some(next) => batch.push(next),
                None => break,
            }
        }
        Ok(batch)
    }

    fn verify(&self, leased: &[Leased]) -> Vec<Outcome> {
        let specs: Vec<&JobSpec> = leased.iter().map(|l| &l.spec).collect();
        self.registry.run(specs[0].family, &specs)
    }

    /// Block until something may be ready (a submission, or a timer), at most `timeout`.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn idle(&self, timeout: Duration) {
        let guard = self.lock();
        let _ = self.changed.wait_timeout(guard, timeout);
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use pool::WorkerPool;

#[cfg(not(target_arch = "wasm32"))]
mod pool {
    use super::Service;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;
    use std::time::Duration;

    const IDLE_WAIT: Duration = Duration::from_millis(20);

    /// Background verification threads. Dropping the pool stops and joins them.
    pub struct WorkerPool {
        stop: Arc<AtomicBool>,
        threads: Vec<JoinHandle<()>>,
    }

    impl WorkerPool {
        pub fn start(service: Arc<Service>, threads: usize) -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let threads = (0..threads.max(1))
                .map(|_| {
                    let (service, stop) = (Arc::clone(&service), Arc::clone(&stop));
                    std::thread::spawn(move || work(&service, &stop))
                })
                .collect();
            Self { stop, threads }
        }
    }

    impl Drop for WorkerPool {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            for t in self.threads.drain(..) {
                let _ = t.join();
            }
        }
    }

    fn work(service: &Service, stop: &AtomicBool) {
        while !stop.load(Ordering::SeqCst) {
            match service.step() {
                Ok(n) if n > 0 => {}
                _ => service.idle(IDLE_WAIT),
            }
        }
    }
}
