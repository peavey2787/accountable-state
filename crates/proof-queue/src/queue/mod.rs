//! The durable job queue: a state machine whose every transition is journaled before it takes
//! effect, so a crash at any point replays to a consistent state. Single-threaded and clock-free
//! (the caller passes `now`); [`crate::service::Service`] adds threads and verifiers.
mod apply;
mod batch;
mod maintain;
mod ops;

use crate::config::Config;
use crate::job::{Event, Job, JobId, JobSpec, JobState, Priority};
use crate::journal::{Journal, Opened};
use crate::metrics::Metrics;
use crate::record::Record;
use batch::Batch;
use gv_core::MatchId;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::io;

type PendKey = (Priority, MatchId, u64, JobId);

#[derive(Debug)]
pub enum SubmitError {
    TooLarge,
    UnknownDependency(JobId),
    /// Global or priority capacity reached: the caller keeps the evidence and retries later.
    Full,
    /// This match already has its share of unfinished jobs.
    MatchFull,
    Storage(io::Error),
}

impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("payload too large"),
            Self::UnknownDependency(_) => f.write_str("dependency is not in the queue"),
            Self::Full => f.write_str("queue is full"),
            Self::MatchFull => f.write_str("match has too many unfinished jobs"),
            Self::Storage(e) => write!(f, "journal: {e}"),
        }
    }
}

impl std::error::Error for SubmitError {}

#[derive(Debug)]
pub enum OpenError {
    /// A record passed its checksum but is not a valid queue record (wrong version or bug).
    Malformed {
        index: usize,
    },
    Storage(io::Error),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { index } => write!(f, "journal record {index} is malformed"),
            Self::Storage(e) => write!(f, "journal: {e}"),
        }
    }
}

impl std::error::Error for OpenError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Submitted {
    New(JobId),
    /// The same evidence is already queued or decided; nothing changed.
    Duplicate(JobId),
    /// A previous attempt ended without a verdict (expired, uncertified, failed): queued afresh.
    Resubmitted(JobId),
}

impl Submitted {
    pub fn id(self) -> JobId {
        match self {
            Self::New(id) | Self::Duplicate(id) | Self::Resubmitted(id) => id,
        }
    }
}

/// A job handed to a worker. Until it completes or the lease lapses, nobody else gets it.
#[derive(Clone, Debug)]
pub struct Leased {
    pub id: JobId,
    pub spec: JobSpec,
    pub attempt: u32,
}

/// Notifications after a cursor. `gap` says some were already discarded: reconcile from the
/// job states instead of assuming nothing was missed.
#[derive(Clone, Debug, Default)]
pub struct Page {
    pub events: Vec<Event>,
    pub gap: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub live: usize,
    pub retained: usize,
    pub pending: usize,
    pub journal_bytes: u64,
}

pub struct Queue {
    cfg: Config,
    journal: Box<dyn Journal>,
    jobs: BTreeMap<JobId, Job>,
    pending: BTreeSet<PendKey>,
    rotation: BTreeMap<Priority, MatchId>,
    events: VecDeque<Event>,
    next_job_seq: u64,
    next_event: u64,
    live: usize,
    live_per_match: BTreeMap<MatchId, usize>,
    last_compact_bytes: u64,
    metrics: Metrics,
}

impl Queue {
    /// Rebuild the queue from what the journal held. Jobs that were mid-verification when the
    /// process died go back to pending: execution is at-least-once, so verifiers are pure.
    pub fn open<J: Journal + 'static>(
        opened: Opened<J>,
        cfg: Config,
        now: u64,
    ) -> Result<Self, OpenError> {
        let mut q = Self {
            cfg,
            journal: Box::new(opened.journal),
            jobs: BTreeMap::new(),
            pending: BTreeSet::new(),
            rotation: BTreeMap::new(),
            events: VecDeque::new(),
            next_job_seq: 0,
            next_event: 1,
            live: 0,
            live_per_match: BTreeMap::new(),
            last_compact_bytes: 0,
            metrics: Metrics::default(),
        };
        q.metrics.truncated_bytes = opened.truncated;
        for (index, bytes) in opened.records.iter().enumerate() {
            let rec = Record::decode(bytes).map_err(|_| OpenError::Malformed { index })?;
            q.apply(rec);
        }
        q.last_compact_bytes = q.journal.size();
        q.recover_leases(now).map_err(OpenError::Storage)?;
        Ok(q)
    }

    pub fn get(&self, id: &JobId) -> Option<&Job> {
        self.jobs.get(id)
    }

    pub fn jobs_of_match<'a>(&'a self, m: &'a MatchId) -> impl Iterator<Item = &'a Job> + 'a {
        self.jobs.values().filter(move |j| &j.spec.match_id == m)
    }

    pub fn stats(&self) -> Stats {
        Stats {
            live: self.live,
            retained: self.jobs.len(),
            pending: self.pending.len(),
            journal_bytes: self.journal.size(),
        }
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Notifications with `seq > cursor`, oldest first, at most `limit`.
    pub fn events_after(&self, cursor: u64, limit: usize) -> Page {
        let gap = self
            .events
            .front()
            .is_some_and(|first| first.seq > cursor.saturating_add(1));
        let events = self
            .events
            .iter()
            .filter(|e| e.seq > cursor)
            .take(limit)
            .cloned()
            .collect();
        Page { events, gap }
    }

    /// The sequence number of the newest notification (0 before any).
    pub fn last_event(&self) -> u64 {
        self.next_event - 1
    }

    fn commit(&mut self, batch: Batch) -> io::Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let encoded: Vec<Vec<u8>> = batch.records().iter().map(Record::encode).collect();
        if let Err(e) = self.journal.append(&encoded) {
            self.metrics.storage_errors += 1;
            return Err(e);
        }
        let finished = batch.finished();
        for rec in batch.into_records() {
            self.apply(rec);
        }
        for id in finished {
            if let Some(j) = self.jobs.get(&id) {
                let took = j.finished_at.saturating_sub(j.submitted_at);
                self.metrics.record_finish(j.state, took);
            }
        }
        Ok(())
    }

    fn batch(&self) -> Batch {
        Batch::new(self.next_event)
    }

    fn is_good(&self, id: &JobId) -> bool {
        self.jobs
            .get(id)
            .is_some_and(|j| j.state.satisfies_dependency())
    }

    fn state_of(&self, id: &JobId) -> Option<JobState> {
        self.jobs.get(id).map(|j| j.state)
    }
}
