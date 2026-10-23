//! A group of records committed together, with the notifications they imply. A batch holds at
//! most one transition per job.
use crate::job::{Event, Job, JobId, JobState};
use crate::record::Record;
use std::collections::BTreeSet;

pub(super) struct Batch {
    records: Vec<Record>,
    next_event: u64,
    touched: BTreeSet<JobId>,
    finished: Vec<JobId>,
    pub(super) lapsed: u64,
}

impl Batch {
    pub(super) fn new(next_event: u64) -> Self {
        Self {
            records: Vec::new(),
            next_event,
            touched: BTreeSet::new(),
            finished: Vec::new(),
            lapsed: 0,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub(super) fn records(&self) -> &[Record] {
        &self.records
    }

    pub(super) fn into_records(self) -> Vec<Record> {
        self.records
    }

    pub(super) fn finished(&self) -> Vec<JobId> {
        self.finished.clone()
    }

    pub(super) fn touched(&self, id: &JobId) -> bool {
        self.touched.contains(id)
    }

    /// A transition that does not end the job (lease, retry, requeue).
    pub(super) fn step(&mut self, job: &Job, rec: Record) {
        self.touched.insert(job.id);
        self.records.push(rec);
    }

    pub(super) fn raw(&mut self, rec: Record) {
        self.records.push(rec);
    }

    pub(super) fn event(&mut self, job: &Job, state: JobState, at: u64) {
        self.records.push(Record::Event(Event {
            seq: self.next_event,
            at,
            job: job.id,
            match_id: job.spec.match_id,
            family: job.spec.family,
            state,
        }));
        self.next_event += 1;
    }

    /// End the job in `state`, with its notification.
    pub(super) fn finish(&mut self, job: &Job, verdict: Verdict, at: u64) {
        let state = verdict.state;
        self.step(
            job,
            Record::Finish {
                id: job.id,
                state,
                at,
                reason: verdict.reason,
                accused: verdict.accused,
                evidence: verdict.evidence,
            },
        );
        self.finished.push(job.id);
        self.event(job, state, at);
    }
}

/// How a job ended.
pub(super) struct Verdict {
    pub(super) state: JobState,
    pub(super) reason: String,
    pub(super) accused: Option<[u8; 32]>,
    pub(super) evidence: Vec<u8>,
}

impl Verdict {
    pub(super) fn new(state: JobState, reason: impl Into<String>) -> Self {
        Self {
            state,
            reason: reason.into(),
            accused: None,
            evidence: Vec::new(),
        }
    }
}
