//! Applying a record to the in-memory state. The one place state changes, for live operation and
//! journal replay alike, so a replay reproduces exactly what happened.
use super::{PendKey, Queue};
use crate::job::{Event, Job, JobId, JobState};
use crate::record::Record;

fn key(j: &Job) -> PendKey {
    (j.spec.priority, j.spec.match_id, j.seq, j.id)
}

impl Queue {
    pub(super) fn apply(&mut self, rec: Record) {
        match rec {
            Record::Job(j) => self.insert_job(*j),
            Record::Lease { id, until } => self.on_lease(&id, until),
            Record::Retry {
                id,
                not_before,
                reason,
            } => self.on_retry(&id, not_before, reason),
            Record::Requeue { id } => self.make_pending(&id, None),
            Record::Finish {
                id,
                state,
                at,
                reason,
                accused,
                evidence,
            } => self.on_finish(&id, state, at, reason, accused, evidence),
            Record::Remove { id } => self.on_remove(&id),
            Record::Event(e) => self.on_event(e),
        }
    }

    fn insert_job(&mut self, j: Job) {
        if self.jobs.contains_key(&j.id) {
            return;
        }
        self.next_job_seq = self.next_job_seq.max(j.seq + 1);
        if !j.state.is_terminal() {
            self.live += 1;
            *self.live_per_match.entry(j.spec.match_id).or_default() += 1;
        }
        if j.state == JobState::Pending {
            self.pending.insert(key(&j));
        }
        self.jobs.insert(j.id, j);
    }

    fn on_lease(&mut self, id: &JobId, until: u64) {
        let Some(j) = self.jobs.get_mut(id) else {
            return;
        };
        if j.state != JobState::Pending {
            return;
        }
        self.pending.remove(&key(j));
        j.state = JobState::Processing;
        j.lease_until = until;
        j.attempts += 1;
    }

    fn on_retry(&mut self, id: &JobId, not_before: u64, reason: String) {
        if self.state_of(id) != Some(JobState::Processing) {
            return;
        }
        self.make_pending(id, Some((not_before, reason)));
    }

    /// Back to pending (a lapsed lease, a restart, or a retry with a delay).
    pub(super) fn make_pending(&mut self, id: &JobId, retry: Option<(u64, String)>) {
        let Some(j) = self.jobs.get_mut(id) else {
            return;
        };
        if j.state.is_terminal() {
            return;
        }
        j.state = JobState::Pending;
        j.lease_until = 0;
        if let Some((not_before, reason)) = retry {
            j.not_before = not_before;
            j.reason = reason;
        }
        self.pending.insert(key(j));
    }

    fn on_finish(
        &mut self,
        id: &JobId,
        state: JobState,
        at: u64,
        reason: String,
        accused: Option<[u8; 32]>,
        evidence: Vec<u8>,
    ) {
        let Some(j) = self.jobs.get_mut(id) else {
            return;
        };
        if j.state.is_terminal() || !state.is_terminal() {
            return;
        }
        self.pending.remove(&key(j));
        j.state = state;
        j.finished_at = at;
        j.reason = reason;
        j.accused = accused;
        j.evidence = evidence;
        j.lease_until = 0;
        self.live -= 1;
        let m = j.spec.match_id;
        if let Some(n) = self.live_per_match.get_mut(&m) {
            *n -= 1;
            if *n == 0 {
                self.live_per_match.remove(&m);
            }
        }
    }

    fn on_remove(&mut self, id: &JobId) {
        if self.state_of(id).is_some_and(JobState::is_terminal) {
            self.jobs.remove(id);
        }
    }

    fn on_event(&mut self, e: Event) {
        self.next_event = self.next_event.max(e.seq + 1);
        self.events.push_back(e);
        while self.events.len() > self.cfg.max_events {
            self.events.pop_front();
        }
    }
}
