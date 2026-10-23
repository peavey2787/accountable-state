//! Operations on the queue: submit, lease, complete, cancel, forget.
use super::batch::{Batch, Verdict};
use super::{Leased, PendKey, Queue, SubmitError, Submitted};
use crate::job::{Family, Job, JobId, JobSpec, JobState, Outcome, Priority};
use crate::record::Record;
use gv_core::MatchId;
use std::io;
use std::ops::Bound::{Excluded, Included};

const PRIORITIES: [Priority; 3] = [Priority::High, Priority::Normal, Priority::Low];

/// A job that ended without a verdict may be submitted again (fresh deadline, fresh attempts).
fn resubmittable(s: JobState) -> bool {
    matches!(
        s,
        JobState::Expired | JobState::Uncertified | JobState::Failed
    )
}

impl Queue {
    pub fn submit(&mut self, spec: JobSpec, now: u64) -> Result<Submitted, SubmitError> {
        let id = spec.id();
        let replace = match self.jobs.get(&id) {
            Some(j) if resubmittable(j.state) => true,
            Some(_) => {
                self.metrics.duplicates += 1;
                return Ok(Submitted::Duplicate(id));
            }
            None => false,
        };
        if let Err(e) = self.admit(&spec) {
            self.count_rejection(&e);
            return Err(e);
        }
        let job = Job::new(spec, now, self.next_job_seq);
        let mut b = self.batch();
        if replace {
            b.raw(Record::Remove { id });
        }
        b.raw(Record::Job(Box::new(job.clone())));
        b.event(&job, JobState::Pending, now);
        self.commit(b).map_err(SubmitError::Storage)?;
        Ok(if replace {
            self.metrics.resubmitted += 1;
            Submitted::Resubmitted(id)
        } else {
            self.metrics.submitted += 1;
            Submitted::New(id)
        })
    }

    fn admit(&self, spec: &JobSpec) -> Result<(), SubmitError> {
        if spec.payload.len() > self.cfg.max_payload {
            return Err(SubmitError::TooLarge);
        }
        if let Some(d) = spec.deps.iter().find(|d| !self.jobs.contains_key(*d)) {
            return Err(SubmitError::UnknownDependency(*d));
        }
        let held_back = match spec.priority {
            Priority::High => 0,
            Priority::Normal => self.cfg.high_reserve,
            Priority::Low => self.cfg.high_reserve.saturating_mul(2),
        };
        let limit = self.cfg.max_live.saturating_sub(held_back);
        if self.live >= limit || self.jobs.len() >= self.cfg.max_retained {
            return Err(SubmitError::Full);
        }
        let in_match = self.live_per_match.get(&spec.match_id).copied();
        if in_match.unwrap_or(0) >= self.cfg.max_live_per_match {
            return Err(SubmitError::MatchFull);
        }
        Ok(())
    }

    fn count_rejection(&mut self, e: &SubmitError) {
        match e {
            SubmitError::Full | SubmitError::MatchFull => self.metrics.rejected_full += 1,
            _ => self.metrics.rejected_invalid += 1,
        }
    }

    /// Hand the next ready job whose family is in `families` to a worker: highest priority first,
    /// matches taking turns within a priority, oldest first within a match.
    pub fn lease(&mut self, now: u64, families: &[Family]) -> io::Result<Option<Leased>> {
        let found = PRIORITIES
            .into_iter()
            .find_map(|p| self.next_ready(p, now, families).map(|id| (p, id)));
        let Some((priority, id)) = found else {
            return Ok(None);
        };
        let Some(job) = self.jobs.get(&id).cloned() else {
            return Ok(None);
        };
        let mut b = self.batch();
        let until = now.saturating_add(self.cfg.lease_ticks);
        b.step(&job, Record::Lease { id, until });
        b.event(&job, JobState::Processing, now);
        self.commit(b)?;
        self.rotation.insert(priority, job.spec.match_id);
        self.metrics.leased += 1;
        Ok(Some(Leased {
            id,
            attempt: job.attempts + 1,
            spec: job.spec,
        }))
    }

    fn next_ready(&self, p: Priority, now: u64, families: &[Family]) -> Option<JobId> {
        let lo: PendKey = (p, [0; 32], 0, [0; 32]);
        let hi: PendKey = (p, [0xff; 32], u64::MAX, [0xff; 32]);
        let pivot: Option<PendKey> = self.rotation.get(&p).map(|m| (p, *m, u64::MAX, [0xff; 32]));
        let tail = match pivot {
            Some(pv) => self.pending.range((Excluded(pv), Included(hi))),
            None => self.pending.range(lo..=hi),
        };
        let wrapped = pivot.map(|pv| self.pending.range(lo..=pv));
        tail.chain(wrapped.into_iter().flatten())
            .find(|k| self.eligible(&k.3, now, families))
            .map(|k| k.3)
    }

    fn eligible(&self, id: &JobId, now: u64, families: &[Family]) -> bool {
        self.jobs.get(id).is_some_and(|j| {
            families.contains(&j.spec.family)
                && j.not_before <= now
                && j.spec.deps.iter().all(|d| self.is_good(d))
        })
    }

    /// Record a worker's result. Returns `false` (and changes nothing) when the job is no longer
    /// leased, for example because the lease lapsed and another worker already finished it:
    /// completing twice is harmless.
    pub fn complete(&mut self, id: &JobId, outcome: Outcome, now: u64) -> io::Result<bool> {
        let Some(job) = self
            .jobs
            .get(id)
            .filter(|j| j.state == JobState::Processing)
        else {
            return Ok(false);
        };
        let mut b = self.batch();
        self.plan_outcome(job, outcome, now, &mut b);
        let retried = b.finished().is_empty();
        self.commit(b)?;
        if retried {
            self.metrics.retries += 1;
        }
        Ok(true)
    }

    fn plan_outcome(&self, job: &Job, outcome: Outcome, now: u64, b: &mut Batch) {
        let verdict = match outcome {
            Outcome::Valid => Verdict::new(JobState::Verified, ""),
            Outcome::Certified => Verdict::new(JobState::Certified, ""),
            Outcome::Violation { accused, evidence } => Verdict {
                accused: Some(accused),
                evidence,
                ..Verdict::new(JobState::ViolationProven, "violation proven")
            },
            Outcome::Invalid(r) => Verdict::new(JobState::Failed, r),
            Outcome::Inconclusive(r) => Verdict::new(JobState::Uncertified, r),
            Outcome::Retry(r) => return self.plan_retry(job, r, now, b),
        };
        b.finish(job, verdict, now);
    }

    fn plan_retry(&self, job: &Job, reason: String, now: u64, b: &mut Batch) {
        if job.attempts >= self.cfg.max_attempts {
            let why = format!("gave up after {} attempts: {reason}", job.attempts);
            b.finish(job, Verdict::new(JobState::Failed, why), now);
            return;
        }
        let exponent = job.attempts.saturating_sub(1).min(32);
        let delay = self
            .cfg
            .retry_base
            .saturating_mul(1u64 << exponent)
            .min(self.cfg.retry_cap);
        let rec = Record::Retry {
            id: job.id,
            not_before: now.saturating_add(delay),
            reason,
        };
        b.step(job, rec);
    }

    /// End an unfinished job without a verdict.
    pub fn cancel(&mut self, id: &JobId, now: u64) -> io::Result<bool> {
        let mut b = self.batch();
        if let Some(job) = self.jobs.get(id).filter(|j| !j.state.is_terminal()) {
            b.finish(job, Verdict::new(JobState::Uncertified, "cancelled"), now);
        }
        let any = !b.is_empty();
        self.commit(b)?;
        Ok(any)
    }

    /// Cancel everything unfinished in a match (the match was abandoned). Returns how many.
    pub fn cancel_match(&mut self, m: &MatchId, now: u64) -> io::Result<usize> {
        let mut b = self.batch();
        for job in self.jobs_of_match(m).filter(|j| !j.state.is_terminal()) {
            b.finish(
                job,
                Verdict::new(JobState::Uncertified, "match cancelled"),
                now,
            );
        }
        let n = b.finished().len();
        self.commit(b)?;
        Ok(n)
    }

    /// The application has acted on a finished job (for example applied a proven violation):
    /// drop it now instead of waiting for collection.
    pub fn forget(&mut self, id: &JobId) -> io::Result<bool> {
        if !self.state_of(id).is_some_and(JobState::is_terminal) {
            return Ok(false);
        }
        let mut b = self.batch();
        b.raw(Record::Remove { id: *id });
        self.commit(b)?;
        Ok(true)
    }
}
