//! Periodic housekeeping: lapsed leases, deadlines, failed dependencies, collection of old
//! results and journal compaction.
use super::batch::{Batch, Verdict};
use super::Queue;
use crate::job::{Job, JobId, JobState};
use crate::record::Record;
use std::collections::BTreeSet;
use std::io;

impl Queue {
    /// Run all housekeeping at `now` in one journal write.
    pub fn maintain(&mut self, now: u64) -> io::Result<()> {
        let mut b = self.batch();
        self.plan_time(now, &mut b);
        self.plan_dependencies(now, &mut b);
        self.plan_collection(now, &mut b);
        let (lapsed, removed) = (b.lapsed, self.count_removals(&b));
        self.commit(b)?;
        self.metrics.lapsed_leases += lapsed;
        self.metrics.gc_removed += removed;
        self.maybe_compact()
    }

    fn count_removals(&self, b: &Batch) -> u64 {
        let removals = b
            .records()
            .iter()
            .filter(|r| matches!(r, Record::Remove { .. }))
            .count();
        removals as u64
    }

    /// A job past its deadline expires (never certifies); a lapsed lease goes back to pending, or
    /// fails once the job has used all its attempts.
    fn plan_time(&self, now: u64, b: &mut Batch) {
        for job in self.jobs.values().filter(|j| !j.state.is_terminal()) {
            if job.spec.deadline.is_some_and(|d| d <= now) {
                b.finish(job, Verdict::new(JobState::Expired, "deadline passed"), now);
            } else if job.state == JobState::Processing && job.lease_until <= now {
                self.plan_lapse(job, now, b);
            }
        }
    }

    fn plan_lapse(&self, job: &Job, now: u64, b: &mut Batch) {
        b.lapsed += 1;
        if job.attempts >= self.cfg.max_attempts {
            b.finish(
                job,
                Verdict::new(JobState::Failed, "lease lapsed too often"),
                now,
            );
        } else {
            b.step(job, Record::Requeue { id: job.id });
        }
    }

    /// A pending job whose dependency ended without being verified can never be verified.
    fn plan_dependencies(&self, now: u64, b: &mut Batch) {
        for job in self.jobs.values().filter(|j| j.state == JobState::Pending) {
            if b.touched(&job.id) {
                continue;
            }
            let broken = job.spec.deps.iter().find(|d| self.dependency_broken(d));
            if let Some(d) = broken {
                let why = format!("dependency {} did not verify", hex_prefix(d));
                b.finish(job, Verdict::new(JobState::Uncertified, why), now);
            }
        }
    }

    fn dependency_broken(&self, id: &JobId) -> bool {
        self.jobs
            .get(id)
            .is_none_or(|d| d.state.is_terminal() && !d.state.satisfies_dependency())
    }

    /// Finished jobs are dropped once their retention passes, except proven violations (kept until
    /// the application forgets them) and jobs something unfinished still depends on.
    fn plan_collection(&self, now: u64, b: &mut Batch) {
        let needed: BTreeSet<JobId> = self
            .jobs
            .values()
            .filter(|j| !j.state.is_terminal())
            .flat_map(|j| j.spec.deps.iter().copied())
            .collect();
        let retention = self.cfg.retention;
        let collectable = |j: &&Job| {
            j.state.is_terminal()
                && j.state != JobState::ViolationProven
                && j.finished_at.saturating_add(retention) <= now
                && !needed.contains(&j.id)
                && !b.touched(&j.id)
        };
        let ids: Vec<JobId> = self
            .jobs
            .values()
            .filter(collectable)
            .map(|j| j.id)
            .collect();
        ids.into_iter().for_each(|id| b.raw(Record::Remove { id }));
    }

    /// Rewrite the journal as a snapshot of what is retained, once it has doubled.
    fn maybe_compact(&mut self) -> io::Result<()> {
        let size = self.journal.size();
        if size < self.cfg.compact_min_bytes || size < self.last_compact_bytes.saturating_mul(2) {
            return Ok(());
        }
        let snapshot: Vec<Vec<u8>> = self.snapshot().iter().map(Record::encode).collect();
        if let Err(e) = self.journal.rewrite(&snapshot) {
            self.metrics.storage_errors += 1;
            return Err(e);
        }
        self.last_compact_bytes = self.journal.size();
        self.metrics.compactions += 1;
        Ok(())
    }

    fn snapshot(&self) -> Vec<Record> {
        let mut jobs: Vec<&Job> = self.jobs.values().collect();
        jobs.sort_by_key(|j| j.seq);
        let jobs = jobs.into_iter().map(|j| Record::Job(Box::new(j.clone())));
        let events = self.events.iter().cloned().map(Record::Event);
        jobs.chain(events).collect()
    }

    /// After a restart nothing is really leased: put those jobs back (or fail the ones that keep
    /// taking the process down).
    pub(super) fn recover_leases(&mut self, now: u64) -> io::Result<()> {
        let mut b = self.batch();
        for job in self
            .jobs
            .values()
            .filter(|j| j.state == JobState::Processing)
        {
            if job.attempts >= self.cfg.max_attempts {
                let v = Verdict::new(JobState::Failed, "interrupted too often");
                b.finish(job, v, now);
            } else {
                b.step(job, Record::Requeue { id: job.id });
            }
        }
        self.commit(b)
    }
}

fn hex_prefix(id: &JobId) -> String {
    id.iter().take(4).map(|b| format!("{b:02x}")).collect()
}
