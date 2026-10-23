//! Offloading proof checks to a durable proof queue. A node that cannot (or should not) verify
//! evidence on its gameplay thread hands it to a [`ProofService`] and reads back [`Finding`]s;
//! the queue journals every job, so a crash loses neither the evidence nor the verdict. A late or
//! missing verdict is never a conviction: only a proven violation becomes a finding.
use crate::io::{Outgoing, Output, WitnessOut};
use gv_core::{MatchId, ParticipantId};
use gv_proof_queue::verify::pack;
use gv_proof_queue::{Family, JobId, JobSpec, JobState, Priority, Service, SubmitError};
use std::sync::Arc;

/// The queue service the node offloads to.
pub type ProofService = Service;

/// Notifications read per call of [`ProofOffload::findings`].
const PAGE: usize = 256;

/// A violation the proof queue proved: who broke the rules, and the evidence that shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub job: JobId,
    pub family: Family,
    pub accused: ParticipantId,
    pub evidence: Vec<u8>,
}

/// New findings since the last call.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Findings {
    pub proven: Vec<Finding>,
    /// Notifications were dropped before they were read (the reader fell too far behind), so a
    /// verdict may have been missed. Nothing is lost from the queue: re-submit the evidence, which
    /// is deduplicated, and read the verdicts again.
    pub missed: bool,
}

/// Connects one node's evidence output to a proof queue service.
pub struct ProofOffload {
    service: Arc<ProofService>,
    match_id: MatchId,
    cursor: u64,
}

impl ProofOffload {
    pub fn new(service: Arc<ProofService>, match_id: MatchId) -> Self {
        Self {
            service,
            match_id,
            cursor: 0,
        }
    }

    /// Queue the evidence in `output` for verification, if it is evidence a proof family covers.
    /// Returns whether a job was accepted (a repeat of known evidence is not a new job).
    pub fn offer(&self, output: &Output) -> Result<bool, SubmitError> {
        let Output::Send(Outgoing::Witness(WitnessOut::Evidence(bytes))) = output else {
            return Ok(false);
        };
        self.submit(Family::EQUIVOCATION, bytes)
    }

    /// Queue one piece of evidence under `family`, ahead of any routine work.
    pub fn submit(&self, family: Family, evidence: &[u8]) -> Result<bool, SubmitError> {
        let spec = JobSpec {
            family,
            match_id: self.match_id,
            payload: pack(&[evidence]),
            priority: Priority::High,
            deadline: None,
            deps: Vec::new(),
        };
        let accepted = self.service.submit(spec)?;
        Ok(!matches!(accepted, gv_proof_queue::Submitted::Duplicate(_)))
    }

    /// Violations proven since the last call. A job that was inconclusive, expired or invalid
    /// produces nothing.
    pub fn findings(&mut self) -> Findings {
        let mut out = Findings::default();
        loop {
            let page = self.service.events_after(self.cursor, PAGE);
            out.missed |= page.gap;
            let Some(last) = page.events.last().map(|e| e.seq) else {
                return out;
            };
            self.cursor = last;
            let proven = page
                .events
                .iter()
                .filter(|e| e.state == JobState::ViolationProven && e.match_id == self.match_id);
            out.proven
                .extend(proven.filter_map(|e| self.finding(&e.job)));
        }
    }

    fn finding(&self, id: &JobId) -> Option<Finding> {
        let job = self.service.job(id)?;
        Some(Finding {
            job: job.id,
            family: job.spec.family,
            accused: job.accused?,
            evidence: job.evidence,
        })
    }

    /// The application has acted on a finding; let the queue drop it.
    pub fn acknowledge(&self, finding: &Finding) -> std::io::Result<bool> {
        self.service.forget(&finding.job)
    }
}
