//! Turns an uncertified log-equivocation finding into [`Evidence::Certified`] by fetching the
//! receipts for each authenticator from the witnesses.
//!
//! Gathering can stall (witnesses down, partitioned or silent): the finding then expires without
//! any verdict. Silence is never evidence.
use super::set::WitnessSet;
use super::wire::{Certificate, Claim, QuorumMsg, Receipt};
use crate::audit::{Authenticator, Evidence};
use gv_core::{Digest, ParticipantId};
use std::collections::BTreeMap;

/// Findings gathered at once; further ones are dropped (the finding recurs if still true).
pub const MAX_JOBS: usize = 16;
/// Ticks after which an unfinished finding is abandoned.
pub const EXPIRY_TICKS: u64 = 6000;

struct Want {
    auth: Authenticator,
    claims: BTreeMap<Digest, (Claim, BTreeMap<ParticipantId, Receipt>)>,
}

impl Want {
    fn certificate(&self, set: &WitnessSet) -> Option<Certificate> {
        self.claims.values().find_map(|(claim, receipts)| {
            let cert = Certificate {
                claim: claim.clone(),
                receipts: receipts.values().cloned().collect(),
            };
            (claim.auth == self.auth && cert.verify(set).is_ok()).then_some(cert)
        })
    }
}

struct Job {
    inner: Evidence,
    wants: Vec<Want>,
    born: u64,
}

pub struct Gatherer {
    set: WitnessSet,
    jobs: BTreeMap<Digest, Job>,
}

impl Gatherer {
    pub fn new(set: WitnessSet) -> Self {
        Self {
            set,
            jobs: BTreeMap::new(),
        }
    }
    pub fn pending(&self) -> usize {
        self.jobs.len()
    }

    /// Begin gathering for `inner` (a plain equivocation proof). Returns the requests to send
    /// to every witness; empty if the finding is already being gathered or the table is full.
    pub fn start(&mut self, inner: Evidence, now: u64) -> Vec<QuorumMsg> {
        let auths = match &inner {
            Evidence::ConflictingAuthenticators(a, b) => vec![a.clone(), b.clone()],
            Evidence::Fork { earlier, later, .. } => vec![earlier.clone(), later.clone()],
            _ => return Vec::new(),
        };
        let Ok(id) = inner.id() else {
            return Vec::new();
        };
        if self.jobs.contains_key(&id) || self.jobs.len() >= MAX_JOBS {
            return Vec::new();
        }
        let wants = auths
            .into_iter()
            .map(|auth| Want {
                auth,
                claims: BTreeMap::new(),
            })
            .collect();
        self.jobs.insert(
            id,
            Job {
                inner,
                wants,
                born: now,
            },
        );
        self.requests()
    }

    /// Every request still needed, for the first send and for retransmission.
    pub fn requests(&self) -> Vec<QuorumMsg> {
        let mut out = Vec::new();
        for job in self.jobs.values() {
            for w in job
                .wants
                .iter()
                .filter(|w| w.certificate(&self.set).is_none())
            {
                out.push(QuorumMsg::HeldReq {
                    owner: w.auth.owner,
                    seq: w.auth.seq,
                });
            }
        }
        out.dedup();
        out
    }

    /// A witness's answer. Returns the evidence of every finding this completed.
    pub fn on_held(&mut self, claim: Claim, receipt: Receipt) -> Vec<Evidence> {
        let valid = self.set.contains(&receipt.witness)
            && receipt.claim == claim.digest()
            && receipt.verify().is_ok()
            && claim.verify().is_ok();
        if !valid {
            return Vec::new();
        }
        let digest = claim.digest();
        for job in self.jobs.values_mut() {
            for w in job.wants.iter_mut().filter(|w| w.auth == claim.auth) {
                w.claims
                    .entry(digest)
                    .or_insert_with(|| (claim.clone(), BTreeMap::new()))
                    .1
                    .insert(receipt.witness, receipt.clone());
            }
        }
        self.take_complete()
    }

    fn take_complete(&mut self) -> Vec<Evidence> {
        let ready: Vec<Digest> = self
            .jobs
            .iter()
            .filter(|(_, j)| j.wants.iter().all(|w| w.certificate(&self.set).is_some()))
            .map(|(id, _)| *id)
            .collect();
        ready
            .into_iter()
            .filter_map(|id| self.jobs.remove(&id))
            .map(|job| {
                let certs = job
                    .wants
                    .iter()
                    .filter_map(|w| w.certificate(&self.set))
                    .collect();
                Evidence::Certified {
                    inner: Box::new(job.inner),
                    certs,
                }
            })
            .collect()
    }

    /// Abandon findings that could not be certified in time. No verdict results.
    pub fn expire(&mut self, now: u64) -> usize {
        let before = self.jobs.len();
        self.jobs
            .retain(|_, j| now.saturating_sub(j.born) < EXPIRY_TICKS);
        before - self.jobs.len()
    }
}
