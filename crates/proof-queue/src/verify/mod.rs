//! Verifiers: pure functions from a job's canonical inputs to a conclusion. Pure matters, because
//! execution is at-least-once (a crash or a lapsed lease runs a job again).
mod builtin;
mod pack;

pub use builtin::{
    transition_payload, Commitments, Equivocation, RecoveryCertificates, SignedInputs,
    TransitionVerifier,
};
pub use pack::{pack, unpack, MAX_ITEMS};

use crate::job::{Family, JobSpec, Outcome};
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

pub trait Verifier: Send + Sync {
    fn family(&self) -> Family;
    fn verify(&self, spec: &JobSpec) -> Outcome;
    /// Several jobs of this family at once; verifiers with a cheaper joint check override it.
    fn verify_batch(&self, specs: &[&JobSpec]) -> Vec<Outcome> {
        specs.iter().map(|s| self.verify(s)).collect()
    }
}

/// The verifiers a worker has, by family. A job whose family has none is never leased by it.
#[derive(Default, Clone)]
pub struct Registry {
    by_family: BTreeMap<Family, Arc<dyn Verifier>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, v: impl Verifier + 'static) -> Self {
        self.by_family.insert(v.family(), Arc::new(v));
        self
    }

    pub fn families(&self) -> Vec<Family> {
        self.by_family.keys().copied().collect()
    }

    /// Run `specs` (all of one family). A verifier that panics is a transient fault, not a
    /// verdict about the evidence.
    pub fn run(&self, family: Family, specs: &[&JobSpec]) -> Vec<Outcome> {
        let Some(v) = self.by_family.get(&family) else {
            return specs
                .iter()
                .map(|_| Outcome::Retry("no verifier for this family".into()))
                .collect();
        };
        match catch_unwind(AssertUnwindSafe(|| v.verify_batch(specs))) {
            Ok(out) if out.len() == specs.len() => out,
            _ => specs
                .iter()
                .map(|_| Outcome::Retry("verifier faulted".into()))
                .collect(),
        }
    }
}
