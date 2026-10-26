use crate::binding::{root, Context};
use crate::{wire, Program};
use gv_zk::{PublicClaim, ZkError, ZkVerifier};
use zk_sdk::predicate::{PredicateProof, Predicates, Transition};

/// Verifies private-transition proofs for one pinned program. A proof is accepted only for a
/// claim naming this program, whose roots are the proof's commitment lists and whose context
/// (match, manifest, ruleset, checkpoint, inputs) is the one the proof was made for.
pub struct PrivateTransitionVerifier {
    program: Program,
    engine: Predicates,
}

impl PrivateTransitionVerifier {
    pub fn new(program: Program) -> Self {
        Self {
            program,
            engine: Predicates::new(),
        }
    }

    fn names_this_program(&self, statement: &PublicClaim) -> bool {
        statement.program_id == self.program.id()
            && statement.violation_code == self.program.violation_code()
    }
}

impl ZkVerifier for PrivateTransitionVerifier {
    fn verify(&self, statement: &PublicClaim, proof: &[u8]) -> Result<(), ZkError> {
        if !self.names_this_program(statement) {
            return Err(ZkError::Invalid);
        }
        let package = wire::decode(proof).ok_or(ZkError::Invalid)?;
        let slots = self.program.fields() + 1;
        let bound = package.old.len() == slots
            && root(&package.old) == statement.prior_root
            && root(&package.new) == statement.next_root;
        if !bound {
            return Err(ZkError::Invalid);
        }
        let tag = Context::of(statement).tag(&self.program);
        let rules = self.program.rules_with_context(slots - 1, tag);
        let transition =
            Transition::new(package.old, package.new, &rules).map_err(|_| ZkError::Invalid)?;
        self.engine
            .verify_all(
                transition.claim(),
                &PredicateProof::from_bytes(package.proof),
            )
            .map_err(|_| ZkError::Invalid)
    }
}
