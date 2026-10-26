use crate::binding::Context;
use crate::{wire, Program, State};
use gv_zk::PublicClaim;
use zk_sdk::predicate::{Commitment, IntType, Number, Predicates, Transition};

#[derive(Debug)]
pub struct StepError(String);

impl StepError {
    pub(crate) fn from_sdk(e: impl std::fmt::Display) -> Self {
        Self(e.to_string())
    }
}

impl std::fmt::Display for StepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StepError {}

/// What leaves the prover: the claim to sign and send, and the proof for it.
pub struct Step {
    pub claim: PublicClaim,
    pub proof: Vec<u8>,
}

/// Move `old` to a new hidden state with the given user-field values, proving the program's
/// rules held. Fails, before proving, when the values break a rule.
pub fn advance(
    program: &Program,
    context: &Context,
    old: &State,
    new_values: &[(IntType, Number)],
) -> Result<(State, Step), StepError> {
    let old_c = old.commitments();
    if new_values.len() + 1 != old_c.len() {
        return Err(StepError(
            "the new state has a different number of fields".into(),
        ));
    }
    let tag = context.tag(program);
    let new = State::with_slot(new_values, tag)?;
    let new_c: Vec<Commitment> = new.commitments();
    let rules = program.rules_with_context(new.slot(), tag);
    let transition =
        Transition::new(old_c.clone(), new_c.clone(), &rules).map_err(StepError::from_sdk)?;
    let openings = old.openings().into_iter().chain(new.openings()).collect();
    let witness = transition.witness(openings).map_err(StepError::from_sdk)?;
    let proof = Predicates::new()
        .prove_all(transition.claim(), witness)
        .map_err(StepError::from_sdk)?;
    let step = Step {
        claim: context.claim(program, &old_c, &new_c),
        proof: wire::encode(&old_c, &new_c, proof.as_bytes()),
    };
    Ok((new, step))
}
