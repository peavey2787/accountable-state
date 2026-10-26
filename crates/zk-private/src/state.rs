use crate::prover::StepError;
use zk_sdk::predicate::{Commitment, IntType, Number, Opening};

/// A hidden state held by its owner: every field's public commitment and private opening. The
/// last field is the context slot.
pub struct State {
    fields: Vec<(Commitment, Opening)>,
}

impl State {
    /// The first state: the given user fields and an empty context slot.
    pub fn genesis(values: &[(IntType, Number)]) -> Result<Self, StepError> {
        Self::with_slot(values, 0)
    }

    pub(crate) fn with_slot(values: &[(IntType, Number)], slot: u128) -> Result<Self, StepError> {
        let mut fields = values
            .iter()
            .map(|(ty, value)| Commitment::commit(*ty, *value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(StepError::from_sdk)?;
        fields.push(Commitment::commit(IntType::U128, slot).map_err(StepError::from_sdk)?);
        Ok(Self { fields })
    }

    /// The public side: publish these, keep the state.
    pub fn commitments(&self) -> Vec<Commitment> {
        self.fields.iter().map(|(c, _)| *c).collect()
    }

    pub(crate) fn openings(&self) -> Vec<Opening> {
        self.fields.iter().map(|(_, o)| o.clone()).collect()
    }

    pub(crate) fn slot(&self) -> usize {
        self.fields.len() - 1
    }
}
