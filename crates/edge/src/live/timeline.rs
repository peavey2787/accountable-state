//! Provisional simulation with bounded prediction and rollback.
//!
//! The timeline advances the *real* rules engine the instant local input is known, predicting
//! every other submitter's input by the configured [`Prediction`]. When authoritative remote
//! input arrives that disagrees with a prediction, the affected ticks are re-simulated.
//! Everything here is provisional: the certified state comes only from the asynchronous
//! checkpoint pipeline, which rebases the timeline once an epoch is certified. The tick rate is
//! the application's business; only the tick index ever enters the rules.
use crate::{EdgeError, InputViolation, StateMachine};
use gv_core::Session;
use gv_replay::step_tick;
use std::collections::VecDeque;

/// What is assumed about a remote participant's input before it arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prediction {
    /// Repeat their last known input (continuous controls).
    HoldLast,
    /// Assume the neutral input (commands that must never be repeated).
    Neutral,
}

#[derive(Clone, Debug)]
struct Slot {
    input: Vec<u8>,
    /// Signed/received from the participant, as opposed to predicted.
    authoritative: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TimelineStats {
    pub rollbacks: u64,
    pub max_rollback_ticks: u64,
    pub resimulated_ticks: u64,
    pub stalls: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdvanceError {
    /// A submitter has not been heard from for more than `max_predict` ticks.
    Stalled,
    Rules(EdgeError),
}

pub struct Timeline<R: StateMachine> {
    rules: R,
    session: Session,
    local: usize,
    neutral: Vec<u8>,
    prediction: Prediction,
    submits: Vec<bool>,
    base_tick: u64,
    base_state: Vec<u8>,
    /// Input history of every submitter starting at `base_tick`.
    inputs: Vec<VecDeque<Slot>>,
    /// `states[k]` is the state after applying tick `base_tick + k`.
    states: VecDeque<Vec<u8>>,
    /// Input in force just before `base_tick`; seeds hold-last prediction.
    carry: Vec<Vec<u8>>,
    /// Per slot: authoritative input is known for every tick below this.
    confirmed: Vec<u64>,
    max_predict: u64,
    /// While a participant is sealed their input is predicted neutral, not held.
    sealed: Vec<Option<(u64, u64)>>,
    violations: Vec<InputViolation>,
    pub stats: TimelineStats,
}

impl<R: StateMachine> Timeline<R> {
    pub fn new(
        rules: R,
        session: Session,
        local: usize,
        verified: (u64, Vec<u8>),
        neutral: Vec<u8>,
        prediction: Prediction,
        max_predict: u64,
    ) -> Option<Self> {
        session.roster.get(local)?;
        let slots = session.roster.len();
        let submits = (0..slots)
            .map(|s| session.roster.get(s).is_some_and(|p| p.role.submits()))
            .collect();
        Some(Self {
            rules,
            session,
            local,
            prediction,
            submits,
            base_tick: verified.0,
            base_state: verified.1,
            inputs: vec![VecDeque::new(); slots],
            states: VecDeque::new(),
            carry: vec![neutral.clone(); slots],
            confirmed: vec![verified.0; slots],
            max_predict,
            sealed: vec![None; slots],
            neutral,
            violations: Vec::new(),
            stats: TimelineStats::default(),
        })
    }
    pub fn local_slot(&self) -> usize {
        self.local
    }
    /// Next tick to simulate.
    pub fn tick(&self) -> u64 {
        self.base_tick + self.states.len() as u64
    }
    pub fn state(&self) -> &[u8] {
        self.states.back().unwrap_or(&self.base_state)
    }
    pub fn verified(&self) -> (u64, &[u8]) {
        (self.base_tick, &self.base_state)
    }
    /// Authoritative input of `slot` is known for every tick below the returned tick.
    pub fn confirmed(&self, slot: usize) -> u64 {
        self.confirmed.get(slot).copied().unwrap_or(0)
    }
    pub fn violations(&self) -> &[InputViolation] {
        &self.violations
    }
    /// Remote submitters other than the local participant.
    fn remotes(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.submits.len()).filter(|s| *s != self.local && self.submits[*s])
    }
    /// How far the simulation has run ahead of the least-confirmed remote submitter.
    pub fn prediction_depth(&self) -> u64 {
        let tick = self.tick();
        self.remotes()
            .map(|s| tick.saturating_sub(self.confirmed[s]))
            .max()
            .unwrap_or(0)
    }
    pub fn set_sealed_window(&mut self, slot: usize, window: Option<(u64, u64)>) {
        if let Some(w) = self.sealed.get_mut(slot) {
            *w = window;
        }
    }
    fn predicted(&self, slot: usize, tick: u64, previous: &[u8]) -> Vec<u8> {
        match (self.sealed[slot], self.prediction) {
            (Some((from, to)), _) if tick >= from && tick < to => self.neutral.clone(),
            (_, Prediction::HoldLast) => previous.to_vec(),
            (_, Prediction::Neutral) => self.neutral.clone(),
        }
    }
    fn previous_input(&self, slot: usize, idx: usize) -> &[u8] {
        match idx.checked_sub(1).and_then(|i| self.inputs[slot].get(i)) {
            Some(s) => &s.input,
            None => &self.carry[slot],
        }
    }
    /// Extend a remote submitter's history with predictions through `idx` inclusive.
    fn fill_predictions(&mut self, slot: usize, idx: usize) {
        while self.inputs[slot].len() <= idx {
            let at = self.inputs[slot].len();
            let input = self.predicted(
                slot,
                self.base_tick + at as u64,
                self.previous_input(slot, at),
            );
            self.inputs[slot].push_back(Slot {
                input,
                authoritative: false,
            });
        }
    }
    fn step(
        &self,
        state: &[u8],
        tick: u64,
        idx: usize,
    ) -> Result<(Vec<u8>, Vec<InputViolation>), EdgeError> {
        let inputs: Vec<Vec<&[u8]>> = (0..self.submits.len())
            .map(|s| {
                if self.submits[s] {
                    vec![self.inputs[s][idx].input.as_slice()]
                } else {
                    Vec::new()
                }
            })
            .collect();
        let mut found = Vec::new();
        let next = step_tick(
            &self.rules,
            &self.session,
            state.to_vec(),
            tick,
            &inputs,
            true,
            &mut found,
        )?;
        Ok((next, found))
    }
    fn stalled(&self, tick: u64) -> bool {
        self.remotes().any(|s| {
            tick.saturating_sub(self.confirmed[s]) > self.max_predict && self.sealed[s].is_none()
        })
    }
    /// Simulate the next tick with the local input; predicts every other submitter.
    pub fn advance(&mut self, local_input: &[u8]) -> Result<u64, AdvanceError> {
        let tick = self.tick();
        // While a participant is sealed their input is deliberately unknown, so the
        // prediction limit does not apply until the reveal fills it in.
        if self.stalled(tick) {
            self.stats.stalls += 1;
            return Err(AdvanceError::Stalled);
        }
        let idx = self.states.len();
        if self.submits[self.local] {
            // Local input is authoritative by definition.
            let slot = Slot {
                input: local_input.to_vec(),
                authoritative: true,
            };
            match self.inputs[self.local].get_mut(idx) {
                Some(existing) => *existing = slot,
                None => self.inputs[self.local].push_back(slot),
            }
        }
        let remotes: Vec<usize> = self.remotes().collect();
        for s in remotes {
            self.fill_predictions(s, idx);
        }
        let (next, found) = self
            .step(self.state(), tick, idx)
            .map_err(AdvanceError::Rules)?;
        self.record(found);
        self.states.push_back(next);
        Ok(tick)
    }
    fn record(&mut self, found: Vec<InputViolation>) {
        for v in found {
            if !self.violations.contains(&v) {
                self.violations.push(v);
            }
        }
    }
    /// Store authoritative input of `slot` for ticks `from_tick..`; the earliest already
    /// simulated tick whose input changed is returned.
    fn store_authoritative(
        &mut self,
        slot: usize,
        from_tick: u64,
        inputs: &[Vec<u8>],
    ) -> Option<u64> {
        let mut dirty: Option<u64> = None;
        for (k, input) in inputs.iter().enumerate() {
            let tick = from_tick + k as u64;
            if tick < self.base_tick {
                continue;
            }
            let idx = (tick - self.base_tick) as usize;
            self.fill_predictions(slot, idx);
            let entry = &mut self.inputs[slot][idx];
            if idx < self.states.len() && entry.input != *input {
                dirty = Some(dirty.map_or(tick, |d| d.min(tick)));
            }
            *entry = Slot {
                input: input.clone(),
                authoritative: true,
            };
        }
        dirty
    }
    /// Confirmed extends over every contiguous authoritative tick, including frames that
    /// arrived early across a gap that has just been filled.
    fn extend_confirmed(&mut self, slot: usize, from_tick: u64, end: u64) {
        if from_tick <= self.confirmed[slot] {
            self.confirmed[slot] = self.confirmed[slot].max(end);
        }
        while self.confirmed[slot] >= self.base_tick
            && self.inputs[slot]
                .get((self.confirmed[slot] - self.base_tick) as usize)
                .is_some_and(|s| s.authoritative)
        {
            self.confirmed[slot] += 1;
        }
    }
    /// Re-derive predictions that follow new authoritative data.
    fn refresh_predictions(&mut self, slot: usize, end: u64, dirty: &mut Option<u64>) {
        let first = (end.max(self.base_tick) - self.base_tick) as usize;
        for idx in first..self.inputs[slot].len() {
            if self.inputs[slot][idx].authoritative {
                continue;
            }
            let tick = self.base_tick + idx as u64;
            let wanted = self.predicted(slot, tick, self.previous_input(slot, idx));
            if self.inputs[slot][idx].input != wanted {
                self.inputs[slot][idx].input = wanted;
                if idx < self.states.len() {
                    *dirty = Some(dirty.map_or(tick, |d| d.min(tick)));
                }
            }
        }
    }
    /// Authoritative inputs of `slot` for ticks `from_tick..from_tick+inputs.len()`. Returns
    /// the number of ticks that had to be re-simulated.
    pub fn set_remote(
        &mut self,
        slot: usize,
        from_tick: u64,
        inputs: &[Vec<u8>],
    ) -> Result<u64, EdgeError> {
        if slot == self.local || !self.submits.get(slot).copied().unwrap_or(false) {
            return Ok(0);
        }
        let end = from_tick + inputs.len() as u64;
        let mut dirty = self.store_authoritative(slot, from_tick, inputs);
        self.extend_confirmed(slot, from_tick, end);
        self.refresh_predictions(slot, end, &mut dirty);
        match dirty {
            Some(tick) => self.resimulate_from(tick),
            None => Ok(0),
        }
    }
    fn resimulate_from(&mut self, tick: u64) -> Result<u64, EdgeError> {
        let idx = (tick - self.base_tick) as usize;
        let target = self.states.len();
        self.states.truncate(idx);
        for at in idx..target {
            let (next, found) = self.step(self.state(), self.base_tick + at as u64, at)?;
            self.record(found);
            self.states.push_back(next);
        }
        let depth = (target - idx) as u64;
        self.stats.rollbacks += 1;
        self.stats.max_rollback_ticks = self.stats.max_rollback_ticks.max(depth);
        self.stats.resimulated_ticks += depth;
        Ok(depth)
    }
    /// What `slot` actually played (local) or was assumed/known to play for `[from, to)`.
    pub fn inputs_of(&self, slot: usize, from: u64, to: u64) -> Option<Vec<Vec<u8>>> {
        if from < self.base_tick || to > self.tick() || from > to || !*self.submits.get(slot)? {
            return None;
        }
        (from..to)
            .map(|t| {
                self.inputs[slot]
                    .get((t - self.base_tick) as usize)
                    .map(|s| s.input.clone())
            })
            .collect()
    }
    /// Inputs the local participant actually played for `[from, to)`.
    pub fn own_inputs(&self, from: u64, to: u64) -> Option<Vec<Vec<u8>>> {
        self.inputs_of(self.local, from, to)
    }
    /// Adopt a certified state. Returns whether the provisional state already agreed with it;
    /// if not, the timeline is replayed from the certified state.
    pub fn rebase(&mut self, tick: u64, state: &[u8]) -> Result<bool, EdgeError> {
        if tick <= self.base_tick {
            return Ok(true);
        }
        let drop = (tick - self.base_tick) as usize;
        let ahead = self.states.len();
        let consistent = drop <= ahead && self.states[drop - 1] == state;
        for s in 0..self.inputs.len() {
            if let Some(slot) = self.inputs[s].get(drop - 1) {
                self.carry[s] = slot.input.clone();
            }
            let keep = drop.min(self.inputs[s].len());
            self.inputs[s].drain(..keep);
        }
        self.base_tick = tick;
        self.base_state = state.to_vec();
        if drop >= ahead {
            self.states.clear();
        } else {
            self.states.drain(..drop);
        }
        if !consistent {
            self.replay_beyond(ahead.saturating_sub(drop))?;
        }
        for c in &mut self.confirmed {
            *c = (*c).max(tick);
        }
        self.violations.retain(|v| v.tick >= tick);
        Ok(consistent)
    }
    /// Replay everything simulated beyond the certified tick.
    fn replay_beyond(&mut self, target: usize) -> Result<(), EdgeError> {
        self.states.clear();
        for at in 0..target {
            let complete =
                (0..self.submits.len()).all(|s| !self.submits[s] || at < self.inputs[s].len());
            if !complete {
                break;
            }
            let (next, found) = self.step(self.state(), self.base_tick + at as u64, at)?;
            self.record(found);
            self.states.push_back(next);
        }
        self.stats.rollbacks += 1;
        self.stats.resimulated_ticks += target as u64;
        Ok(())
    }
}
