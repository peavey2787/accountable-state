//! Provisional 60 Hz simulation with bounded prediction and rollback.
//!
//! The timeline advances the *real* rules engine the instant local input is
//! known, predicting the opponent's input by holding their last known control.
//! When authoritative remote input arrives that disagrees with the prediction,
//! the affected ticks are re-simulated. Everything here is provisional: the
//! certified state comes only from the asynchronous checkpoint pipeline, which
//! rebases the timeline once an epoch is co-signed.
use crate::{apply_tick, EdgeError, InputViolation, StateMachine};
use gv_core::PlayerId;
use std::collections::VecDeque;

/// Fixed simulation rate. Time never enters the rules: only the tick index.
pub const TICK_HZ: u32 = 60;

#[derive(Clone, Copy, Debug)]
struct Slot {
    control: u16,
    /// Signed/received from the player, as opposed to predicted.
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
    /// The opponent has not been heard from for more than `max_predict` ticks.
    Stalled,
    Rules(EdgeError),
}

pub struct Timeline<R: StateMachine> {
    rules: R,
    roster: [PlayerId; 2],
    local: usize,
    base_tick: u64,
    base_state: Vec<u8>,
    /// Control history for both players starting at `base_tick`.
    inputs: [VecDeque<Slot>; 2],
    /// `states[k]` is the state after applying tick `base_tick + k`.
    states: VecDeque<Vec<u8>>,
    /// Control in force just before `base_tick`; seeds hold-last prediction.
    carry: [u16; 2],
    /// Remote input is authoritative for every tick below this.
    remote_confirmed: u64,
    max_predict: u64,
    /// While the opponent is hidden their input is predicted neutral, not held.
    neutral_window: Option<(u64, u64)>,
    violations: Vec<InputViolation>,
    pub stats: TimelineStats,
}

impl<R: StateMachine> Timeline<R> {
    pub fn new(
        rules: R,
        roster: [PlayerId; 2],
        local_player: PlayerId,
        verified_tick: u64,
        verified_state: Vec<u8>,
        max_predict: u64,
    ) -> Option<Self> {
        let local = roster.iter().position(|p| *p == local_player)?;
        Some(Self {
            rules,
            roster,
            local,
            base_tick: verified_tick,
            base_state: verified_state,
            inputs: [VecDeque::new(), VecDeque::new()],
            states: VecDeque::new(),
            carry: [0, 0],
            remote_confirmed: verified_tick,
            max_predict,
            neutral_window: None,
            violations: Vec::new(),
            stats: TimelineStats::default(),
        })
    }
    pub fn local_index(&self) -> usize {
        self.local
    }
    fn remote(&self) -> usize {
        1 - self.local
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
    pub fn remote_confirmed(&self) -> u64 {
        self.remote_confirmed
    }
    pub fn violations(&self) -> &[InputViolation] {
        &self.violations
    }
    /// How far the simulation has run ahead of the opponent's confirmed input.
    pub fn prediction_depth(&self) -> u64 {
        self.tick().saturating_sub(self.remote_confirmed)
    }
    pub fn set_neutral_window(&mut self, window: Option<(u64, u64)>) {
        self.neutral_window = window;
    }
    fn predicted_remote(&self, tick: u64, previous: u16) -> u16 {
        match self.neutral_window {
            Some((from, to)) if tick >= from && tick < to => 0,
            _ => previous,
        }
    }
    fn previous_control(&self, player: usize, idx: usize) -> u16 {
        if idx == 0 {
            self.carry[player]
        } else {
            self.inputs[player]
                .get(idx - 1)
                .map_or(self.carry[player], |s| s.control)
        }
    }
    fn step(
        &self,
        state: &[u8],
        tick: u64,
        controls: [u16; 2],
    ) -> Result<(Vec<u8>, Vec<InputViolation>), EdgeError> {
        let mut next = state.to_vec();
        let mut found = Vec::new();
        for (p, control) in controls.iter().enumerate() {
            let (n, v) = apply_tick(&self.rules, &next, &self.roster[p], tick, *control, true)?;
            next = n;
            found.extend(v);
        }
        Ok((next, found))
    }
    /// Simulate the next tick with the local control; predicts the opponent.
    pub fn advance(&mut self, local_control: u16) -> Result<u64, AdvanceError> {
        let tick = self.tick();
        // While the opponent is hidden their input is deliberately unknown, so
        // the prediction limit does not apply until the reveal fills it in.
        if tick.saturating_sub(self.remote_confirmed) > self.max_predict
            && self.neutral_window.is_none()
        {
            self.stats.stalls += 1;
            return Err(AdvanceError::Stalled);
        }
        let idx = self.states.len();
        let (l, r) = (self.local, self.remote());
        // Local input is authoritative by definition.
        let slot = Slot {
            control: local_control,
            authoritative: true,
        };
        if self.inputs[l].len() > idx {
            self.inputs[l][idx] = slot;
        } else {
            self.inputs[l].push_back(slot);
        }
        // Remote input: known (arrived early) or predicted.
        while self.inputs[r].len() <= idx {
            let at = self.inputs[r].len();
            let prev = self.previous_control(r, at);
            let control = self.predicted_remote(self.base_tick + at as u64, prev);
            self.inputs[r].push_back(Slot {
                control,
                authoritative: false,
            });
        }
        let mut controls = [0u16; 2];
        controls[l] = self.inputs[l][idx].control;
        controls[r] = self.inputs[r][idx].control;
        let (next, found) = self
            .step(self.state(), tick, controls)
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
    /// Authoritative remote controls for ticks `from_tick..from_tick+controls.len()`.
    /// Returns the number of ticks that had to be re-simulated.
    pub fn set_remote(&mut self, from_tick: u64, controls: &[u16]) -> Result<u64, EdgeError> {
        let r = self.remote();
        let mut dirty: Option<u64> = None;
        let end = from_tick + controls.len() as u64;
        for (k, control) in controls.iter().enumerate() {
            let tick = from_tick + k as u64;
            if tick < self.base_tick {
                continue;
            }
            let idx = (tick - self.base_tick) as usize;
            while self.inputs[r].len() <= idx {
                let at = self.inputs[r].len();
                let prev = self.previous_control(r, at);
                let control = self.predicted_remote(self.base_tick + at as u64, prev);
                self.inputs[r].push_back(Slot {
                    control,
                    authoritative: false,
                });
            }
            let slot = &mut self.inputs[r][idx];
            if idx < self.states.len() && slot.control != *control {
                dirty = Some(dirty.map_or(tick, |d| d.min(tick)));
            }
            *slot = Slot {
                control: *control,
                authoritative: true,
            };
        }
        // Confirmed extends over every contiguous authoritative tick, including
        // frames that arrived early across a gap that has just been filled.
        if from_tick <= self.remote_confirmed {
            self.remote_confirmed = self.remote_confirmed.max(end);
        }
        while self.remote_confirmed >= self.base_tick
            && self.inputs[r]
                .get((self.remote_confirmed - self.base_tick) as usize)
                .is_some_and(|slot| slot.authoritative)
        {
            self.remote_confirmed += 1;
        }
        // Re-derive hold-last predictions that follow the new authoritative data.
        let first = end.max(self.base_tick) - self.base_tick;
        for idx in first as usize..self.inputs[r].len() {
            if self.inputs[r][idx].authoritative {
                continue;
            }
            let tick = self.base_tick + idx as u64;
            let prev = self.previous_control(r, idx);
            let wanted = self.predicted_remote(tick, prev);
            if self.inputs[r][idx].control != wanted {
                self.inputs[r][idx].control = wanted;
                if idx < self.states.len() {
                    dirty = Some(dirty.map_or(tick, |d| d.min(tick)));
                }
            }
        }
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
            let t = self.base_tick + at as u64;
            let controls = [self.inputs[0][at].control, self.inputs[1][at].control];
            let (next, found) = self.step(self.state(), t, controls)?;
            self.record(found);
            self.states.push_back(next);
        }
        let depth = (target - idx) as u64;
        self.stats.rollbacks += 1;
        self.stats.max_rollback_ticks = self.stats.max_rollback_ticks.max(depth);
        self.stats.resimulated_ticks += depth;
        Ok(depth)
    }
    /// Controls the local player actually played for `[from, to)`.
    pub fn own_controls(&self, from: u64, to: u64) -> Option<Vec<u16>> {
        if from < self.base_tick || to > self.tick() || from > to {
            return None;
        }
        Some(
            (from..to)
                .map(|t| self.inputs[self.local][(t - self.base_tick) as usize].control)
                .collect(),
        )
    }
    /// Controls used for `player` for `[from, to)`, predicted or authoritative.
    pub fn controls_of(&self, player: usize, from: u64, to: u64) -> Option<Vec<u16>> {
        if from < self.base_tick || to > self.tick() || from > to {
            return None;
        }
        Some(
            (from..to)
                .map(|t| self.inputs[player][(t - self.base_tick) as usize].control)
                .collect(),
        )
    }
    /// Adopt a certified state. Returns whether the provisional state already
    /// agreed with it; if not, the timeline is replayed from the certified state.
    pub fn rebase(&mut self, tick: u64, state: &[u8]) -> Result<bool, EdgeError> {
        if tick <= self.base_tick {
            return Ok(true);
        }
        let drop = (tick - self.base_tick) as usize;
        let ahead = self.states.len();
        let consistent = drop <= ahead && self.states[drop - 1] == state;
        for p in 0..2 {
            if let Some(slot) = self.inputs[p].get(drop - 1) {
                self.carry[p] = slot.control;
            }
            let keep = drop.min(self.inputs[p].len());
            self.inputs[p].drain(..keep);
        }
        self.base_tick = tick;
        self.base_state = state.to_vec();
        if drop >= ahead {
            self.states.clear();
        } else {
            self.states.drain(..drop);
        }
        if !consistent {
            // Replay everything we had simulated beyond the certified tick.
            let target = ahead.saturating_sub(drop);
            self.states.clear();
            for at in 0..target {
                if at >= self.inputs[0].len() || at >= self.inputs[1].len() {
                    break;
                }
                let t = self.base_tick + at as u64;
                let controls = [self.inputs[0][at].control, self.inputs[1][at].control];
                let (next, found) = self.step(self.state(), t, controls)?;
                self.record(found);
                self.states.push_back(next);
            }
            self.stats.rollbacks += 1;
            self.stats.resimulated_ticks += target as u64;
        }
        self.remote_confirmed = self.remote_confirmed.max(tick);
        self.violations.retain(|v| v.tick >= tick);
        Ok(consistent)
    }
}
