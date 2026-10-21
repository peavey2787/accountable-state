//! Deliberate misbehaviour, for demonstrating and testing the accountability layer. Each fault
//! must be detected by an honest peer and end in a verifiable package or a cleared suspicion.
use crate::node::AccountableState;
use gv_replay::StateMachine;

/// How long [`AccountableState::withhold_answers`] stays silent.
const WITHHOLD_TICKS: u64 = 600;

impl<M: StateMachine + Clone> AccountableState<M> {
    /// Sign a false state in the next checkpoint (provable with a fraud bundle).
    pub fn inject_false_checkpoint(&mut self) {
        self.pipe.inject_cheat();
    }
    /// Sign two conflicting log heads (provable equivocation).
    pub fn equivocate_next(&mut self) {
        self.pipe.auditor_mut().equivocate_next_authenticator();
    }
    /// Stop answering audit challenges for a while (suspicion that later clears).
    pub fn withhold_answers(&mut self) {
        let until = self.now + WITHHOLD_TICKS;
        self.pipe.auditor_mut().withhold_answers_until(until);
    }
    /// Frame the opponent with forged evidence and a false missing-batch claim; both must be
    /// rejected.
    pub fn accuse_falsely(&mut self) {
        if let Some(c) = self.pipe.last_peer_checkpoint().cloned() {
            self.pipe.auditor_mut().send_forged_accusation(&c);
        }
        let epoch = u64::from(self.epoch_ticks.max(1));
        let at = self.pipe.replica().next_tick().saturating_sub(1);
        let now = self.now;
        self.pipe
            .auditor_mut()
            .accuse_missing_batch(at / epoch * epoch, now);
    }
}
