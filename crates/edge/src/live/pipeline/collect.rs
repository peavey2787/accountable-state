//! Public-play epochs: each submitter signs the exact input batch it played; the epoch ends at
//! the shortest end any participant proposed, so no negotiation round is needed.
//!
//! Only a participant with something to certify proposes an epoch end; every other submitter
//! answers with the same end. If several propose at once, the shortest end wins and the others
//! also sign the (identical-prefix) shorter batch. Nobody signs a longer end after a shorter one,
//! so an end that every submitter signed is never undercut by a later proposal.
use super::config::{OwnInputs, PipeEvent, Suspicion, SuspicionKind, Violation, ViolationKind};
use super::{Pipeline, Stage};
use crate::live::msg::{Close, Outgoing, PipeMsg};
use crate::StateMachine;
use gv_codec::{EventBatch, EventBody, HeldChange, SignedEventBatch};
use gv_core::{Digest, MatchId, ParticipantId};
use gv_sig::SigningKey;

/// Most future-epoch batches kept per roster member.
const FUTURE_PER_MEMBER: usize = 8;

pub(super) struct Collect {
    /// Per roster slot: signed batches starting at the verified tick (identical prefixes,
    /// distinct ends).
    batches: Vec<Vec<SignedEventBatch>>,
    future: Vec<SignedEventBatch>,
    owed: Option<u64>,
    /// Tick at which the current epoch first held a batch; drives the close timeout.
    first_seen: Option<u64>,
    reported_silent: Vec<ParticipantId>,
}
impl Collect {
    pub(super) fn new(slots: usize) -> Self {
        Self {
            batches: vec![Vec::new(); slots],
            future: Vec::new(),
            owed: None,
            first_seen: None,
            reported_silent: Vec::new(),
        }
    }
    /// A longer batch for the epoch that just closed can arrive while it certifies; once the
    /// window moves on it is stale, and must not be compared with the next window's batches.
    pub(super) fn drop_before(&mut self, ws: u64) {
        self.batches
            .iter_mut()
            .for_each(|slot| slot.retain(|b| b.record.start_tick >= ws));
    }
    pub(super) fn reset_epoch(&mut self) {
        self.batches.iter_mut().for_each(Vec::clear);
        self.owed = None;
        self.first_seen = None;
        self.reported_silent.clear();
    }
    fn is_empty(&self) -> bool {
        self.batches.iter().all(Vec::is_empty)
    }
    fn has_end(&self, slot: usize, end: u64) -> bool {
        self.batches[slot].iter().any(|b| end_of(b) == end)
    }
    fn get(&self, slot: usize, end: u64) -> Option<&SignedEventBatch> {
        self.batches[slot].iter().find(|b| end_of(b) == end)
    }
    fn get_by_participant(
        &self,
        roster: &gv_core::Roster,
        b: &SignedEventBatch,
    ) -> Option<&SignedEventBatch> {
        let slot = roster.index_of(&b.record.participant)?;
        self.get(slot, end_of(b))
    }
    fn min_end(&self, slot: usize) -> Option<u64> {
        self.batches[slot].iter().map(end_of).min()
    }
    /// The shortest end every slot in `slots` has signed.
    fn common_end(&self, slots: &[usize]) -> Option<u64> {
        let first = *slots.first()?;
        self.batches[first]
            .iter()
            .map(end_of)
            .filter(|e| slots.iter().all(|s| self.has_end(*s, *e)))
            .min()
    }
    pub(super) fn drop_stale(&mut self, ws: u64) {
        self.future.retain(|b| b.record.start_tick >= ws);
    }
    pub(super) fn take_ready(&mut self, ws: u64) -> Vec<SignedEventBatch> {
        let (ready, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.future)
            .into_iter()
            .partition(|b| b.record.start_tick == ws);
        self.future = rest;
        ready
    }
}

pub(super) fn end_of(b: &SignedEventBatch) -> u64 {
    b.record.start_tick + u64::from(b.record.tick_count)
}

/// The per-tick held inputs of a batch.
pub(super) fn held_inputs(b: &SignedEventBatch) -> Vec<Vec<u8>> {
    (0..b.record.tick_count)
        .map(|k| {
            b.record
                .held_at(k)
                .ok()
                .flatten()
                .map(<[u8]>::to_vec)
                .unwrap_or_default()
        })
        .collect()
}

pub(super) fn pack(
    match_id: MatchId,
    participant: ParticipantId,
    head: Digest,
    start: u64,
    inputs: &[Vec<u8>],
    key: &SigningKey,
) -> Option<SignedEventBatch> {
    let initial = inputs.first()?.clone();
    let width = initial.len();
    if inputs.iter().any(|i| i.len() != width) {
        return None;
    }
    let mut changes = Vec::new();
    let mut previous = &initial;
    for (k, c) in inputs.iter().enumerate().skip(1) {
        if c != previous {
            changes.push(HeldChange {
                offset: u32::try_from(k).ok()?,
                payload: c.clone(),
            });
            previous = c;
        }
    }
    let record = EventBatch {
        match_id,
        participant,
        previous_batch_hash: head,
        start_tick: start,
        tick_count: u32::try_from(inputs.len()).ok()?,
        body: EventBody::Held { initial, changes },
    };
    SignedEventBatch::sign(record, key).ok()
}

impl<R: StateMachine + Clone> Pipeline<R> {
    pub(super) fn ws(&self) -> u64 {
        self.replica.next_tick()
    }
    fn my_slot(&self) -> Option<usize> {
        self.session
            .roster
            .index_of(&self.me)
            .filter(|_| self.can_submit())
    }
    pub(super) fn can_submit(&self) -> bool {
        self.session
            .roster
            .find(&self.me)
            .is_some_and(|p| p.role.submits())
    }
    fn submitter_slots(&self) -> Vec<usize> {
        self.session.roster.submitters()
    }
    fn sign_batch(&mut self, end: u64, own: OwnInputs<'_>) -> Option<SignedEventBatch> {
        if self.auditor.persistence_failed() {
            return None; // fail closed: sign nothing new while the write-ahead store fails
        }
        let slot = self.my_slot()?;
        let ws = self.ws();
        if ws < self.auditor.sign_floor().max(self.signed_floor) {
            return None; // a previous incarnation's committed head covers these ticks
        }
        let head = self.replica.next_batch_head(self.me)?;
        let inputs = own(ws, end).filter(|i| i.len() as u64 == end - ws)?;
        let b = pack(self.session.match_id, self.me, head, ws, &inputs, &self.key)?;
        self.collect.batches[slot].push(b.clone());
        self.collect.first_seen.get_or_insert(self.clock);
        self.auditor.record_my_batch(&b);
        Some(b)
    }
    /// Remember batches a previous process of this identity signed and released. The ticks they
    /// cover are never signed a second time, so sending them again, unchanged, is the only way to
    /// complete their epochs.
    pub fn restore_own_batches(&mut self, batches: Vec<SignedEventBatch>) {
        self.restorable = batches;
        self.restore_due();
    }
    /// Send again the remembered batches that start at the verified tick.
    pub(super) fn restore_due(&mut self) {
        if self.restorable.is_empty() {
            return;
        }
        let ws = self.ws();
        self.restorable.retain(|b| b.record.start_tick >= ws);
        let Some(slot) = self.my_slot() else { return };
        let due: Vec<SignedEventBatch> = self
            .restorable
            .iter()
            .filter(|b| b.record.start_tick == ws && !self.collect.has_end(slot, end_of(b)))
            .cloned()
            .collect();
        for b in due {
            let extends =
                self.replica.next_batch_head(self.me) == Some(b.record.previous_batch_hash);
            if b.verify().is_ok() && b.record.participant == self.me && extends {
                self.collect.batches[slot].push(b.clone());
                self.enqueue(Outgoing::all(PipeMsg::Batch(b)));
            }
        }
    }
    fn respond(&mut self, end: u64, own: OwnInputs<'_>) {
        let Some(slot) = self.my_slot() else { return };
        if self.collect.has_end(slot, end) {
            return;
        }
        if let Some(b) = self.sign_batch(end, own) {
            self.enqueue(Outgoing::all(PipeMsg::Batch(b)));
        }
    }
    /// An end I may sign: never longer than one I already signed.
    fn may_sign(&self, end: u64) -> bool {
        self.my_slot().is_some_and(|slot| {
            self.collect.batches[slot].is_empty() || Some(end) <= self.collect.min_end(slot)
        })
    }
    fn settle_owed(&mut self, now: u64, own: OwnInputs<'_>) {
        let Some(end) = self.collect.owed.filter(|e| now >= *e) else {
            return;
        };
        self.collect.owed = None;
        if self.may_sign(end) {
            self.respond(end, own);
            self.try_complete(now);
        }
    }
    fn proposal_end(&self, now: u64) -> Option<(u64, bool)> {
        let ws = self.ws();
        let grid = u64::from(self.cfg.epoch_ticks);
        let cut = self.seal_cut();
        let mut end = (now / grid) * grid;
        if let Some(h0) = cut.filter(|h0| now >= *h0) {
            end = h0;
        }
        if end <= ws {
            return None;
        }
        let max = u64::from(self.cfg.max_window);
        let forced = cut == Some(end) || end - ws >= max;
        Some((end.min(ws + max), forced))
    }
    pub(super) fn propose_or_respond(&mut self, now: u64, own: OwnInputs<'_>) {
        if !matches!(self.stage, Stage::Collect) || self.in_sealed_window() || !self.can_submit() {
            return;
        }
        self.settle_owed(now, own);
        if !self.collect.is_empty() {
            return;
        }
        let Some((end, forced)) = self.proposal_end(now) else {
            return;
        };
        let ws = self.ws();
        let active = forced
            || self.cheat_pending
            || own(ws, end).is_some_and(|c| c.iter().any(|x| *x != self.cfg.idle_input));
        if !active {
            return;
        }
        if let Some(b) = self.sign_batch(end, own) {
            self.enqueue(Outgoing::all(PipeMsg::Batch(b)));
            self.try_complete(now);
        }
    }

    // ---- receiving ----------------------------------------------------------

    fn batch_slot(&self, b: &SignedEventBatch) -> Option<usize> {
        let ok = b.verify().is_ok()
            && b.record.match_id == self.session.match_id
            && b.record.participant != self.me
            && b.record.tick_count > 0
            && b.record.tick_count <= self.cfg.max_window;
        ok.then(|| self.session.roster.index_of(&b.record.participant))
            .flatten()
            .filter(|slot| self.submitter_slots().contains(slot))
    }
    pub(super) fn accept_batch(&mut self, b: SignedEventBatch, now: u64, own: OwnInputs<'_>) {
        let Some(slot) = self.batch_slot(&b) else {
            self.fault("rejected malformed batch");
            return;
        };
        self.auditor.observe_batch(&b);
        let ws = self.ws();
        if b.record.start_tick < ws {
            return;
        }
        if b.record.start_tick > ws {
            let cap = FUTURE_PER_MEMBER * self.session.roster.len();
            if self.collect.future.len() < cap {
                self.collect.future.push(b);
            }
            return;
        }
        if self.replica.next_batch_head(b.record.participant) != Some(b.record.previous_batch_hash)
        {
            self.fault("batch does not extend their chain");
            return;
        }
        if self.in_sealed_window() {
            self.fault("public batch inside sealed window");
            return;
        }
        let end = end_of(&b);
        if let Some(existing) = self.collect.get(slot, end) {
            if existing.record != b.record {
                let pair = [existing.clone(), b];
                self.flag_batch_equivocation(&pair, ws);
            }
            return;
        }
        self.events.push_back(PipeEvent::RemoteInputs {
            participant: b.record.participant,
            from_tick: ws,
            inputs: held_inputs(&b),
        });
        self.collect.batches[slot].push(b);
        self.collect.first_seen.get_or_insert(now);
        if matches!(self.stage, Stage::Collect) {
            self.answer_proposal(end, now, own);
            self.try_complete(now);
        }
    }
    fn flag_batch_equivocation(&mut self, pair: &[SignedEventBatch; 2], tick: u64) {
        let mut evidence = Vec::new();
        for x in pair {
            if let Ok(bytes) = x.encode() {
                evidence.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                evidence.extend_from_slice(&bytes);
            }
        }
        self.events.push_back(PipeEvent::Violation(Violation {
            kind: ViolationKind::Equivocation,
            accused: pair[0].record.participant,
            tick,
            evidence,
        }));
    }
    /// Never sign across the start of a sealed window: answer with the identical-prefix batch
    /// that stops at it.
    fn answer_proposal(&mut self, end: u64, now: u64, own: OwnInputs<'_>) {
        if !self.can_submit() {
            return;
        }
        let answer = self.seal_cut().map_or(end, |h0| end.min(h0));
        if !self.may_sign(answer) {
            return;
        }
        if now >= answer {
            self.respond(answer, own);
        } else {
            self.collect.owed = Some(answer);
        }
    }

    // ---- completing an epoch -------------------------------------------------

    pub(super) fn try_complete(&mut self, now: u64) {
        if !matches!(self.stage, Stage::Collect) {
            return;
        }
        let slots = self.submitter_slots();
        let Some(end) = self.collect.common_end(&slots) else {
            return;
        };
        let inputs = self.epoch_inputs(end, &slots);
        self.collect.reset_epoch();
        self.begin_epoch(inputs, false, now);
    }
    fn epoch_inputs(&self, end: u64, slots: &[usize]) -> Vec<Option<SignedEventBatch>> {
        let mut inputs = vec![None; self.session.roster.len()];
        for slot in slots {
            inputs[*slot] = self.collect.get(*slot, end).cloned();
        }
        inputs
    }
    pub(super) fn drain_future(&mut self, now: u64, own: OwnInputs<'_>) {
        if !matches!(self.stage, Stage::Collect) {
            return;
        }
        let ws = self.ws();
        for b in self.collect.take_ready(ws) {
            self.accept_batch(b, now, own);
        }
        self.collect.drop_stale(ws);
    }

    // ---- close: a subset epoch when someone stays silent ----------------------

    fn close_attempt(&self, now: u64) -> Option<u8> {
        let after = self.cfg.close_after_ticks.filter(|a| *a > 0)?;
        let waited = now.checked_sub(self.collect.first_seen?)?;
        let steps = waited / after;
        u8::try_from(steps.checked_sub(1)?).ok()
    }
    /// The signer whose turn it is to decide the epoch's batch set.
    fn coordinator(&self, attempt: u8) -> Option<ParticipantId> {
        let roster = &self.session.roster;
        let signers: Vec<usize> = self
            .session
            .ordering
            .order(roster, self.ws())
            .into_iter()
            .filter(|s| roster.get(*s).is_some_and(|p| p.role.signs()))
            .collect();
        let slot = signers.get(usize::from(attempt) % signers.len().max(1))?;
        roster.get(*slot).map(|p| p.id)
    }
    fn report_silent(&mut self) {
        let ws = self.ws();
        let silent: Vec<ParticipantId> = self
            .submitter_slots()
            .into_iter()
            .filter(|s| self.collect.batches[*s].is_empty())
            .filter_map(|s| self.session.roster.get(s).map(|p| p.id))
            .filter(|id| *id != self.me && !self.collect.reported_silent.contains(id))
            .collect();
        for id in silent {
            self.collect.reported_silent.push(id);
            self.events.push_back(PipeEvent::Suspicion(Suspicion {
                kind: SuspicionKind::Unresponsive,
                subject: id,
                tick: ws,
            }));
        }
    }
    pub(super) fn maybe_close(&mut self, now: u64) {
        if !matches!(self.stage, Stage::Collect) {
            return;
        }
        let Some(attempt) = self.close_attempt(now) else {
            return;
        };
        self.report_silent();
        if self.coordinator(attempt) != Some(self.me) {
            return;
        }
        let present: Vec<usize> = self
            .submitter_slots()
            .into_iter()
            .filter(|s| !self.collect.batches[*s].is_empty())
            .collect();
        let Some(end) = self
            .collect
            .common_end(&present)
            .filter(|end| *end > self.ws())
        else {
            return;
        };
        let batches: Vec<SignedEventBatch> = present
            .iter()
            .filter_map(|s| self.collect.get(*s, end).cloned())
            .collect();
        let close = Close {
            epoch_start: self.ws(),
            tick_count: u32::try_from(end - self.ws()).unwrap_or(0),
            attempt,
            batches,
        };
        self.enqueue(Outgoing::all(PipeMsg::Close(close.clone())));
        self.adopt_close(&close, now);
    }
    pub(super) fn on_close(&mut self, from: ParticipantId, close: Close, now: u64) {
        let legitimate = matches!(self.stage, Stage::Collect)
            && close.epoch_start == self.ws()
            && self.coordinator(close.attempt) == Some(from)
            && self.close_attempt(now).is_some_and(|a| close.attempt <= a);
        if !legitimate {
            self.fault("close rejected");
            return;
        }
        self.adopt_close(&close, now);
    }
    /// Admit exactly the coordinator's batch set. Every batch is its author's own signed
    /// statement, so a coordinator can only choose which submitters are present.
    fn adopt_close(&mut self, close: &Close, now: u64) {
        let slots = self.submitter_slots();
        let mut inputs: Vec<Option<SignedEventBatch>> = vec![None; self.session.roster.len()];
        for b in &close.batches {
            let slot = self.session.roster.index_of(&b.record.participant);
            let fits = b.verify().is_ok()
                && b.record.match_id == self.session.match_id
                && b.record.start_tick == close.epoch_start
                && b.record.tick_count == close.tick_count
                && self.replica.next_batch_head(b.record.participant)
                    == Some(b.record.previous_batch_hash);
            match slot.filter(|s| fits && slots.contains(s) && inputs[*s].is_none()) {
                Some(s) => inputs[s] = Some(b.clone()),
                None => {
                    self.fault("close carries an unusable batch");
                    return;
                }
            }
        }
        if inputs.iter().all(Option::is_none) {
            self.fault("empty close");
            return;
        }
        for b in close
            .batches
            .iter()
            .filter(|b| b.record.participant != self.me)
        {
            self.auditor.observe_batch(b);
            if self
                .collect
                .get_by_participant(&self.session.roster, b)
                .is_none()
            {
                self.events.push_back(PipeEvent::RemoteInputs {
                    participant: b.record.participant,
                    from_tick: close.epoch_start,
                    inputs: held_inputs(b),
                });
            }
        }
        self.collect.reset_epoch();
        self.begin_epoch(inputs, false, now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(key: &SigningKey, start: u64, count: u32) -> SignedEventBatch {
        let record = EventBatch {
            match_id: [1; 32],
            participant: key.id(),
            previous_batch_hash: [0; 32],
            start_tick: start,
            tick_count: count,
            body: EventBody::Held {
                initial: vec![0],
                changes: vec![],
            },
        };
        SignedEventBatch::sign(record, key).unwrap()
    }

    #[test]
    fn a_late_batch_for_a_finished_window_is_dropped_when_the_window_moves_on() {
        let key = SigningKey::from_seed([3; 32]);
        let mut c = Collect::new(1);
        c.batches[0].push(batch(&key, 100, 100));
        c.batches[0].push(batch(&key, 180, 20));
        c.drop_before(180);
        assert_eq!(c.batches[0].len(), 1);
        assert_eq!(c.batches[0][0].record.start_tick, 180);
        assert!(c.has_end(0, 200));
    }
}
