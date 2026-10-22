//! Optional sealed windows (commit, lock, reveal). One participant may keep its inputs secret for
//! a fixed window; every submitter commits per epoch, the commitment set is locked, and only
//! then are batches opened (everyone else at once, the owner after the window). Public play needs
//! none of this: it exists for games where hidden information is part of the rules.
use super::collect::{held_inputs, pack};
use super::config::OwnInputs;
use super::config::{PipeEvent, SealError, Suspicion, SuspicionKind};
use super::{Pipeline, Stage};
use crate::live::msg::{Opening, Outgoing, PipeMsg, SignedSeal};
use crate::{
    BatchCommitment, EpochAdmission, SignedBatchCommitment, SignedEpochLock, StateMachine,
};
use gv_codec::SignedEventBatch;
use gv_core::{Digest, ParticipantId};
use std::collections::BTreeMap;

/// Buffered messages kept per cell and kind, per roster member.
const PENDING_PER_MEMBER: usize = 2;

pub(super) struct Cell {
    pub(super) start: u64,
    end: u64,
    pub(super) mine: Option<SignedEventBatch>,
    adm: Option<EpochAdmission>,
    /// Every commitment seen, by author (also what challenges about reveals are checked against).
    pub(super) commits: BTreeMap<ParticipantId, SignedBatchCommitment>,
    pending_locks: Vec<SignedEpochLock>,
    /// Commitments already offered to the admission (it verifies each signature once).
    commits_tried: Vec<ParticipantId>,
    /// `(commit_count, pending locks)` at the last lock attempt: a lock can only start matching
    /// when either grows.
    lock_tried_at: (usize, usize),
    pending_reveals: Vec<(ParticipantId, Opening)>,
    /// Secret blinding factor of my commitment (CSPRNG; revealed only with the opening).
    pub(super) blind: [u8; 32],
    my_commit_sent: bool,
    my_lock_sent: bool,
    pub(super) my_reveal_sent: bool,
    done: bool,
}
impl Cell {
    fn new(start: u64, end: u64) -> Self {
        Self {
            start,
            end,
            mine: None,
            adm: None,
            commits: BTreeMap::new(),
            pending_locks: Vec::new(),
            commits_tried: Vec::new(),
            lock_tried_at: (0, 0),
            pending_reveals: Vec::new(),
            blind: gv_sig::random_32().unwrap_or([0; 32]),
            my_commit_sent: false,
            my_lock_sent: false,
            my_reveal_sent: false,
            done: false,
        }
    }
    fn locked(&self) -> bool {
        self.adm.as_ref().is_some_and(EpochAdmission::locked)
    }
}

pub(super) struct Window {
    pub(super) owner: ParticipantId,
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) cells: Vec<Cell>,
    anchor: Option<Digest>,
    /// My latest batch digest inside the window (chain head for the next cell).
    my_head: Option<Digest>,
    reveal_deadline: u64,
    suspected: bool,
}

#[derive(Default)]
pub(super) struct Sealed {
    pub(super) window: Option<Window>,
    /// Earliest tick at which each participant may request another window.
    cooldowns: BTreeMap<ParticipantId, u64>,
}
impl Sealed {
    pub(super) fn cooldown_until(&self, who: &ParticipantId) -> u64 {
        self.cooldowns.get(who).copied().unwrap_or(0)
    }
}

impl<R: StateMachine + Clone> Pipeline<R> {
    pub(super) fn seal_cut(&self) -> Option<u64> {
        let ws = self.ws();
        self.sealed
            .window
            .as_ref()
            .filter(|w| ws < w.start)
            .map(|w| w.start)
    }
    pub(super) fn in_sealed_window(&self) -> bool {
        let ws = self.ws();
        self.sealed
            .window
            .as_ref()
            .is_some_and(|w| ws >= w.start && ws < w.end)
    }
    /// The active window as `(owner, start, end)`.
    pub fn seal_window(&self) -> Option<(ParticipantId, u64, u64)> {
        self.sealed
            .window
            .as_ref()
            .map(|w| (w.owner, w.start, w.end))
    }
    pub fn seal_cooldown_until(&self) -> u64 {
        self.sealed.cooldown_until(&self.me)
    }

    // ---- scheduling -----------------------------------------------------------

    /// Keep my inputs sealed for the policy's window, starting at the next epoch edge.
    pub fn request_seal(&mut self, now: u64) -> Result<(), SealError> {
        let policy = self.cfg.seal.clone().ok_or(SealError::Disabled)?;
        if !self.can_submit() {
            return Err(SealError::NotSubmitter);
        }
        if self.sealed.window.is_some() {
            return Err(SealError::Busy);
        }
        let until = self.sealed.cooldown_until(&self.me);
        if now < until {
            return Err(SealError::Cooldown { until });
        }
        let grid = u64::from(self.cfg.epoch_ticks);
        let start = (now + u64::from(policy.lead_ticks)).div_ceil(grid) * grid;
        let ticks = policy.ticks.div_ceil(self.cfg.epoch_ticks) * self.cfg.epoch_ticks;
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&now.to_le_bytes());
        nonce[8..].copy_from_slice(&start.to_le_bytes());
        let msg = SignedSeal::sign(self.session.match_id, start, ticks, nonce, &self.key);
        self.begin_window(&msg);
        self.enqueue(Outgoing::all(PipeMsg::Seal(msg)));
        Ok(())
    }
    fn begin_window(&mut self, msg: &SignedSeal) {
        let grid = u64::from(self.cfg.epoch_ticks);
        let end = msg.start_tick + u64::from(msg.ticks);
        let reveal_timeout = self.cfg.seal.as_ref().map_or(0, |p| p.reveal_timeout_ticks);
        let cells = (0..u64::from(msg.ticks) / grid)
            .map(|k| Cell::new(msg.start_tick + k * grid, msg.start_tick + (k + 1) * grid))
            .collect();
        self.sealed.window = Some(Window {
            owner: msg.owner,
            start: msg.start_tick,
            end,
            cells,
            anchor: None,
            my_head: None,
            reveal_deadline: end + reveal_timeout,
            suspected: false,
        });
        self.events.push_back(PipeEvent::SealScheduled {
            owner: msg.owner,
            start: msg.start_tick,
            end,
        });
    }
    pub(super) fn on_seal(&mut self, from: ParticipantId, msg: SignedSeal, now: u64) {
        let Some(policy) = self.cfg.seal.clone() else {
            self.fault("sealed window without a policy");
            return;
        };
        let grid = u64::from(self.cfg.epoch_ticks);
        let submits = self
            .session
            .roster
            .find(&msg.owner)
            .is_some_and(|p| p.role.submits());
        let valid = msg.verify().is_ok()
            && msg.owner == from
            && submits
            && msg.match_id == self.session.match_id
            && self.sealed.window.is_none()
            && now >= self.sealed.cooldown_until(&msg.owner)
            && msg.start_tick >= self.ws()
            && msg.start_tick % grid == 0
            && msg.ticks > 0
            && msg.ticks % self.cfg.epoch_ticks == 0
            && msg.ticks <= policy.ticks + self.cfg.epoch_ticks;
        if !valid {
            self.fault("seal announcement rejected");
            return;
        }
        self.begin_window(&msg);
    }

    // ---- receiving --------------------------------------------------------------

    pub(super) fn on_sealed_msg(&mut self, from: ParticipantId, msg: PipeMsg) {
        let cap = PENDING_PER_MEMBER * self.session.roster.len();
        let Some(w) = self.sealed.window.as_mut() else {
            self.fault("sealed-window message with no window");
            return;
        };
        match msg {
            PipeMsg::Commit(c) => {
                if let Some(cell) = w.cells.iter_mut().find(|x| x.start == c.claim.start_tick) {
                    cell.commits.entry(c.claim.participant).or_insert(c);
                }
            }
            PipeMsg::Lock { start_tick, lock } => {
                if let Some(cell) = w.cells.iter_mut().find(|x| x.start == start_tick) {
                    if cell.pending_locks.len() < cap {
                        cell.pending_locks.push(lock);
                    }
                }
            }
            PipeMsg::Reveal(o) => {
                if let Some(cell) = w
                    .cells
                    .iter_mut()
                    .find(|x| x.start == o.batch.record.start_tick)
                {
                    if cell.pending_reveals.len() < cap {
                        cell.pending_reveals.push((from, o));
                    }
                }
            }
            _ => {}
        }
    }

    // ---- driving ------------------------------------------------------------------

    pub(super) fn drive_sealed(&mut self, now: u64, own: OwnInputs<'_>) {
        let Some(mut w) = self.sealed.window.take() else {
            return;
        };
        if w.anchor.is_none() && self.ws() == w.start {
            w.anchor = Some(self.replica.previous_checkpoint());
            w.my_head = self.replica.next_batch_head(self.me);
        }
        if w.anchor.is_some() {
            for k in 0..w.cells.len() {
                self.drive_cell(&mut w, k, now, own);
            }
            if let Some(inputs) = self.revealed_cell(&mut w) {
                self.sealed.window = Some(w);
                self.begin_epoch(inputs, true, now);
                return;
            }
        }
        self.sealed.window = self.finish_or_suspect(w, now);
    }
    fn drive_cell(&mut self, w: &mut Window, k: usize, now: u64, own: OwnInputs<'_>) {
        self.sign_cell_batch(w, k, now, own);
        self.open_admission(w, k, now);
        self.apply_commits(&mut w.cells[k]);
        self.lock_cell(&mut w.cells[k]);
        self.reveal_cell(w, k, now);
        self.apply_reveals(&mut w.cells[k]);
    }
    fn sign_cell_batch(&mut self, w: &mut Window, k: usize, now: u64, own: OwnInputs<'_>) {
        let (start, end) = (w.cells[k].start, w.cells[k].end);
        let prior_signed = k == 0 || w.cells[k - 1].mine.is_some();
        if !self.can_submit() || w.cells[k].mine.is_some() || now < end || !prior_signed {
            return;
        }
        let (Some(head), Some(inputs)) = (w.my_head, own(start, end)) else {
            return;
        };
        if let Some(b) = pack(
            self.session.match_id,
            self.me,
            head,
            start,
            &inputs,
            &self.key,
        ) {
            w.my_head = b.digest().ok();
            w.cells[k].mine = Some(b);
        }
    }
    /// Observers and submitters alike track the cell's admission once it has been played.
    fn open_admission(&mut self, w: &mut Window, k: usize, now: u64) {
        let (Some(anchor), cell) = (w.anchor, &mut w.cells[k]) else {
            return;
        };
        if cell.adm.is_none() && now >= cell.end {
            cell.adm = EpochAdmission::new(
                self.session.clone(),
                self.rules.ruleset_hash(),
                anchor,
                cell.start,
                u32::try_from(cell.end - cell.start).unwrap_or(0),
            )
            .ok();
        }
        if cell.my_commit_sent {
            return;
        }
        let (Some(adm), Some(mine)) = (cell.adm.as_mut(), cell.mine.as_ref()) else {
            return;
        };
        let ruleset = self.rules.ruleset_hash();
        let signed = BatchCommitment::for_batch(mine, ruleset, anchor, &cell.blind)
            .and_then(|claim| SignedBatchCommitment::sign(claim, &self.key));
        if let Ok(commit) = signed {
            if adm.admit_commit(commit.clone()).is_ok() {
                cell.commits.insert(self.me, commit.clone());
                self.enqueue(Outgoing::all(PipeMsg::Commit(commit)));
                cell.my_commit_sent = true;
            }
        }
    }
    /// Feed buffered commitments into the admission; a commitment the admission rejects is not
    /// retried (it can only be a duplicate, a late arrival after the lock, or invalid).
    fn apply_commits(&mut self, cell: &mut Cell) {
        let Some(adm) = cell.adm.as_mut() else { return };
        for (author, commit) in &cell.commits {
            if *author != self.me && !cell.commits_tried.contains(author) {
                cell.commits_tried.push(*author);
                // A rejected commitment (late, duplicate, invalid) is simply not part of the set.
                let _ = adm.admit_commit(commit.clone());
            }
        }
    }
    fn lock_cell(&mut self, cell: &mut Cell) {
        let submitters = self.session.roster.submitters().len();
        let Some(adm) = cell.adm.as_mut() else { return };
        if self.can_submit() && !cell.my_lock_sent && adm.commit_count() == submitters {
            if let Ok(lock) = adm.sign_lock(&self.key) {
                if adm.admit_lock(lock.clone()).is_ok() {
                    self.enqueue(Outgoing::all(PipeMsg::Lock {
                        start_tick: cell.start,
                        lock,
                    }));
                    cell.my_lock_sent = true;
                }
            }
        }
        if (adm.commit_count(), cell.pending_locks.len()) != cell.lock_tried_at {
            cell.pending_locks
                .retain(|l| adm.admit_lock(l.clone()).is_err() && l.verify().is_ok());
            cell.lock_tried_at = (adm.commit_count(), cell.pending_locks.len());
        }
    }
    fn reveal_cell(&mut self, w: &mut Window, k: usize, now: u64) {
        let i_own = w.owner == self.me;
        let all_locked = w.cells.iter().all(Cell::locked);
        let window_over = now >= w.end;
        let cell = &mut w.cells[k];
        if !cell.locked() || cell.my_reveal_sent || (i_own && !(window_over && all_locked)) {
            return;
        }
        let (Some(b), Some(adm)) = (cell.mine.clone(), cell.adm.as_mut()) else {
            return;
        };
        // Our own opening counts toward the certified set too.
        if adm.admit_reveal(b.clone(), &cell.blind).is_ok() {
            self.enqueue(Outgoing::all(PipeMsg::Reveal(Opening {
                batch: b,
                blind: cell.blind,
            })));
            cell.my_reveal_sent = true;
        }
    }
    fn apply_reveals(&mut self, cell: &mut Cell) {
        if !cell.locked() {
            return;
        }
        for (from, o) in std::mem::take(&mut cell.pending_reveals) {
            let Some(adm) = cell.adm.as_mut() else { return };
            match adm.admit_reveal(o.batch.clone(), &o.blind) {
                Ok(()) => self.events.push_back(PipeEvent::RemoteInputs {
                    participant: o.batch.record.participant,
                    from_tick: cell.start,
                    inputs: held_inputs(&o.batch),
                }),
                Err(crate::AdmissionError::Duplicate) => {}
                Err(_) => self.events.push_back(PipeEvent::Suspicion(Suspicion {
                    kind: SuspicionKind::BadReveal,
                    subject: from,
                    tick: cell.start,
                })),
            }
        }
    }

    // ---- certifying revealed cells in order ---------------------------------------

    /// The next cell in order, once every committer has revealed it.
    fn revealed_cell(&mut self, w: &mut Window) -> Option<Vec<Option<SignedEventBatch>>> {
        if !matches!(self.stage, Stage::Collect) {
            return None;
        }
        let ws = self.ws();
        let cell = w.cells.iter_mut().find(|c| c.start == ws && !c.done)?;
        let inputs = cell.adm.as_ref()?.ordered_reveals().ok()?;
        cell.done = true;
        Some(inputs)
    }
    fn finish_or_suspect(&mut self, mut w: Window, now: u64) -> Option<Window> {
        let complete = w.cells.iter().all(|c| c.done)
            && matches!(self.stage, Stage::Collect)
            && self.ws() >= w.end;
        if complete {
            let cooldown = self.cfg.seal.as_ref().map_or(0, |p| p.cooldown_ticks);
            self.sealed.cooldowns.insert(w.owner, now + cooldown);
            self.events
                .push_back(PipeEvent::SealRevealed { owner: w.owner });
            return None;
        }
        if !w.suspected && now > w.reveal_deadline && w.owner != self.me {
            w.suspected = true;
            self.events.push_back(PipeEvent::Suspicion(Suspicion {
                kind: SuspicionKind::WithheldReveal,
                subject: w.owner,
                tick: w.end,
            }));
        }
        Some(w)
    }
}
