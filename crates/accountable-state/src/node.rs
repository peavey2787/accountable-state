use crate::config::Config;
use crate::evidence::{Context, EvidencePackage, ExportQuery};
use crate::io::{OpenError, Outgoing, Output, Peer, ReceiveError, SubmitError, WitnessOut};
use crate::own::OwnInputs;
use crate::persist::{Persistence, Sink};
use crate::view::{AuthorizedView, ObserverRole, ViewPolicy};
use gv_core::{Digest, MatchId, PlayerId};
use gv_edge::export::{export_audit, export_match, DisclosurePolicy, ExportError};
use gv_edge::feed::SignedEvent;
use gv_edge::live::{HideError, PipeEvent, PipeMsg, Pipeline, PipelineConfig};
use gv_edge::CertifiedMatch;
use gv_replay::{ActionOrdering, StateMachine};
use std::collections::VecDeque;
use std::time::Instant;

/// Certified state and where this node stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateView<'a> {
    /// First tick not yet covered by a certified epoch.
    pub certified_tick: u64,
    pub state: &'a [u8],
    /// Checkpoint hash of the last finalized epoch (`None` before the first).
    pub checkpoint: Option<Digest>,
    /// Next tick [`AccountableState::submit`] will fill.
    pub next_submit: u64,
    /// After a (re)start nothing is signed until the anchor check completes.
    pub anchor_check_pending: bool,
}

/// One participant of an accountable two-party state machine. Sans-IO: the application feeds it
/// local actions and received bytes, and drains [`AccountableState::poll`].
pub struct AccountableState<M: StateMachine + Clone> {
    pub(crate) pipe: Pipeline<M>,
    machine: M,
    match_id: MatchId,
    roster: [PlayerId; 2],
    disclosure: DisclosurePolicy,
    witnesses: bool,
    hide_cooldown_ticks: u64,
    #[cfg(feature = "fault-injection")]
    pub(crate) epoch_ticks: u32,
    pub(crate) now: u64,
    own: OwnInputs,
    checkpoint: Option<Digest>,
    persist: Persistence,
    outgoing: VecDeque<Outgoing>,
    events: VecDeque<PipeEvent>,
}

impl<M: StateMachine + Clone> AccountableState<M> {
    /// Open (or recover) a node. Fails closed: storage that cannot be opened, a resume archive
    /// that does not authenticate, or a key outside the roster is an error, never a weaker mode.
    pub fn open(machine: M, config: Config) -> Result<Self, OpenError> {
        let receipts = config.resume.clone().unwrap_or(CertifiedMatch {
            epochs: Vec::new(),
            disputes: Vec::new(),
            live: true,
        });
        if !receipts.live {
            return Err(OpenError::Recovery(
                "resume needs a live-engine archive".into(),
            ));
        }
        let replica = receipts
            .restore(config.match_id, config.roster, machine.clone())
            .map_err(|e| OpenError::Recovery(format!("{e:?}")))?;
        let start = replica.next_tick();
        let pipe_cfg = PipelineConfig {
            #[cfg(feature = "fault-injection")]
            epoch_ticks: config.epoch_ticks,
            ..PipelineConfig::default()
        };
        let hide_cooldown_ticks = pipe_cfg.hide_cooldown_ticks;
        let mut pipe = Pipeline::new(
            config.key.clone(),
            config.roster,
            config.match_id,
            machine.clone(),
            replica,
            pipe_cfg,
        )
        .ok_or(OpenError::NotInRoster)?;
        for w in &config.witnesses {
            pipe.auditor_mut().admit_witness(*w);
        }
        let mut outgoing = VecDeque::new();
        let mut events = VecDeque::new();
        let witnesses = !config.witnesses.is_empty();
        let mut sink = Sink {
            outgoing: &mut outgoing,
            events: &mut events,
            witnesses,
        };
        let persist = Persistence::open(
            &config.storage,
            &mut pipe,
            &receipts,
            config.key,
            start,
            &mut sink,
        )?;
        Ok(Self {
            pipe,
            machine,
            match_id: config.match_id,
            roster: config.roster,
            disclosure: config.disclosure,
            witnesses,
            hide_cooldown_ticks,
            #[cfg(feature = "fault-injection")]
            epoch_ticks: config.epoch_ticks,
            now: start,
            own: OwnInputs::new(start),
            checkpoint: None,
            persist,
            outgoing,
            events,
        })
    }

    /// Execute one local action at the next tick and propagate it. Returns that tick. An action
    /// the machine says needs a global order is refused: it could never be made final here.
    pub fn submit(&mut self, action: u16) -> Result<u64, SubmitError> {
        if self.machine.ordering(action) == ActionOrdering::RequiresExternalOrdering {
            return Err(SubmitError::RequiresExternalOrdering);
        }
        let tick = self.now;
        self.own.push(action);
        self.now += 1;
        self.drive(|pipe, now, own| pipe.tick(now, own));
        Ok(tick)
    }

    /// Bytes from the opponent's reliable pipeline or from the local witness service.
    pub fn receive(&mut self, from: Peer, bytes: &[u8]) -> Result<(), ReceiveError> {
        let msg = PipeMsg::decode(bytes).map_err(|_| ReceiveError::Malformed)?;
        match (from, msg) {
            (Peer::Opponent, msg) => {
                if let PipeMsg::Auth(a) = &msg {
                    self.queue_for_witness(WitnessOut::Auth(a.clone()));
                }
                self.drive(|pipe, now, own| pipe.on_message(msg, now, own));
            }
            (Peer::Witness, PipeMsg::Anchor(Some(a))) => {
                self.pipe.auditor_mut().on_witness_anchor(&a);
            }
            (Peer::Witness, msg @ PipeMsg::Challenge(_)) => {
                self.drive(|pipe, now, own| pipe.on_message(msg, now, own));
            }
            (Peer::Witness, _) => return Err(ReceiveError::NotAllowedFromWitness),
        }
        Ok(())
    }

    /// The next thing to deliver or report, after time-driven housekeeping. Call until `None`.
    pub fn poll(&mut self, now: Instant) -> Option<Output> {
        let mut sink = Sink {
            outgoing: &mut self.outgoing,
            events: &mut self.events,
            witnesses: self.witnesses,
        };
        self.persist.housekeeping(now, &mut self.pipe, &mut sink);
        self.drain_pipeline(now);
        self.next_output()
    }

    pub fn state(&self) -> StateView<'_> {
        StateView {
            certified_tick: self.pipe.verified_tick(),
            state: self.pipe.verified_state(),
            checkpoint: self.checkpoint,
            next_submit: self.now,
            anchor_check_pending: self.pipe.auditor().anchor_check_pending(),
        }
    }

    /// Signed, numbered, durable events after `cursor` (0 = from the start). Resume with the
    /// last id seen; ids survive restarts.
    pub fn subscribe(&self, cursor: u64, limit: usize) -> Vec<SignedEvent> {
        self.persist.since(cursor, limit)
    }

    pub fn export(&self, query: ExportQuery) -> Result<EvidencePackage, ExportError> {
        let package = match query {
            ExportQuery::MatchArchive => {
                let archive = self.persist.archive().ok_or(ExportError::Invalid)?;
                export_match(
                    &self.machine,
                    self.match_id,
                    self.roster,
                    &archive,
                    self.disclosure,
                )?
            }
            ExportQuery::Fraud(id) => {
                let bytes = self
                    .persist
                    .package(&id)
                    .ok_or(ExportError::UnknownPayload)?;
                return EvidencePackage::decode(bytes);
            }
            ExportQuery::Audit => export_audit(
                &self.machine,
                self.match_id,
                self.roster,
                &self.persist.audit(&self.pipe),
                self.disclosure,
            )?,
        };
        EvidencePackage::new(package)
    }

    /// The certified state as `observer` may see it.
    pub fn view<P: ViewPolicy>(
        &self,
        policy: &P,
        observer: &PlayerId,
        role: ObserverRole,
    ) -> Result<AuthorizedView, String> {
        policy.view_for(self.pipe.verified_state(), observer, role)
    }

    /// Advanced: schedule a hidden window (inputs committed now, revealed later).
    pub fn request_hide(&mut self) -> Result<(), HideError> {
        let now = self.now;
        self.pipe.request_hide(now)?;
        self.drive(|pipe, now, own| pipe.tick(now, own));
        Ok(())
    }

    /// Advanced: ticks between two hide requests.
    pub fn hide_cooldown_ticks(&self) -> u64 {
        self.hide_cooldown_ticks
    }

    /// Write anything buffered (the certified archive) before shutdown.
    pub fn flush(&mut self) {
        let mut sink = Sink {
            outgoing: &mut self.outgoing,
            events: &mut self.events,
            witnesses: self.witnesses,
        };
        self.persist.flush(&mut sink);
    }

    pub(crate) fn drive(
        &mut self,
        step: impl FnOnce(&mut Pipeline<M>, u64, &dyn Fn(u64, u64) -> Option<Vec<u16>>),
    ) {
        let own = &self.own;
        step(&mut self.pipe, self.now, &|from, to| own.range(from, to));
    }

    fn queue_for_witness(&mut self, m: WitnessOut) {
        if self.witnesses {
            self.outgoing.push_back(Outgoing::Witness(m));
        }
    }

    fn drain_pipeline(&mut self, now: Instant) {
        let cx = Context {
            machine: &self.machine,
            match_id: self.match_id,
            roster: self.roster,
            disclosure: self.disclosure,
        };
        while let Some(ev) = self.pipe.poll_event() {
            let mut sink = Sink {
                outgoing: &mut self.outgoing,
                events: &mut self.events,
                witnesses: self.witnesses,
            };
            if let Some(end) = self
                .persist
                .on_event(&ev, &mut self.pipe, &cx, now, &mut sink)
            {
                self.own.release_before(end);
            }
            if let PipeEvent::Finalized { checkpoint, .. } = &ev {
                self.checkpoint = Some(*checkpoint);
            }
            self.events.push_back(ev);
        }
    }

    fn next_output(&mut self) -> Option<Output> {
        if let Some(o) = self.outgoing.pop_front() {
            return Some(Output::Send(o));
        }
        if let Some(r) = self.pipe.auditor_mut().poll_witness_response() {
            if self.witnesses {
                return Some(Output::Send(Outgoing::Witness(WitnessOut::Response(r))));
            }
        }
        if let Some(out) = self.next_message() {
            return Some(out);
        }
        self.events.pop_front().map(Output::Event)
    }

    fn next_message(&mut self) -> Option<Output> {
        let m = self.pipe.poll_outbox()?;
        if let PipeMsg::Auth(a) = &m {
            self.queue_for_witness(WitnessOut::Auth(a.clone()));
        }
        match m.encode() {
            Ok(bytes) => Some(Output::Send(Outgoing::Opponent(bytes))),
            Err(e) => Some(Output::Event(PipeEvent::Fault(format!(
                "encode failed: {e:?}"
            )))),
        }
    }
}
