use crate::config::{Config, WitnessMode};
use crate::evidence::{Context, EvidencePackage, ExportQuery};
use crate::ingress::{Ingress, IngressLimits};
use crate::io::{OpenError, Outgoing, Output, Peer, ReceiveError, SubmitError, WitnessOut};
use crate::own::OwnInputs;
use crate::persist::{Persistence, Sink};
use crate::view::{AuthorizedView, ObserverRole, ViewPolicy};
use gv_core::{Digest, ParticipantId, Session};
use gv_edge::export::{export_audit, export_match, DisclosurePolicy, ExportError};
use gv_edge::feed::SignedEvent;
use gv_edge::live::{PipeEvent, PipeMsg, Pipeline, SealError};
use gv_edge::quorum::WitnessSet;
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
    /// Witness-quorum recovery has not yet read a quorum: nothing is signed, and nothing
    /// resumes on a timeout.
    pub recovery_blocked: bool,
}

/// One participant of an accountable state machine shared by a roster. Sans-IO: the application feeds it
/// local actions and received bytes, and drains [`AccountableState::poll`].
pub struct AccountableState<M: StateMachine + Clone> {
    pub(crate) pipe: Pipeline<M>,
    machine: M,
    session: Session,
    disclosure: DisclosurePolicy,
    witnesses: bool,
    width: usize,
    #[cfg(feature = "fault-injection")]
    pub(crate) epoch_ticks: u32,
    pub(crate) now: u64,
    own: OwnInputs,
    checkpoint: Option<Digest>,
    persist: Persistence,
    outgoing: VecDeque<Outgoing>,
    events: VecDeque<PipeEvent>,
    ingress: Ingress,
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
            .restore(config.session.clone(), machine.clone())
            .map_err(|e| OpenError::Recovery(format!("{e:?}")))?;
        let start = replica.next_tick();
        let width = config.pipeline.idle_input.len();
        #[cfg(feature = "fault-injection")]
        let epoch_ticks = config.pipeline.epoch_ticks;
        let mut pipe = Pipeline::new(config.key.clone(), replica, config.pipeline)
            .ok_or(OpenError::NotInRoster)?;
        pipe.set_incarnation(crate::incarnation::next(&config.storage)?);
        for w in &config.witnesses {
            pipe.auditor_mut().admit_witness(*w);
        }
        let quorum = match config.witness_mode {
            WitnessMode::PeersOnly => None,
            WitnessMode::Quorum => Some(WitnessSet::new(&config.witnesses).ok_or_else(|| {
                OpenError::Witnesses("quorum mode needs 1..=31 distinct witnesses".into())
            })?),
        };
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
            quorum,
            &mut sink,
        )?;
        Ok(Self {
            pipe,
            machine,
            session: config.session,
            disclosure: config.disclosure,
            witnesses,
            width,
            #[cfg(feature = "fault-injection")]
            epoch_ticks,
            now: start,
            own: OwnInputs::new(start),
            checkpoint: None,
            persist,
            outgoing,
            events,
            ingress: Ingress::new(IngressLimits::default()),
        })
    }

    /// Execute one local action at the next tick and propagate it. Returns that tick. An action
    /// the machine says needs a global order is refused: it could never be made final here.
    pub fn submit(&mut self, action: &[u8]) -> Result<u64, SubmitError> {
        if action.len() != self.width {
            return Err(SubmitError::WrongWidth {
                expected: self.width,
            });
        }
        if self.machine.ordering(action) == ActionOrdering::RequiresExternalOrdering {
            return Err(SubmitError::RequiresExternalOrdering);
        }
        let tick = self.now;
        self.own.push(action.to_vec());
        self.now += 1;
        self.drive(|pipe, now, own| pipe.tick(now, own));
        Ok(tick)
    }

    /// Bytes from a member's reliable pipeline or from a pinned witness service.
    pub fn receive(&mut self, from: Peer, bytes: &[u8]) -> Result<(), ReceiveError> {
        self.ingress.admit(from, bytes)?;
        let msg = PipeMsg::decode(bytes).map_err(|_| ReceiveError::Malformed)?;
        match (from, msg) {
            (Peer::Member(id), msg) => {
                if let PipeMsg::Auth(a) = &msg {
                    self.queue_for_witness(WitnessOut::Auth(Box::new(a.clone())));
                }
                self.drive(|pipe, now, own| pipe.on_message(id, msg, now, own));
            }
            (Peer::Witness(_), PipeMsg::Anchor(Some(a))) => {
                self.pipe.auditor_mut().on_witness_anchor(&a);
            }
            (Peer::Witness(id), msg @ (PipeMsg::Challenge(_) | PipeMsg::Quorum(_))) => {
                self.drive(|pipe, now, own| pipe.on_message(id, msg, now, own));
            }
            (Peer::Witness(_), _) => return Err(ReceiveError::NotAllowedFromWitness),
        }
        Ok(())
    }

    /// Replace the per-peer ingress budget (defaults suit a real-time game).
    pub fn set_ingress_limits(&mut self, limits: IngressLimits) {
        self.ingress.set_limits(limits);
    }

    /// The transport connected to roster member `id` (first time or again): ask it to prove its
    /// key and incarnation, then both sides sync certified epochs.
    pub fn peer_up(&mut self, id: ParticipantId) {
        self.pipe.peer_up(id);
    }

    /// The transport lost roster member `id`. Starts its grace period; nothing is concluded.
    pub fn peer_down(&mut self, id: ParticipantId) {
        self.pipe.peer_down(id, self.now);
    }

    /// The next thing to deliver or report, after time-driven housekeeping. Call until `None`.
    pub fn poll(&mut self, now: Instant) -> Option<Output> {
        self.ingress.advance(now);
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
            recovery_blocked: self.pipe.auditor().recovery_blocked(),
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
                export_match(&self.machine, &self.session, &archive, self.disclosure)?
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
                &self.session,
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
        observer: &ParticipantId,
        role: ObserverRole,
    ) -> Result<AuthorizedView, String> {
        policy.view_for(self.pipe.verified_state(), observer, role)
    }

    /// Optional: keep this participant's inputs sealed for the configured window (committed
    /// now, revealed after it). Refused unless the pipeline configuration has a seal policy.
    pub fn request_seal(&mut self) -> Result<(), SealError> {
        let now = self.now;
        self.pipe.request_seal(now)?;
        self.drive(|pipe, now, own| pipe.tick(now, own));
        Ok(())
    }

    /// First tick at which this participant may request another sealed window.
    pub fn seal_cooldown_until(&self) -> u64 {
        self.pipe.seal_cooldown_until()
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
        step: impl FnOnce(&mut Pipeline<M>, u64, &dyn Fn(u64, u64) -> Option<Vec<Vec<u8>>>),
    ) {
        let own = &self.own;
        step(&mut self.pipe, self.now, &|from, to| own.range(from, to));
    }

    /// A synced epoch can end beyond what this node has played (it was away): continue from
    /// there, with no stale local inputs.
    fn adopt_synced_tick(&mut self, end: u64) {
        if end > self.now {
            self.now = end;
            self.own = OwnInputs::new(end);
        }
    }

    fn queue_for_witness(&mut self, m: WitnessOut) {
        if self.witnesses {
            self.outgoing.push_back(Outgoing::Witness(m));
        }
    }

    fn drain_pipeline(&mut self, now: Instant) {
        let cx = Context {
            machine: &self.machine,
            session: &self.session,
            disclosure: self.disclosure,
        };
        let mut synced_to = 0;
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
            if let PipeEvent::Finalized {
                checkpoint, end, ..
            } = &ev
            {
                self.checkpoint = Some(*checkpoint);
                synced_to = synced_to.max(*end);
            }
            self.events.push_back(ev);
        }
        self.adopt_synced_tick(synced_to);
    }

    fn next_output(&mut self) -> Option<Output> {
        if let Some(o) = self.outgoing.pop_front() {
            return Some(Output::Send(o));
        }
        if let Some((to, msg)) = self.pipe.auditor_mut().poll_quorum() {
            return Some(Output::Send(Outgoing::Witness(WitnessOut::Quorum {
                to,
                msg: Box::new(msg),
            })));
        }
        if let Some(r) = self.pipe.auditor_mut().poll_witness_response() {
            if self.witnesses {
                return Some(Output::Send(Outgoing::Witness(WitnessOut::Response(
                    Box::new(r),
                ))));
            }
        }
        if let Some(out) = self.next_message() {
            return Some(out);
        }
        self.events.pop_front().map(Output::Event)
    }

    fn next_message(&mut self) -> Option<Output> {
        let out = self.pipe.poll_outbox()?;
        if let PipeMsg::Auth(a) = &out.msg {
            self.queue_for_witness(WitnessOut::Auth(Box::new(a.clone())));
        }
        match out.msg.encode() {
            Ok(bytes) => Some(Output::Send(Outgoing::Member { to: out.to, bytes })),
            Err(e) => Some(Output::Event(PipeEvent::Fault(format!(
                "encode failed: {e:?}"
            )))),
        }
    }
}
