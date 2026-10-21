//! The real-time match: a 60 Hz deterministic simulation that never waits for
//! the network or for cryptography, plus an independent pipeline task that
//! signs, replays and co-certifies it a few hundred milliseconds behind.
//!
//! ```text
//!   UI ──controls──▶ sim loop (60 Hz) ──inputs──▶ pipeline task (ML-DSA-65, replay,
//!                      │  ▲                          Merkle, checkpoints, fraud, hide)
//!        input stream  │  │ rollback / rebase / verdicts
//!        (lossy, 20 Hz)▼  │
//!                    P2P session (Hydra + p2p-net) ◀── reliable epoch messages
//! ```
use crate::bounded::Outbox;
use crate::ui::{ArenaUi, HideView};
use crate::witness_net::{spawn_player_hub, HubIn, LinkSpec};
use gv_core::{MatchId, PlayerId};
use gv_edge::audit::journal::{FileTrustStore, TrustStore};
use gv_edge::audit::store::RecordFile;
use gv_edge::export::ExportEvent;
use gv_edge::feed::{FeedStore, SignedFeed};
use gv_edge::{
    live::{
        AdvanceError, PipeEvent, PipeMsg, Pipeline, PipelineConfig, StreamFrame, StreamSender,
        Timeline, ViolationKind, TICK_HZ,
    },
    ArchiveBuilder, ArenaRules, ArenaState, CertifiedEpoch, CertifiedMatch, CheckpointEvidence,
    FraudBundle,
};
use gv_p2p::native::{Incoming, LiveLink, LiveSession, SessionSender};
use gv_sig::SigningKey;
use std::{
    collections::VecDeque,
    fs,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use tokio::{
    sync::mpsc::{self, Receiver, Sender},
    time::MissedTickBehavior,
};

const TICK: Duration = Duration::from_nanos(1_000_000_000 / TICK_HZ as u64);
/// Session-level control message (not a pipeline message): "tick 0 is now".
const GO: u8 = 0xE0;
/// Ticks the simulation may run ahead of the opponent's confirmed input.
const MAX_PREDICT_TICKS: u64 = 180;
const STREAM_KEEPALIVE_TICKS: u64 = 60;
const STREAM_RESEND_TICKS: u64 = 4;

pub struct GameConfig {
    pub initiator: bool,
    pub key: SigningKey,
    pub roster: [PlayerId; 2],
    pub match_id: MatchId,
    pub epoch_ticks: u32,
    /// Headless mode: scripted inputs, stop after this many certified epochs.
    pub headless_epochs: Option<usize>,
    /// Request a hide at this tick (headless/demo).
    pub hide_at: Option<u64>,
    /// Sign a false checkpoint / an illegal control word at this tick (demo).
    pub cheat_at: Option<u64>,
    pub illegal_at: Option<u64>,
    /// Demo: sign two conflicting log heads at this tick (provable equivocation).
    pub equivocate_at: Option<u64>,
    /// Demo: stop answering audit challenges for 10 s from this tick (suspicion, then cleared).
    pub withhold_at: Option<u64>,
    /// Demo: frame the opponent with forged evidence and a false missing-batch claim.
    pub accuse_falsely_at: Option<u64>,
    pub artifact_path: String,
    pub resume: Option<CertifiedMatch>,
    /// Pinned third-party witnesses (optional; a 1v1 match needs none).
    pub witness_links: Vec<LinkSpec>,
    pub witness_keys: Vec<PlayerId>,
}

/// A store that always fails: used when the journal cannot be opened, so nothing signed can ever
/// leave the process (fail closed).
struct NoStore;
impl TrustStore for NoStore {
    fn commit(
        &mut self,
        _: &gv_edge::audit::AuditLog,
        _: &[gv_edge::audit::Authenticator],
    ) -> std::io::Result<()> {
        Err(std::io::Error::other("write-ahead journal unavailable"))
    }
}

/// Build a `GV-EVIDENCE-PACKAGE/V1` fraud witness for an observed violation, if the evidence is
/// self-sufficient (false-checkpoint bundles need the certified history, which is only present
/// while the archive is complete).
fn fraud_package(
    pipe: &Pipeline<ArenaRules>,
    kind: ViolationKind,
    raw: &[u8],
    bytes: &[u8],
) -> Option<(Vec<u8>, gv_edge::export::Commitment)> {
    use gv_edge::export::{export_fraud, DisclosurePolicy, FraudWitness};
    let roster = pipe.replica().roster;
    let rules = ArenaRules::new(roster);
    let policy = DisclosurePolicy::PUBLIC;
    let match_id = pipe.match_id();
    let pkg = match kind {
        ViolationKind::FalseCheckpoint => {
            let bundle = FraudBundle::decode(bytes).ok()?;
            export_fraud(
                &rules,
                match_id,
                roster,
                FraudWitness::FalseCheckpoint(&bundle),
                policy,
            )
        }
        _ => {
            let ev = CheckpointEvidence::decode(raw).ok()?;
            export_fraud(
                &rules,
                match_id,
                roster,
                FraudWitness::IllegalInput(&ev),
                policy,
            )
        }
    }
    .ok()?;
    let commitment = pkg.commitment();
    Some((pkg.encode().ok()?, commitment))
}

/// Package and commitment for a proven equivocation.
fn equivocation_package(
    pipe: &Pipeline<ArenaRules>,
    evidence: &[u8],
) -> Option<(Vec<u8>, gv_edge::export::Commitment)> {
    use gv_edge::export::{export_fraud, DisclosurePolicy, FraudWitness};
    let ev = gv_edge::audit::Evidence::decode(evidence).ok()?;
    let roster = pipe.replica().roster;
    let pkg = export_fraud(
        &ArenaRules::new(roster),
        pipe.match_id(),
        roster,
        FraudWitness::Equivocation(&ev),
        DisclosurePolicy::PUBLIC,
    )
    .ok()?;
    let commitment = pkg.commitment();
    Some((pkg.encode().ok()?, commitment))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn atomic_save(path: &str, data: &[u8]) -> Result<(), String> {
    let tmp = format!("{path}.pending");
    fs::write(&tmp, data).map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| format!("rename: {e}"))
}

/// Deterministic scripted input for headless runs: a short press every 45 ticks.
fn bot_controls(index: usize, tick: u64) -> u16 {
    use gv_edge::arena::{ATTACK, DOWN, LEFT, RIGHT, UP};
    let moves = [UP, RIGHT, ATTACK, DOWN, LEFT, ATTACK];
    if tick % 45 < 6 {
        moves[((tick / 45) as usize + index) % moves.len()]
    } else {
        0
    }
}

// ---------------------------------------------------------------- pipeline

enum PipeIn {
    Control(u16),
    Net(Box<PipeMsg>),
    Hide,
    Cheat,
    Equivocate,
    Withhold,
    AccuseFalsely,
}

/// Reliable messages awaiting room in the transport queue.
const NET_HOLD: usize = 4096;
/// Pipeline inputs / events in flight between tasks.
const PIPE_CHANNEL: usize = 4096;
const PIPE_HOLD: usize = 65_536;
const EVENT_CHANNEL: usize = 1024;
const EVENT_HOLD: usize = 8192;
const HUB_HOLD: usize = 8192;

fn pump(net: &SessionSender, hold: &mut VecDeque<Vec<u8>>) {
    while let Some(b) = hold.pop_front() {
        if let Err(b) = net.try_send_reliable(b) {
            hold.push_front(b);
            break;
        }
    }
}

/// Pipeline → app events. Snapshots are provisional (the next replaces them); everything else
/// (violations, faults, evidence) is required and never dropped.
struct EventOut(std::sync::Mutex<Outbox<PipeEvent>>);
impl EventOut {
    fn new(tx: Sender<PipeEvent>) -> Self {
        Self(std::sync::Mutex::new(Outbox::new(tx, EVENT_HOLD)))
    }
    fn send(&self, ev: PipeEvent) {
        let mut o = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if matches!(ev, PipeEvent::Audit(gv_edge::live::AuditEvent::Snapshot(_))) {
            o.push_or_replace(ev, |q, _| {
                matches!(q, PipeEvent::Audit(gv_edge::live::AuditEvent::Snapshot(_)))
            });
        } else {
            o.push_required(ev);
        }
    }
    fn flush(&self) {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).flush();
    }
    fn has_room(&self) -> bool {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).has_room(0)
    }
}

/// Pipeline → witness hub. A newer head for the same owner replaces a queued one (heads are
/// cumulative); evidence, packages and challenge responses are required.
struct HubOut(std::sync::Mutex<Outbox<HubIn>>);
impl HubOut {
    fn new(tx: Sender<HubIn>) -> Self {
        Self(std::sync::Mutex::new(Outbox::new(tx, HUB_HOLD)))
    }
    fn send(&self, m: HubIn) {
        let mut o = self.0.lock().unwrap_or_else(|p| p.into_inner());
        match m {
            HubIn::Auth(_) => o.push_or_replace(m, |q, n| match (q, n) {
                (HubIn::Auth(a), HubIn::Auth(b)) => a.owner == b.owner && b.seq >= a.seq,
                _ => false,
            }),
            m => o.push_required(m),
        }
    }
    fn flush(&self) {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).flush();
    }
}

/// Owns the signing key and the verified replica. All cryptography and replay
/// happens here, off the 60 Hz path, and reports back only through `out`.
#[allow(clippy::too_many_arguments)]
async fn pipeline_task(
    mut pipe: Pipeline<ArenaRules>,
    start_tick: u64,
    mut input: Receiver<PipeIn>,
    out: EventOut,
    net: SessionSender,
    artifact_path: String,
    receipts: CertifiedMatch,
    hub: Option<HubOut>,
    witnesses: Vec<PlayerId>,
    key: SigningKey,
) {
    for w in &witnesses {
        pipe.auditor_mut().admit_witness(*w);
    }
    let mut log: VecDeque<u16> = VecDeque::new();
    let mut log_from = start_tick;
    let mut now = start_tick;
    let mut archive_complete = true;
    let mut dispute_proof: Option<CheckpointEvidence> = None;
    let mut evidence_files = 0u32;
    let mut evidence_bytes = 0u64;
    let mut persist_ok = true;
    let mut last_snapshot = Instant::now();
    let mut last_log_save = Instant::now();
    let ledger_path = format!("{artifact_path}.evidence-ledger");
    let durable = gv_edge::audit::durable::Durable::new(&artifact_path);
    let mut ledger_file = match RecordFile::open(std::path::Path::new(&ledger_path)) {
        Ok((f, recovered)) => {
            // Crash recovery: re-verify persisted evidence and adopt the write-ahead journal
            // (snapshot + journal replay). Everything this player signed was durable before it
            // left the process, so the journalled heads are valid anchors.
            let me = pipe.auditor().log().owner();
            match FileTrustStore::open(&artifact_path, pipe.match_id(), me) {
                Ok((store, loaded)) => {
                    let top = loaded.heads.iter().map(|h| h.seq).max().unwrap_or(0);
                    let log = loaded.log.ok();
                    let len = log.as_ref().map_or(0, |l| l.len());
                    let mut anchors: Vec<_> = durable
                        .load_pins()
                        .ok()
                        .unwrap_or_default()
                        .items()
                        .to_vec();
                    anchors.extend(loaded.heads);
                    let report = pipe.auditor_mut().restore(log, &anchors, &recovered);
                    pipe.auditor_mut().attach_store(Box::new(store), len, top);
                    // State loss is only detectable against heads held elsewhere: always ask the
                    // opponent and the witnesses before signing anything after a (re)start.
                    pipe.auditor_mut().require_anchor_check();
                    if !report.recovery.may_sign() {
                        out.send(PipeEvent::Fault(format!(
                            "audit recovery not trusted: {:?}",
                            report.recovery
                        )));
                    }
                }
                Err(e) => {
                    out.send(PipeEvent::Fault(format!(
                        "cannot open write-ahead trust journal: {e}; signing is disabled"
                    )));
                    persist_ok = false;
                    // Fail closed: without the journal nothing signed could be made durable.
                    pipe.auditor_mut().attach_store(Box::new(NoStore), 0, 0);
                }
            }
            if let Some(cs) = durable.load_challenges().ok() {
                pipe.auditor_mut().resume_challenges(&cs, start_tick);
            }
            Some(f)
        }
        Err(e) => {
            out.send(PipeEvent::Fault(format!(
                "cannot open evidence ledger: {e}"
            )));
            persist_ok = false;
            None
        }
    };
    // Receipts are appended (each epoch encoded once) and written at most once a
    // second: re-encoding and rewriting the whole archive per epoch is quadratic
    // and showed up as finality latency that grew with every epoch.
    let mut archive = match ArchiveBuilder::new(&receipts) {
        Ok(b) => b,
        Err(e) => {
            out.send(PipeEvent::Fault(format!(
                "cannot start receipt archive: {e:?}"
            )));
            return;
        }
    };
    let mut net_hold: VecDeque<Vec<u8>> = VecDeque::new();
    // Authenticated, persistent evidence stream (`<artifact>.feed`): every event is signed,
    // numbered and synced before any subscriber sees it. Checkpoint announcements are
    // provisional (the archive holds every epoch) and sent at most every few seconds.
    let mut feed = match FeedStore::open(
        std::path::Path::new(&format!("{artifact_path}.feed")),
        key,
        pipe.match_id(),
    ) {
        Ok(store) => Some(SignedFeed::new(store)),
        Err(e) => {
            out.send(PipeEvent::Fault(format!("cannot open evidence feed: {e}")));
            None
        }
    };
    let mut last_checkpoint_event: Option<Instant> = None;
    let publish = |feed: &mut Option<SignedFeed>, ev: ExportEvent| {
        if let Some(f) = feed.as_mut() {
            if let Err(e) = f.publish(ev) {
                out.send(PipeEvent::Fault(format!("cannot persist feed event: {e}")));
            }
        }
    };
    let mut dirty = false;
    let mut last_save = Instant::now();
    let mut flush = tokio::time::interval(Duration::from_millis(500));
    flush.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        let item = tokio::select! {
            item = input.recv(), if out.has_room() => match item {
                Some(item) => item,
                None => break,
            },
            _ = flush.tick() => {
                if dirty && last_save.elapsed() >= Duration::from_secs(1) {
                    if let Err(e) = atomic_save(&artifact_path, archive.as_bytes()) {
                        out.send(PipeEvent::Fault(format!("cannot save receipts: {e}")));
                    }
                    dirty = false;
                    last_save = Instant::now();
                }
                continue;
            }
        };
        if let PipeIn::Control(c) = &item {
            log.push_back(*c);
            now += 1;
        }
        let own = |from: u64, to: u64| -> Option<Vec<u16>> {
            if from < log_from || to > log_from + log.len() as u64 || from > to {
                return None;
            }
            Some((from..to).map(|t| log[(t - log_from) as usize]).collect())
        };
        match item {
            PipeIn::Control(_) => pipe.tick(now, &own),
            PipeIn::Net(msg) => {
                if let (Some(h), PipeMsg::Auth(a)) = (&hub, &*msg) {
                    h.send(HubIn::Auth(a.clone()));
                }
                pipe.on_message(*msg, now, &own);
            }
            PipeIn::Hide => {
                if let Err(e) = pipe.request_hide(now) {
                    out.send(PipeEvent::Fault(format!("hide refused: {e:?}")));
                }
                pipe.tick(now, &own);
            }
            PipeIn::Cheat => pipe.inject_cheat(),
            PipeIn::Equivocate => pipe.auditor_mut().equivocate_next_authenticator(),
            PipeIn::Withhold => pipe.auditor_mut().withhold_answers_until(now + 600),
            PipeIn::AccuseFalsely => {
                let last = pipe.last_peer_checkpoint().cloned();
                if let Some(c) = last {
                    pipe.auditor_mut().send_forged_accusation(&c);
                }
                let at = pipe.replica().next_tick().saturating_sub(1);
                pipe.auditor_mut().accuse_missing_batch(at / 20 * 20, now);
            }
        }
        if let Some(h) = &hub {
            while let Some(r) = pipe.auditor_mut().poll_witness_response() {
                h.send(HubIn::Response(r));
            }
        }
        pump(&net, &mut net_hold);
        out.flush();
        if let Some(h) = &hub {
            h.flush();
        }
        // Backpressure: while the link cannot take more, signed output stays queued in the
        // pipeline (already durable), instead of growing a second unbounded queue here.
        while net_hold.len() < NET_HOLD {
            let Some(m) = pipe.poll_outbox() else { break };
            if let (Some(h), PipeMsg::Auth(a)) = (&hub, &m) {
                h.send(HubIn::Auth(a.clone()));
            }
            match m.encode() {
                Ok(bytes) => net_hold.push_back(bytes),
                Err(e) => {
                    out.send(PipeEvent::Fault(format!("encode failed: {e:?}")));
                }
            }
        }
        if last_snapshot.elapsed() >= Duration::from_millis(500) {
            last_snapshot = Instant::now();
            let mut stats = pipe.auditor().stats();
            stats.evidence_files = evidence_files;
            stats.evidence_bytes = evidence_bytes;
            stats.persist_ok = persist_ok;
            out.send(PipeEvent::Audit(gv_edge::live::AuditEvent::Snapshot(stats)));
        }
        if last_log_save.elapsed() >= Duration::from_secs(5) {
            last_log_save = Instant::now();
            if durable
                .save_challenges(&pipe.auditor().open_challenges())
                .is_err()
            {
                persist_ok = false;
            }
        }
        if let Some(pins) = pipe.auditor_mut().take_dirty_pins() {
            if durable.save_pins(pins).is_err() {
                persist_ok = false;
            }
        }
        while let Some(ev) = pipe.poll_event() {
            match &ev {
                PipeEvent::Audit(gv_edge::live::AuditEvent::ProvenEquivocation {
                    evidence,
                    ..
                }) => {
                    if let Some(h) = &hub {
                        h.send(HubIn::Evidence(evidence.clone()));
                    }
                    if let (Some((pkg, commitment)), Ok(parsed)) = (
                        equivocation_package(&pipe, evidence),
                        gv_edge::audit::Evidence::decode(evidence),
                    ) {
                        let _ = fs::write(
                            format!(
                                "{artifact_path}.equivocation-{}.package",
                                hex(&commitment.id[..4])
                            ),
                            &pkg,
                        );
                        publish(
                            &mut feed,
                            ExportEvent::Evidence {
                                accused: parsed.accused(),
                                commitment,
                            },
                        );
                    }
                    if let Some(f) = ledger_file.as_mut() {
                        match f.append(evidence) {
                            Ok(()) => evidence_bytes += evidence.len() as u64,
                            Err(_) => persist_ok = false,
                        }
                    }
                }
                PipeEvent::Audit(gv_edge::live::AuditEvent::Challenge { id, status, .. }) => {
                    publish(
                        &mut feed,
                        ExportEvent::Audit {
                            challenge: *id,
                            status: *status,
                        },
                    );
                }
                PipeEvent::Finalized {
                    disputed,
                    end,
                    start,
                    checkpoint,
                    ..
                } => {
                    if !*disputed
                        && last_checkpoint_event
                            .is_none_or(|t| t.elapsed() >= Duration::from_secs(5))
                    {
                        last_checkpoint_event = Some(Instant::now());
                        publish(
                            &mut feed,
                            ExportEvent::Checkpoint {
                                epoch_start: *start,
                                hash: *checkpoint,
                            },
                        );
                    }
                    if *disputed {
                        // A disputed epoch has no dual signature. It is recorded as an explicit
                        // gap carrying the fraud proof, and the next certified epoch links to
                        // the honestly replayed result, so the archive continues past it. Only
                        // an epoch with no checkable proof ends the exportable chain.
                        match dispute_proof
                            .take()
                            .filter(|p| p.accused.claim.epoch_start == *start)
                        {
                            Some(proof) if archive_complete => {
                                if let Err(e) = archive.push_dispute(&proof) {
                                    out.send(PipeEvent::Fault(format!(
                                        "cannot record disputed epoch: {e:?}"
                                    )));
                                    archive_complete = false;
                                }
                                dirty = true;
                                pipe.prune_history(2);
                            }
                            _ => archive_complete = false,
                        }
                    } else if archive_complete {
                        if let Some(last) = pipe.replica().accepted().last() {
                            match CertifiedEpoch::from_accepted(last, pipe.replica().roster) {
                                Ok(cert) => {
                                    if let Err(e) = archive.push(&cert) {
                                        out.send(PipeEvent::Fault(format!(
                                            "cannot encode receipts: {e:?}"
                                        )));
                                    }
                                    dirty = true;
                                    pipe.prune_history(2);
                                    if last_save.elapsed() >= Duration::from_secs(1) {
                                        if let Err(e) =
                                            atomic_save(&artifact_path, archive.as_bytes())
                                        {
                                            out.send(PipeEvent::Fault(format!(
                                                "cannot save receipts: {e}"
                                            )));
                                        }
                                        dirty = false;
                                        last_save = Instant::now();
                                    }
                                }
                                Err(e) => {
                                    out.send(PipeEvent::Fault(format!(
                                        "cannot certify epoch: {e:?}"
                                    )));
                                }
                            }
                        }
                    }
                    let keep = log_from.max(*end);
                    while log_from < keep && !log.is_empty() {
                        log.pop_front();
                        log_from += 1;
                    }
                }
                PipeEvent::Violation(v) => {
                    if v.kind == ViolationKind::FalseCheckpoint && dispute_proof.is_none() {
                        dispute_proof = CheckpointEvidence::decode(&v.evidence).ok();
                    }
                    evidence_files += 1;
                    let kind = format!("{:?}", v.kind).to_lowercase();
                    let path = format!("{artifact_path}.violation-{evidence_files}-{kind}.bin");
                    let mut bytes = v.evidence.clone();
                    // A false checkpoint becomes a self-contained fraud bundle
                    // that `verify` can check against the certified history.
                    if v.kind == ViolationKind::FalseCheckpoint && archive_complete {
                        if let (Ok(history), Ok(allegation)) = (
                            CertifiedMatch::decode(archive.as_bytes()),
                            CheckpointEvidence::decode(&v.evidence),
                        ) {
                            let bundle = FraudBundle {
                                history,
                                allegation,
                            };
                            if let Ok(b) = bundle.encode() {
                                bytes = b;
                            }
                        }
                    }
                    if let Some((pkg, commitment)) =
                        fraud_package(&pipe, v.kind, &v.evidence, &bytes)
                    {
                        publish(
                            &mut feed,
                            ExportEvent::Evidence {
                                accused: v.accused,
                                commitment,
                            },
                        );
                        // Standalone `GV-EVIDENCE-PACKAGE/V1`; check with the
                        // `verify_package` example. Best effort, never blocks play.
                        let _ = fs::write(format!("{path}.package"), &pkg);
                        if let Some(h) = &hub {
                            h.send(HubIn::Package(pkg));
                        }
                    }
                    if !bytes.is_empty() {
                        match fs::write(&path, &bytes) {
                            Ok(()) => evidence_bytes += bytes.len() as u64,
                            Err(_) => persist_ok = false,
                        }
                    }
                }
                _ => {}
            }
            out.send(ev);
        }
    }
    if dirty {
        let _ = atomic_save(&artifact_path, archive.as_bytes());
    }
}

// --------------------------------------------------------------- simulation

struct Telemetry {
    last_tick: Option<Instant>,
    jitter_ema: f64,
    window_start: Instant,
    window_ticks: u32,
    tick_hz: f64,
    sim_us_ema: f64,
    finality_ema: Option<f64>,
    net_mark: (Instant, u64, u64),
}

struct Sim {
    timeline: Timeline<ArenaRules>,
    sender: StreamSender,
    ui: Option<ArenaUi>,
    session: LiveSession,
    pipe_tx: Outbox<PipeIn>,
    index: usize,
    roster: [PlayerId; 2],
    me: PlayerId,
    ticks_seen: VecDeque<(u64, Instant)>,
    tel: Telemetry,
    hide_cooldown_until: u64,
    cfg_hide_cooldown: u64,
    certified: usize,
    headless_epochs: Option<usize>,
    hide_at: Option<u64>,
    cheat_at: Option<u64>,
    illegal_at: Option<u64>,
    equivocate_at: Option<u64>,
    withhold_at: Option<u64>,
    accuse_falsely_at: Option<u64>,
    stalled_noted: bool,
    finished: Option<String>,
    /// Last tick with any non-neutral input (either player) and the oldest
    /// such tick that is not yet certified.
    last_active: Option<u64>,
    pending_first: Option<u64>,
}

fn arena(state: &[u8]) -> Option<ArenaState> {
    ArenaState::decode(state).ok()
}

impl Sim {
    fn name(&self, who: &PlayerId) -> &'static str {
        if *who == self.me {
            "You"
        } else {
            "Opponent"
        }
    }
    fn index_of(&self, who: &PlayerId) -> usize {
        self.roster.iter().position(|p| p == who).unwrap_or(0)
    }

    /// Record play that still needs a checkpoint (drives the honest status chip).
    fn note_active(&mut self, tick: u64) {
        self.last_active = Some(self.last_active.map_or(tick, |t| t.max(tick)));
        if self.pending_first.is_none() {
            self.pending_first = Some(tick);
        }
    }
    fn note_controls(&mut self, from: u64, controls: &[u16]) {
        let verified = self.timeline.verified().0;
        if let Some(k) = controls.iter().position(|c| *c != 0) {
            if from + k as u64 >= verified {
                self.note_active(from + k as u64);
            }
        }
    }

    /// Hand an item to the pipeline task. Never blocks the 60 Hz loop; items wait in a bounded
    /// holdback, and a pipeline that falls this far behind ends the match loudly instead of
    /// silently losing signed inputs.
    fn queue_pipe(&mut self, item: PipeIn) {
        if self.pipe_tx.push(item).is_err() && self.finished.is_none() {
            self.finished = Some("verification pipeline stalled: input backlog exceeded".into());
        }
    }
    fn on_tick(&mut self) {
        self.pipe_tx.flush();
        let started = Instant::now();
        let tick = self.timeline.tick();
        // Input for this tick.
        let mut control = match self.ui.as_mut() {
            Some(ui) => ui.sample_controls(),
            None => self
                .headless_epochs
                .map_or(0, |_| bot_controls(self.index, tick)),
        };
        let (mut send_cheat, mut send_hide) = (false, false);
        if let Some(ui) = self.ui.as_ref() {
            let (cheat, illegal, hide) = ui.take_injections();
            if cheat {
                send_cheat = true;
                ui.event("TEST: next signed checkpoint will carry a false state");
            }
            if illegal {
                control = 128;
                ui.event("TEST: this tick carries an illegal signed control word");
            }
            send_hide = hide;
        }
        if send_cheat {
            self.queue_pipe(PipeIn::Cheat);
        }
        if send_hide {
            self.queue_pipe(PipeIn::Hide);
        }
        if self.hide_at.is_some_and(|t| tick >= t) {
            self.hide_at = None;
            self.queue_pipe(PipeIn::Hide);
        }
        if self.cheat_at.is_some_and(|t| tick >= t) {
            self.cheat_at = None;
            self.queue_pipe(PipeIn::Cheat);
        }
        if self.equivocate_at.is_some_and(|t| tick >= t) {
            self.equivocate_at = None;
            self.queue_pipe(PipeIn::Equivocate);
        }
        if self.withhold_at.is_some_and(|t| tick >= t) {
            self.withhold_at = None;
            self.queue_pipe(PipeIn::Withhold);
        }
        if self.accuse_falsely_at.is_some_and(|t| tick >= t) {
            self.accuse_falsely_at = None;
            self.queue_pipe(PipeIn::AccuseFalsely);
        }
        if self.illegal_at.is_some_and(|t| tick >= t) {
            self.illegal_at = None;
            control = 128;
        }
        match self.timeline.advance(control) {
            Ok(t) => {
                self.stalled_noted = false;
                if control != 0 {
                    self.note_active(t);
                }
                self.sender.push(control);
                let ack = self.timeline.remote_confirmed();
                for frame in self.sender.due(t + 1, ack) {
                    // Provisional: a full queue drops it and the next frame supersedes it.
                    let _ = self.session.send_stream(frame.encode());
                }
                self.queue_pipe(PipeIn::Control(control));
                self.ticks_seen.push_back((t, Instant::now()));
                while self.ticks_seen.len() > 1500 {
                    self.ticks_seen.pop_front();
                }
            }
            Err(AdvanceError::Stalled) => {
                if !self.stalled_noted {
                    self.stalled_noted = true;
                    if let Some(ui) = &self.ui {
                        ui.event("Waiting for the opponent's inputs (prediction limit reached)");
                    }
                }
            }
            Err(AdvanceError::Rules(e)) => {
                self.finished = Some(format!("simulation rules error: {e:?}"));
                return;
            }
        }
        self.publish(started);
    }

    fn publish(&mut self, started: Instant) {
        let now = Instant::now();
        let t = &mut self.tel;
        if let Some(prev) = t.last_tick {
            let dt = now.duration_since(prev).as_secs_f64() * 1000.0;
            t.jitter_ema = t.jitter_ema * 0.97 + (dt - TICK.as_secs_f64() * 1000.0).abs() * 0.03;
        }
        t.last_tick = Some(now);
        t.window_ticks += 1;
        t.sim_us_ema = t.sim_us_ema * 0.95 + started.elapsed().as_micros() as f64 * 0.05;
        if now.duration_since(t.window_start) >= Duration::from_secs(1) {
            t.tick_hz =
                f64::from(t.window_ticks) / now.duration_since(t.window_start).as_secs_f64();
            t.window_ticks = 0;
            t.window_start = now;
            let (at, tx0, rx0) = t.net_mark;
            let dt = now.duration_since(at).as_secs_f64().max(0.001);
            let tx = self.session.stats.bytes_tx.load(Ordering::Relaxed);
            let rx = self.session.stats.bytes_rx.load(Ordering::Relaxed);
            let kbps = |a: u64, b: u64| (a.saturating_sub(b)) as f64 * 8.0 / 1000.0 / dt;
            t.net_mark = (now, tx, rx);
            let (txk, rxk) = (kbps(tx, tx0), kbps(rx, rx0));
            let st = &self.session.stats;
            let sends = st.send_count.load(Ordering::Relaxed).max(1);
            let avg = st.send_micros_total.load(Ordering::Relaxed) / sends;
            let max = st.send_micros_max.load(Ordering::Relaxed);
            let stall = st.loop_gap_micros_max.load(Ordering::Relaxed);
            let lagged = st.lagged.load(Ordering::Relaxed);
            let (hsend, hrecv, hslow) = (
                st.hydra_send_max_micros.load(Ordering::Relaxed),
                st.hydra_recv_max_micros.load(Ordering::Relaxed),
                st.hydra_slow_calls.load(Ordering::Relaxed),
            );
            let (retx, bad, errs, supp) = (
                st.reliable_retransmits.load(Ordering::Relaxed),
                st.bad_frames.load(Ordering::Relaxed),
                st.send_errors.load(Ordering::Relaxed),
                st.stream_suppressed.load(Ordering::Relaxed),
            );
            if let Some(ui) = &self.ui {
                ui.update(|v| {
                    v.net_tx_kbps = Some(txk);
                    v.net_rx_kbps = Some(rxk);
                    v.send_avg_us = Some(avg);
                    v.send_max_us = Some(max);
                    v.inbox_stall_us = Some(stall);
                    v.lagged = lagged;
                    v.retransmits = retx;
                    v.bad_frames = bad;
                    v.send_errors = errs;
                    v.suppressed = supp;
                    v.hydra_send_max_us = hsend;
                    v.hydra_recv_max_us = hrecv;
                    v.hydra_slow_calls = hslow;
                });
            }
        }
        let provisional = arena(self.timeline.state());
        let stats = self.timeline.stats.clone();
        let depth = self.timeline.prediction_depth();
        let tick = self.timeline.tick();
        let stalled = self.stalled_noted;
        let (hz, jitter, sim_us) = (t.tick_hz, t.jitter_ema, t.sim_us_ema);
        let cooldown = self.hide_cooldown_until.saturating_sub(tick);
        let pending = self.pending_first.map(|first| tick.saturating_sub(first));
        if let (Some(ui), Some(p)) = (&self.ui, provisional) {
            ui.update(|v| {
                v.players = p.fighters;
                v.tick = tick;
                v.prediction = depth;
                v.rollbacks = stats.rollbacks;
                v.max_rollback = stats.max_rollback_ticks;
                v.stalled = stalled;
                v.tick_hz = (hz > 0.0).then_some(hz);
                v.jitter_ms = Some(jitter);
                v.sim_us = Some(sim_us as u64);
                v.hide_cooldown_ticks = cooldown;
                v.pending_ticks = pending;
                if !stalled && !v.stopped {
                    v.phase = if v
                        .hide
                        .as_ref()
                        .is_some_and(|h| tick >= h.start && tick < h.end)
                    {
                        "Hidden window: commit-lock-reveal active".into()
                    } else {
                        "Playing at 60 Hz · certified in the background".into()
                    };
                }
            });
        }
    }

    fn on_stream(&mut self, bytes: &[u8]) {
        let Ok(frame) = StreamFrame::decode(bytes) else {
            return;
        };
        let controls = frame.expand();
        self.note_controls(frame.from_tick, &controls);
        match self.timeline.set_remote(frame.from_tick, &controls) {
            Ok(depth) => {
                self.sender.on_peer_ack(frame.ack_through);
                // Only news deserves an acknowledgement; acks never beget acks.
                if depth > 0 || !frame.changes.is_empty() {
                    self.sender.note_received();
                }
            }
            Err(e) => self.finished = Some(format!("rollback failed: {e:?}")),
        }
    }

    fn on_reliable(&mut self, bytes: Vec<u8>) {
        match PipeMsg::decode(&bytes) {
            Ok(msg) => {
                self.queue_pipe(PipeIn::Net(Box::new(msg)));
            }
            Err(_) => {
                if let Some(ui) = &self.ui {
                    ui.event("ignored an undecodable pipeline message");
                }
            }
        }
    }

    fn on_pipe_event(&mut self, ev: PipeEvent) {
        let tick = self.timeline.tick();
        match ev {
            PipeEvent::RemoteInputs {
                from_tick,
                controls,
            } => {
                self.note_controls(from_tick, &controls);
                if let Err(e) = self.timeline.set_remote(from_tick, &controls) {
                    self.finished = Some(format!("rollback failed: {e:?}"));
                }
            }
            PipeEvent::Finalized {
                start,
                end,
                checkpoint,
                state,
                disputed,
                hidden,
            } => {
                let consistent = self.timeline.rebase(end, &state).unwrap_or(false);
                self.pending_first = self.last_active.filter(|t| *t >= end).map(|_| end);
                // Finality latency: from the wall-clock moment tick `end - 1`
                // was played to the moment both signatures agreed.
                let played = self
                    .ticks_seen
                    .iter()
                    .rev()
                    .find(|(t, _)| *t + 1 == end)
                    .map(|(_, at)| at.elapsed());
                let lag_ms = played.map(|d| d.as_secs_f64() * 1000.0);
                if let Some(ms) = lag_ms {
                    let e = &mut self.tel.finality_ema;
                    *e = Some(e.map_or(ms, |old| old * 0.8 + ms * 0.2));
                }
                self.certified += 1;
                let finality = self.tel.finality_ema;
                let verified = arena(&state);
                if let (Some(ui), Some(v)) = (&self.ui, &verified) {
                    let dead = v.fighters.iter().any(|f| f.hp == 0);
                    let cp = hex(&checkpoint);
                    ui.update(|view| {
                        view.verified = v.fighters;
                        view.verified_tick = end;
                        view.checkpoint = cp.clone();
                        view.verdict = "valid";
                        if disputed {
                            view.disputed += 1;
                        } else {
                            view.accepted += 1;
                        }
                        view.finality_ms = lag_ms.map(|m| m as u64);
                        view.finality_avg_ms = finality;
                        let note = if hidden { " · hidden window" } else { "" };
                        view.push_event(format!(
                            "CERTIFIED ticks {start}..{end}{note} · {}{}",
                            &cp[..16],
                            lag_ms.map_or(String::new(), |m| format!(" · final in {m:.0} ms"))
                        ));
                        if !consistent {
                            view.push_event(
                                "Provisional state corrected to the certified state".into(),
                            );
                        }
                    });
                    if dead && self.finished.is_none() {
                        self.finished = Some("Match finished: one player has zero health".into());
                    }
                }
                println!(
                    "Certified ticks {start}..{end} checkpoint={} state={:?}{}",
                    hex(&checkpoint),
                    verified,
                    lag_ms.map_or(String::new(), |m| format!(" final_in={m:.0}ms"))
                );
                if self
                    .headless_epochs
                    .is_some_and(|n| self.certified >= n && self.finished.is_none())
                {
                    self.finished = Some("headless run complete".into());
                }
            }
            PipeEvent::Violation(v) => {
                let who = self.name(&v.accused);
                let what = match v.kind {
                    ViolationKind::FalseCheckpoint => "signed a false state claim",
                    ViolationKind::IllegalInput => "signed an illegal input",
                    ViolationKind::BadReveal => "opened a commitment with different inputs",
                    ViolationKind::Equivocation => "signed two conflicting input batches",
                    ViolationKind::WithheldReveal => "never opened a locked commitment",
                    ViolationKind::LogEquivocation => "signed two conflicting log histories",
                };
                println!("PROVEN VIOLATION: {who} {what} (tick {})", v.tick);
                if let Some(ui) = &self.ui {
                    ui.update(|view| {
                        view.rejected += 1;
                        view.verdict = "invalid";
                        view.push_event(format!(
                            "INVALID · {who} {what} · tick {} · evidence saved",
                            v.tick
                        ));
                    });
                }
            }
            PipeEvent::Audit(a) => {
                use gv_edge::audit::Status;
                use gv_edge::live::AuditEvent;
                match a {
                    AuditEvent::Snapshot(stats) => {
                        if let Some(ui) = &self.ui {
                            ui.update(|v| v.audit = stats);
                        }
                    }
                    AuditEvent::Challenge { status, .. } => {
                        let text = match status {
                            Status::SuspectedNonCooperation => "AUDIT · opponent has not answered a challenge yet: suspected non-cooperation (delay or loss is NOT a cheating verdict)",
                            Status::Cleared => "AUDIT · challenge answered: cleared",
                            Status::Unavailable => "AUDIT · opponent unavailable for audit (no verdict)",
                            Status::Inconclusive => "AUDIT · answer did not settle the challenge (inconclusive)",
                            _ => "",
                        };
                        if !text.is_empty() {
                            println!("{text}");
                            if let Some(ui) = &self.ui {
                                ui.update(|v| v.push_event(text.into()));
                            }
                        }
                    }
                    AuditEvent::RejectedEvidence => {
                        let text =
                            "AUDIT · an accusation did not verify: rejected, nobody is accused";
                        println!("{text}");
                        if let Some(ui) = &self.ui {
                            ui.update(|v| v.push_event(text.into()));
                        }
                    }
                    AuditEvent::PersistenceFailed(why) => {
                        let text = format!(
                            "AUDIT · cannot persist signed state ({why}): signing is paused until it recovers (not a verdict about anyone)"
                        );
                        println!("{text}");
                        if let Some(ui) = &self.ui {
                            ui.update(|v| v.push_event(text.clone()));
                        }
                    }
                    AuditEvent::Rebased { seq } => {
                        let text = format!(
                            "AUDIT · recovered local state from a signed head at seq {seq}"
                        );
                        println!("{text}");
                        if let Some(ui) = &self.ui {
                            ui.update(|v| v.push_event(text.clone()));
                        }
                    }
                    AuditEvent::ProvenEquivocation { .. } | AuditEvent::RecoveryNotTrusted(_) => {}
                }
            }
            PipeEvent::HideScheduled { hider, start, end } => {
                let idx = self.index_of(&hider);
                if hider == self.me {
                    self.sender.set_blackout(Some((start, end)));
                } else {
                    self.timeline.set_neutral_window(Some((start, end)));
                }
                let mine = hider == self.me;
                if let Some(ui) = &self.ui {
                    ui.update(|v| {
                        v.hide = Some(HideView {
                            hider: idx,
                            start,
                            end,
                        });
                        v.push_event(if mine {
                            format!("You hide from tick {start} to {end}: inputs are committed, not shown")
                        } else {
                            format!("Opponent hides from tick {start} to {end}: only commitments arrive")
                        });
                    });
                }
                println!("Hide scheduled: hider={} ticks {start}..{end}", hex(&hider));
            }
            PipeEvent::HideRevealed { hider } => {
                self.sender.set_blackout(None);
                self.timeline.set_neutral_window(None);
                self.hide_cooldown_until = tick + self.cfg_hide_cooldown;
                let mine = hider == self.me;
                if let Some(ui) = &self.ui {
                    ui.update(|v| {
                        v.hide = None;
                        v.push_event(if mine {
                            "Your hidden moves were revealed and verified".into()
                        } else {
                            "Opponent revealed their hidden moves · verified by replay".into()
                        });
                    });
                }
                println!("Hide revealed and certified");
            }
            PipeEvent::Fault(text) => {
                eprintln!("pipeline note: {text}");
                if let Some(ui) = &self.ui {
                    ui.event(format!("Protocol note (not a cheat): {text}"));
                }
            }
        }
    }
}

/// Run the whole match. Returns when it ends or fails.
pub async fn play(cfg: GameConfig, link: LiveLink, ui: Option<ArenaUi>) -> Result<(), String> {
    let me = cfg.key.id();
    let rules = ArenaRules::new(cfg.roster);
    let receipts = cfg.resume.clone().unwrap_or(CertifiedMatch {
        epochs: Vec::new(),
        disputes: Vec::new(),
        live: true,
    });
    if !receipts.epochs.is_empty() && !receipts.live {
        return Err("--resume needs a live-engine archive (GV-CERTIFIED-MATCH/V1)".into());
    }
    let mut replica = receipts
        .restore(cfg.match_id, cfg.roster, rules.clone())
        .map_err(|e| format!("cannot authenticate recovered history: {e:?}"))?;
    if receipts.live {
        replica = replica.live();
    }
    let start_tick = replica.next_tick();
    let start_state = replica.state().to_vec();
    let rtt = link.last_ack_rtt;
    let index = cfg
        .roster
        .iter()
        .position(|p| *p == me)
        .ok_or("not in roster")?;
    let session = link.into_session();
    let net = session.sender();

    let pipe_cfg = PipelineConfig {
        epoch_ticks: cfg.epoch_ticks,
        ..PipelineConfig::default()
    };
    let hide_cooldown = pipe_cfg.hide_cooldown_ticks;
    let pipeline = Pipeline::new(
        cfg.key.clone(),
        cfg.roster,
        cfg.match_id,
        rules.clone(),
        replica,
        pipe_cfg,
    )
    .ok_or("cannot build the checkpoint pipeline")?;
    let (pipe_raw, pipe_rx) = mpsc::channel::<PipeIn>(PIPE_CHANNEL);
    let (event_tx, mut events) = mpsc::channel::<PipeEvent>(EVENT_CHANNEL);
    let pipe_tx = Outbox::new(pipe_raw.clone(), PIPE_HOLD);
    let witness_ids: Vec<PlayerId> = cfg.witness_keys.clone();
    let hub = if cfg.witness_links.is_empty() {
        None
    } else {
        // Witness traffic lives in its own tasks; the only thing it hands back to the
        // pipeline is a witness challenge or anchor, via this bounded queue (the forwarder
        // waits for room, so a busy pipeline slows only the witness side).
        let (wtx, mut wrx) = mpsc::channel::<PipeMsg>(256);
        let ptx = pipe_raw.clone();
        tokio::spawn(async move {
            while let Some(m) = wrx.recv().await {
                if ptx.send(PipeIn::Net(Box::new(m))).await.is_err() {
                    break;
                }
            }
        });
        Some(spawn_player_hub(
            cfg.key.clone(),
            cfg.roster,
            cfg.match_id,
            witness_ids.clone(),
            cfg.witness_links.clone(),
            wtx,
        ))
    };
    tokio::spawn(pipeline_task(
        pipeline,
        start_tick,
        pipe_rx,
        EventOut::new(event_tx),
        net.clone(),
        cfg.artifact_path.clone(),
        receipts,
        hub.map(HubOut::new),
        witness_ids,
        cfg.key.clone(),
    ));

    let mut session = session;
    // Align tick 0 on both machines. Alice starts now and tells Bob how long
    // the message took; Bob backdates his clock by half the round trip.
    let mut buffered: Vec<Incoming> = Vec::new();
    let sim_start = if cfg.initiator {
        let rtt_us = rtt.map_or(0, |d| d.as_micros() as u64);
        let mut go = vec![GO];
        go.extend_from_slice(&rtt_us.to_le_bytes());
        let _ = session.send_reliable(go); // first message of a fresh session: queue is empty
        Instant::now()
    } else {
        loop {
            match tokio::time::timeout(Duration::from_secs(60), session.rx.recv()).await {
                Ok(Some(Incoming::Reliable(b))) if b.first() == Some(&GO) && b.len() == 9 => {
                    let rtt_us = u64::from_le_bytes(b[1..9].try_into().unwrap_or([0; 8]));
                    let half = Duration::from_micros(rtt_us / 2).min(Duration::from_millis(500));
                    break Instant::now() - half;
                }
                Ok(Some(Incoming::Closed(why))) => {
                    return Err(format!("link closed before start: {why}"))
                }
                Ok(Some(other)) => buffered.push(other),
                Ok(None) => return Err("session ended before start".into()),
                Err(_) => return Err("timed out waiting for the opponent to start".into()),
            }
        }
    };
    if let Some(ui) = &ui {
        ui.status("Playing at 60 Hz · certified in the background");
        ui.update(|v| {
            v.rtt_ms = rtt.map(|d| d.as_secs_f64() * 1000.0);
            v.push_event("Both players connected · simulation started".into());
        });
    }
    let timeline = Timeline::new(
        rules.clone(),
        cfg.roster,
        me,
        start_tick,
        start_state,
        MAX_PREDICT_TICKS,
    )
    .ok_or("cannot build the timeline")?;
    let now = Instant::now();
    let mut sim = Sim {
        timeline,
        sender: StreamSender::new(start_tick, STREAM_KEEPALIVE_TICKS, STREAM_RESEND_TICKS),
        ui,
        session,
        pipe_tx,
        index,
        roster: cfg.roster,
        me,
        ticks_seen: VecDeque::new(),
        tel: Telemetry {
            last_tick: None,
            jitter_ema: 0.0,
            window_start: now,
            window_ticks: 0,
            tick_hz: 0.0,
            sim_us_ema: 0.0,
            finality_ema: None,
            net_mark: (now, 0, 0),
        },
        hide_cooldown_until: 0,
        cfg_hide_cooldown: hide_cooldown,
        certified: 0,
        headless_epochs: cfg.headless_epochs,
        hide_at: cfg.hide_at,
        cheat_at: cfg.cheat_at,
        illegal_at: cfg.illegal_at,
        equivocate_at: cfg.equivocate_at,
        withhold_at: cfg.withhold_at,
        accuse_falsely_at: cfg.accuse_falsely_at,
        stalled_noted: false,
        finished: None,
        last_active: None,
        pending_first: None,
    };
    for item in buffered {
        match item {
            Incoming::Stream(b) => sim.on_stream(&b),
            Incoming::Reliable(b) => sim.on_reliable(b),
            Incoming::Closed(why) => return Err(format!("link closed: {why}")),
        }
    }
    let mut ticker =
        tokio::time::interval_at(tokio::time::Instant::from_std(sim_start + TICK), TICK);
    // Burst keeps the long-run rate at exactly 60 Hz even after a slow tick.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Burst);
    let mut closed: Option<String> = None;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                sim.on_tick();
                if sim.stalled_noted {
                    ticker.reset();
                }
            }
            incoming = sim.session.rx.recv(), if sim.pipe_tx.has_room(PIPE_HOLD / 2) => match incoming {
                Some(Incoming::Stream(b)) => sim.on_stream(&b),
                Some(Incoming::Reliable(b)) => sim.on_reliable(b),
                Some(Incoming::Closed(why)) => { closed = Some(why); }
                None => { closed = Some("session ended".into()); }
            },
            Some(ev) = events.recv() => sim.on_pipe_event(ev),
        }
        if let Some(why) = sim.finished.take() {
            // Let the final certification land before reporting the result.
            if let Some(ui) = &sim.ui {
                ui.stop(&why);
            }
            println!("{why}");
            break;
        }
        if let Some(why) = closed.take() {
            if sim.certified == 0 || sim.headless_epochs.is_some() {
                return Err(format!("link lost: {why}"));
            }
            if let Some(ui) = &sim.ui {
                ui.failure(&format!("link lost: {why}"));
            }
            return Err(format!("link lost: {why}"));
        }
    }
    let Sim { ui, session, .. } = sim;
    session.shutdown().await;
    if let Some(ui) = ui {
        // Keep the page up so the final certified state stays visible.
        let _ = &ui;
        std::future::pending::<()>().await;
    }
    Ok(())
}
