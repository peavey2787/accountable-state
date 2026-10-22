//! Everything a node keeps on disk, and what it records for each pipeline event: the
//! write-ahead trust journal, pins and open challenges, the evidence ledger, the signed event
//! feed, the certified archive and standalone fraud packages.
use crate::config::DurableStorage;
use crate::evidence::{Context, EvidencePackage};
use crate::io::{OpenError, Outgoing, WitnessOut};
use gv_core::Digest;
use gv_edge::audit::durable::Durable;
use gv_edge::audit::fsync::replace_file;
use gv_edge::audit::journal::FileTrustStore;
use gv_edge::audit::store::RecordFile;
use gv_edge::audit::{Evidence, Status};
use gv_edge::export::{AuditExport, ExportEvent, MAX_AUDIT_ITEMS};
use gv_edge::feed::{FeedStore, SignedEvent};
use gv_edge::live::{AuditEvent, PipeEvent, Pipeline, Violation, ViolationKind};
use gv_edge::{ArchiveBuilder, CertifiedEpoch, CertifiedMatch, CheckpointEvidence, FraudBundle};
use gv_replay::StateMachine;
use gv_sig::SigningKey;
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// Fraud packages kept in memory for [`crate::ExportQuery::Fraud`] (they are also on disk).
const MAX_PACKAGES: usize = 256;
const SAVE_EVERY: Duration = Duration::from_secs(1);
const SNAPSHOT_EVERY: Duration = Duration::from_millis(500);
const CHALLENGES_EVERY: Duration = Duration::from_secs(5);
/// Checkpoint announcements are provisional (the archive holds every epoch): rate-limited.
const CHECKPOINT_EVENT_EVERY: Duration = Duration::from_secs(5);

/// Where [`Persistence`] hands what it produces.
pub(crate) struct Sink<'a> {
    pub outgoing: &'a mut VecDeque<Outgoing>,
    pub events: &'a mut VecDeque<PipeEvent>,
    pub witnesses: bool,
}

impl Sink<'_> {
    fn fault(&mut self, text: String) {
        self.events.push_back(PipeEvent::Fault(text));
    }
    fn witness(&mut self, m: WitnessOut) {
        if self.witnesses {
            self.outgoing.push_back(Outgoing::Witness(m));
        }
    }
}

pub(crate) struct Persistence {
    storage: DurableStorage,
    durable: Durable,
    ledger: RecordFile,
    feed: FeedStore,
    archive: ArchiveBuilder,
    archive_complete: bool,
    dispute_proof: Option<CheckpointEvidence>,
    packages: BTreeMap<Digest, Vec<u8>>,
    evidence_files: u32,
    evidence_bytes: u64,
    persist_ok: bool,
    dirty: bool,
    last_save: Option<Instant>,
    last_snapshot: Option<Instant>,
    last_challenges: Option<Instant>,
    last_checkpoint_event: Option<Instant>,
}

fn storage_error(storage: &DurableStorage, suffix: &str, e: impl ToString) -> OpenError {
    OpenError::Storage {
        file: storage.file(suffix).display().to_string(),
        error: e.to_string(),
    }
}

fn due(last: Option<Instant>, now: Instant, every: Duration) -> bool {
    last.is_none_or(|t| now.saturating_duration_since(t) >= every)
}

impl Persistence {
    /// Open every durable file and recover the auditor from them. Any failure is an error:
    /// there is no degraded in-memory mode.
    pub fn open<M: StateMachine + Clone>(
        storage: &DurableStorage,
        pipe: &mut Pipeline<M>,
        receipts: &CertifiedMatch,
        key: SigningKey,
        start_tick: u64,
        sink: &mut Sink<'_>,
    ) -> Result<Self, OpenError> {
        let (ledger, recovered) = RecordFile::open(&storage.file(".evidence-ledger"))
            .map_err(|e| storage_error(storage, ".evidence-ledger", e))?;
        let durable = Durable::new(storage.base());
        recover_auditor(storage, &durable, pipe, &recovered, sink)?;
        if let Some(cs) = durable.load_challenges().ok() {
            pipe.auditor_mut().resume_challenges(&cs, start_tick);
        }
        let archive = ArchiveBuilder::new(receipts)
            .map_err(|e| OpenError::Recovery(format!("receipt archive: {e:?}")))?;
        let feed = FeedStore::open(&storage.file(".feed"), key, pipe.match_id())
            .map_err(|e| storage_error(storage, ".feed", e))?;
        Ok(Self {
            storage: storage.clone(),
            durable,
            ledger,
            feed,
            archive,
            archive_complete: true,
            dispute_proof: None,
            packages: BTreeMap::new(),
            evidence_files: 0,
            evidence_bytes: 0,
            persist_ok: true,
            dirty: false,
            last_save: Some(Instant::now()),
            last_snapshot: None,
            last_challenges: Some(Instant::now()),
            last_checkpoint_event: None,
        })
    }

    pub fn since(&self, cursor: u64, limit: usize) -> Vec<SignedEvent> {
        self.feed.since(cursor, limit)
    }
    pub fn archive(&self) -> Option<CertifiedMatch> {
        self.archive_complete
            .then(|| CertifiedMatch::decode(self.archive.as_bytes()).ok())
            .flatten()
    }
    pub fn package(&self, id: &Digest) -> Option<&[u8]> {
        self.packages.get(id).map(Vec::as_slice)
    }
    /// Signed heads I pinned and the verified evidence in my ledger, bounded.
    pub fn audit<M: StateMachine + Clone>(&self, pipe: &Pipeline<M>) -> AuditExport {
        let evidence = RecordFile::read_all(self.ledger.path())
            .unwrap_or_default()
            .iter()
            .filter_map(|r| Evidence::decode(r).ok())
            .take(MAX_AUDIT_ITEMS)
            .collect();
        AuditExport {
            authenticators: pipe
                .auditor()
                .pins()
                .items()
                .iter()
                .take(MAX_AUDIT_ITEMS)
                .cloned()
                .collect(),
            evidence,
            ..AuditExport::default()
        }
    }

    /// Time-driven work: archive flush, challenge and pin persistence, a stats snapshot.
    pub fn housekeeping<M: StateMachine + Clone>(
        &mut self,
        now: Instant,
        pipe: &mut Pipeline<M>,
        sink: &mut Sink<'_>,
    ) {
        if self.dirty && due(self.last_save, now, SAVE_EVERY) {
            self.save_archive(now, sink);
        }
        if due(self.last_challenges, now, CHALLENGES_EVERY) {
            self.last_challenges = Some(now);
            let open = pipe.auditor().open_challenges();
            self.persist_ok &= self.durable.save_challenges(&open).is_ok();
        }
        if let Some(pins) = pipe.auditor_mut().take_dirty_pins() {
            self.persist_ok &= self.durable.save_pins(pins).is_ok();
        }
        if due(self.last_snapshot, now, SNAPSHOT_EVERY) {
            self.last_snapshot = Some(now);
            let mut stats = pipe.auditor().stats();
            stats.evidence_files = self.evidence_files;
            stats.evidence_bytes = self.evidence_bytes;
            stats.persist_ok = self.persist_ok;
            sink.events
                .push_back(PipeEvent::Audit(AuditEvent::Snapshot(stats)));
        }
    }
    pub fn flush(&mut self, sink: &mut Sink<'_>) {
        if self.dirty {
            self.save_archive(Instant::now(), sink);
        }
    }
    fn save_archive(&mut self, now: Instant, sink: &mut Sink<'_>) {
        if let Err(e) = replace_file(self.storage.base(), self.archive.as_bytes()) {
            sink.fault(format!("cannot save receipts: {e}"));
        }
        self.dirty = false;
        self.last_save = Some(now);
    }
    fn publish(&mut self, event: ExportEvent, sink: &mut Sink<'_>) {
        if let Err(e) = self.feed.append(event) {
            sink.fault(format!("cannot persist feed event: {e}"));
        }
    }
    /// Keep a package for export and as a standalone file for offline verification.
    fn keep_package(&mut self, pkg: &EvidencePackage, label: &str) {
        let id = pkg.commitment().id;
        let file = self
            .storage
            .file(&format!(".{label}-{}.package", hex(&id[..4])));
        match replace_file(&file, pkg.bytes()) {
            Ok(()) => {
                self.evidence_files += 1;
                self.evidence_bytes += pkg.bytes().len() as u64;
            }
            Err(_) => self.persist_ok = false,
        }
        if self.packages.len() < MAX_PACKAGES {
            self.packages.insert(id, pkg.bytes().to_vec());
        }
    }

    /// Record what an event requires. Returns the tick before which my own inputs are no
    /// longer needed (after a certified epoch).
    pub fn on_event<M: StateMachine + Clone>(
        &mut self,
        ev: &PipeEvent,
        pipe: &mut Pipeline<M>,
        cx: &Context<'_, M>,
        now: Instant,
        sink: &mut Sink<'_>,
    ) -> Option<u64> {
        match ev {
            PipeEvent::Audit(AuditEvent::ProvenEquivocation { evidence, .. }) => {
                self.on_equivocation(evidence, cx, sink);
            }
            PipeEvent::Audit(AuditEvent::Challenge { id, status, .. }) => {
                self.on_challenge(*id, *status, sink);
            }
            PipeEvent::Finalized {
                disputed,
                end,
                start,
                checkpoint,
                ..
            } => {
                self.on_finalized(*start, *checkpoint, *disputed, pipe, now, sink);
                return Some(*end);
            }
            PipeEvent::Violation(v) => self.on_violation(v, cx, sink),
            _ => {}
        }
        None
    }

    fn on_equivocation<M: StateMachine>(
        &mut self,
        evidence: &[u8],
        cx: &Context<'_, M>,
        sink: &mut Sink<'_>,
    ) {
        sink.witness(WitnessOut::Evidence(evidence.to_vec()));
        if let Ok(parsed) = Evidence::decode(evidence) {
            if let Some(pkg) = cx.equivocation(&parsed) {
                let commitment = pkg.commitment();
                self.keep_package(&pkg, "equivocation");
                let accused = parsed.accused();
                self.publish(
                    ExportEvent::Evidence {
                        accused,
                        commitment,
                    },
                    sink,
                );
            }
        }
        match self.ledger.append(evidence) {
            Ok(()) => self.evidence_bytes += evidence.len() as u64,
            Err(_) => self.persist_ok = false,
        }
    }

    fn on_challenge(&mut self, challenge: Digest, status: Status, sink: &mut Sink<'_>) {
        self.publish(ExportEvent::Audit { challenge, status }, sink);
    }

    fn on_finalized<M: StateMachine + Clone>(
        &mut self,
        start: u64,
        checkpoint: Digest,
        disputed: bool,
        pipe: &mut Pipeline<M>,
        now: Instant,
        sink: &mut Sink<'_>,
    ) {
        if disputed {
            self.record_dispute(start, pipe, sink);
            return;
        }
        if due(self.last_checkpoint_event, now, CHECKPOINT_EVENT_EVERY) {
            self.last_checkpoint_event = Some(now);
            self.publish(
                ExportEvent::Checkpoint {
                    epoch_start: start,
                    hash: checkpoint,
                },
                sink,
            );
        }
        if self.archive_complete {
            self.record_certified(pipe, now, sink);
        }
    }

    /// A disputed epoch has no dual signature. It is recorded as an explicit gap carrying the
    /// fraud proof, and the next certified epoch links to the honestly replayed result, so the
    /// archive continues past it. Only an epoch with no checkable proof ends the chain.
    fn record_dispute<M: StateMachine + Clone>(
        &mut self,
        start: u64,
        pipe: &mut Pipeline<M>,
        sink: &mut Sink<'_>,
    ) {
        let proof = self
            .dispute_proof
            .take()
            .filter(|p| p.accused.claim.epoch_start == start);
        match proof {
            Some(proof) if self.archive_complete => {
                if let Err(e) = self.archive.push_dispute(&proof) {
                    sink.fault(format!("cannot record disputed epoch: {e:?}"));
                    self.archive_complete = false;
                }
                self.dirty = true;
                pipe.prune_history(2);
            }
            _ => self.archive_complete = false,
        }
    }

    fn record_certified<M: StateMachine + Clone>(
        &mut self,
        pipe: &mut Pipeline<M>,
        now: Instant,
        sink: &mut Sink<'_>,
    ) {
        let Some(last) = pipe.replica().accepted().last() else {
            return;
        };
        match CertifiedEpoch::from_accepted(last, pipe.session()) {
            Ok(cert) => {
                if let Err(e) = self.archive.push(&cert) {
                    sink.fault(format!("cannot encode receipts: {e:?}"));
                }
                self.dirty = true;
                pipe.prune_history(2);
                if due(self.last_save, now, SAVE_EVERY) {
                    self.save_archive(now, sink);
                }
            }
            Err(e) => sink.fault(format!("cannot certify epoch: {e:?}")),
        }
    }

    fn on_violation<M: StateMachine>(
        &mut self,
        v: &Violation,
        cx: &Context<'_, M>,
        sink: &mut Sink<'_>,
    ) {
        // Equivocation is packaged from its own proven-evidence event; this one carries no
        // checkpoint evidence to package.
        if matches!(
            v.kind,
            ViolationKind::Equivocation | ViolationKind::LogEquivocation
        ) {
            return;
        }
        let false_checkpoint = v.kind == ViolationKind::FalseCheckpoint;
        if false_checkpoint && self.dispute_proof.is_none() {
            self.dispute_proof = CheckpointEvidence::decode(&v.evidence).ok();
        }
        let bundle = false_checkpoint
            .then(|| self.fraud_bundle(&v.evidence))
            .flatten();
        let Some(pkg) = cx.violation(v.kind, &v.evidence, bundle.as_ref()) else {
            sink.fault(format!("{:?} evidence could not be packaged", v.kind));
            return;
        };
        let commitment = pkg.commitment();
        self.publish(
            ExportEvent::Evidence {
                accused: v.accused,
                commitment,
            },
            sink,
        );
        sink.witness(WitnessOut::Package(pkg.bytes().to_vec()));
        let label = format!("violation-{:?}", v.kind).to_lowercase();
        self.keep_package(&pkg, &label);
    }

    /// A false checkpoint becomes a self-contained fraud bundle, checkable against the
    /// certified history (only while the archive is complete).
    fn fraud_bundle(&self, evidence: &[u8]) -> Option<FraudBundle> {
        if !self.archive_complete {
            return None;
        }
        Some(FraudBundle {
            history: CertifiedMatch::decode(self.archive.as_bytes()).ok()?,
            allegation: CheckpointEvidence::decode(evidence).ok()?,
        })
    }
}

/// Crash recovery: re-verify persisted evidence and adopt the write-ahead journal. Everything
/// this participant signed was durable before it left the process, so journalled heads are
/// valid anchors. State loss is only detectable against heads held elsewhere, so signing
/// always waits for the anchor check after a (re)start.
fn recover_auditor<M: StateMachine + Clone>(
    storage: &DurableStorage,
    durable: &Durable,
    pipe: &mut Pipeline<M>,
    recovered: &[Vec<u8>],
    sink: &mut Sink<'_>,
) -> Result<(), OpenError> {
    let me = pipe.auditor().log().owner();
    let (store, loaded) = FileTrustStore::open(storage.base(), pipe.match_id(), me)
        .map_err(|e| storage_error(storage, "", e))?;
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
    let report = pipe.auditor_mut().restore(log, &anchors, recovered);
    pipe.auditor_mut().attach_store(Box::new(store), len, top);
    pipe.auditor_mut().require_anchor_check();
    if !report.recovery.may_sign() {
        sink.fault(format!("audit recovery not trusted: {:?}", report.recovery));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
