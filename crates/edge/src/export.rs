//! Chain-agnostic evidence export (`GV-EVIDENCE-PACKAGE/V1`).
//!
//! One interface to export, import, independently verify and stream evidence. A package wraps
//! artifacts the engine already produces (certified match archive, fraud bundle, input-violation
//! evidence, accountability evidence, audit records) in a canonical, bounded, domain-separated
//! envelope. Packages carry no secrets and no signature of their own: authenticity comes from the
//! signatures inside the payload, so a verifier needs only the pinned match id, ruleset and roster.
//!
//! A [`Commitment`] is a 32-byte identifier of a package. Publishing a commitment anywhere (a
//! file, an object store, a settlement system) **proves publication of a digest, not fraud**:
//! fraud is established only by verifying the package itself with [`verify_package`].
use crate::audit::{Authenticator, Challenge, Evidence, Proof, Response, Segment};
use crate::{
    evidence_violations, CertifiedMatch, CheckpointEvidence, EvidenceVerdict, FraudBundle,
    PublicRules,
};
use gv_core::{Digest, MatchId, PlayerId};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;

const PACKAGE_MAGIC: &[u8] = b"GV-EVIDENCE-PACKAGE/V1\0";
const COMMITMENT_MAGIC: &[u8] = b"GV-EVIDENCE-COMMITMENT/V1\0";
const AUDIT_MAGIC: &[u8] = b"GV-AUDIT-EXPORT/V1\0";
const COMMIT_DOMAIN: &[u8] = b"gv/export/commitment/v1\0";
const PAYLOAD_DOMAIN: &[u8] = b"gv/export/payload/v1\0";
/// Commitment hash algorithm identifier: 1 = SHA-256.
pub const HASH_SHA256: u8 = 1;
pub const MAX_PACKAGE_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_AUDIT_ITEMS: usize = 256;
pub const MAX_AUDIT_BYTES: usize = 64 * 1024 * 1024;
const VK_LEN: usize = 1952;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportError {
    Malformed,
    TooLarge,
    /// The disclosure policy does not permit exporting this content.
    DisclosureForbidden,
    WrongContext,
    UnknownPayload,
    /// The payload failed independent verification.
    Invalid,
    /// The payload is well formed but proves nothing (e.g. a valid claim, an honest extension).
    NotAViolation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PackageKind {
    MatchArchive = 1,
    FraudWitness = 2,
    Audit = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FraudKind {
    /// A signed checkpoint with a false state (`FraudBundle`, includes certified predecessors).
    FalseCheckpoint = 1,
    /// A signed illegal control word (`CheckpointEvidence`).
    IllegalInput = 2,
    /// Two signed contradictory statements (`audit::Evidence`).
    Equivocation = 3,
}

/// What the game permits to leave the process. There is deliberately no `Default`: the caller
/// must state the policy. Exports of input history are refused unless inputs are releasable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisclosurePolicy {
    /// Signed input batches (and therefore every player's controls) may be released.
    pub inputs_releasable: bool,
    /// The game promises some state stays secret even after play. Match archives are then refused.
    pub permanently_secret_state: bool,
}

impl DisclosurePolicy {
    /// Public-state game; all inputs were revealed to the opponent during or after play.
    pub const PUBLIC: Self = Self {
        inputs_releasable: true,
        permanently_secret_state: false,
    };
    fn allows_inputs(self) -> bool {
        self.inputs_releasable && !self.permanently_secret_state
    }
}

/// Independently pinned facts a verifier must know before trusting any package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustAnchor {
    pub match_id: MatchId,
    pub ruleset: Digest,
    pub roster: [PlayerId; 2],
}

fn sorted(mut r: [PlayerId; 2]) -> [PlayerId; 2] {
    r.sort();
    r
}

/// Compact commitment to a package. 32-byte `id`, plus the metadata a consumer needs without
/// parsing the package. `publication_only` is always set: a commitment is not a fraud verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub alg: u8,
    pub kind: PackageKind,
    pub fraud: Option<FraudKind>,
    pub match_id: MatchId,
    pub ruleset: Digest,
    pub id: Digest,
}

impl Commitment {
    pub const WIRE_SIZE: usize = 26 + 1 + 1 + 1 + 1 + 32 * 3;
    pub fn encode(&self) -> Vec<u8> {
        let mut o = COMMITMENT_MAGIC.to_vec();
        o.push(self.alg);
        o.push(self.kind as u8);
        o.push(self.fraud.map_or(0, |f| f as u8));
        o.push(1); // publication_only: this commits to bytes; it is not on-chain/third-party fraud verification
        o.extend_from_slice(&self.match_id);
        o.extend_from_slice(&self.ruleset);
        o.extend_from_slice(&self.id);
        o
    }
    pub fn decode(b: &[u8]) -> Result<Self, ExportError> {
        if b.len() != Self::WIRE_SIZE || !b.starts_with(COMMITMENT_MAGIC) {
            return Err(ExportError::Malformed);
        }
        let r = &b[COMMITMENT_MAGIC.len()..];
        if r[0] != HASH_SHA256 || r[3] != 1 {
            return Err(ExportError::Malformed);
        }
        let kind = match r[1] {
            1 => PackageKind::MatchArchive,
            2 => PackageKind::FraudWitness,
            3 => PackageKind::Audit,
            _ => return Err(ExportError::Malformed),
        };
        let fraud = match (kind, r[2]) {
            (PackageKind::FraudWitness, 1) => Some(FraudKind::FalseCheckpoint),
            (PackageKind::FraudWitness, 2) => Some(FraudKind::IllegalInput),
            (PackageKind::FraudWitness, 3) => Some(FraudKind::Equivocation),
            (PackageKind::FraudWitness, _) => return Err(ExportError::Malformed),
            (_, 0) => None,
            _ => return Err(ExportError::Malformed),
        };
        let take = |i: usize| -> Digest {
            r[4 + 32 * i..4 + 32 * (i + 1)]
                .try_into()
                .unwrap_or([0; 32])
        };
        Ok(Self {
            alg: r[0],
            kind,
            fraud,
            match_id: take(0),
            ruleset: take(1),
            id: take(2),
        })
    }
}

/// A canonical evidence package. Construct with the `export_*` functions or [`Package::decode`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    kind: PackageKind,
    fraud: Option<FraudKind>,
    match_id: MatchId,
    ruleset: Digest,
    roster: [PlayerId; 2],
    inputs_disclosed: bool,
    payload: Vec<u8>,
}

fn payload_hash(p: &[u8]) -> Digest {
    let mut s = Sha256::new();
    s.update(PAYLOAD_DOMAIN);
    s.update(p);
    s.finalize().into()
}

impl Package {
    pub fn kind(&self) -> PackageKind {
        self.kind
    }
    pub fn fraud_kind(&self) -> Option<FraudKind> {
        self.fraud
    }
    pub fn match_id(&self) -> MatchId {
        self.match_id
    }
    pub fn inputs_disclosed(&self) -> bool {
        self.inputs_disclosed
    }
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }
    /// Deterministic 32-byte identifier: binds algorithm, kind, context, disclosure and payload.
    pub fn id(&self) -> Digest {
        let mut s = Sha256::new();
        s.update(COMMIT_DOMAIN);
        s.update([
            HASH_SHA256,
            self.kind as u8,
            self.fraud.map_or(0, |f| f as u8),
        ]);
        s.update([u8::from(self.inputs_disclosed)]);
        s.update(self.match_id);
        s.update(self.ruleset);
        s.update(self.roster[0]);
        s.update(self.roster[1]);
        s.update(payload_hash(&self.payload));
        s.finalize().into()
    }
    pub fn commitment(&self) -> Commitment {
        Commitment {
            alg: HASH_SHA256,
            kind: self.kind,
            fraud: self.fraud,
            match_id: self.match_id,
            ruleset: self.ruleset,
            id: self.id(),
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>, ExportError> {
        let mut o = PACKAGE_MAGIC.to_vec();
        o.push(self.kind as u8);
        o.push(self.fraud.map_or(0, |f| f as u8));
        o.push(u8::from(self.inputs_disclosed));
        o.extend_from_slice(&self.match_id);
        o.extend_from_slice(&self.ruleset);
        for p in &self.roster {
            o.extend_from_slice(p);
        }
        // Verifying keys are public and self-authenticating (PlayerId = H(key)).
        for p in &self.roster {
            let vk = gv_sig::public_key_bytes(p).ok_or(ExportError::Invalid)?;
            o.extend_from_slice(&vk);
        }
        o.extend_from_slice(&(self.payload.len() as u64).to_le_bytes());
        o.extend_from_slice(&self.payload);
        o.extend_from_slice(&payload_hash(&self.payload));
        if o.len() > MAX_PACKAGE_BYTES {
            return Err(ExportError::TooLarge);
        }
        Ok(o)
    }
    /// Strict decode: exact lengths, known tags, payload hash, no trailing bytes. Registers the
    /// carried verifying keys only if they hash to the stated player ids.
    pub fn decode(b: &[u8]) -> Result<Self, ExportError> {
        if b.len() > MAX_PACKAGE_BYTES {
            return Err(ExportError::TooLarge);
        }
        let r = b
            .strip_prefix(PACKAGE_MAGIC)
            .ok_or(ExportError::Malformed)?;
        let fixed = 3 + 32 * 4 + 2 * VK_LEN + 8;
        if r.len() < fixed + 32 {
            return Err(ExportError::Malformed);
        }
        let kind = match r[0] {
            1 => PackageKind::MatchArchive,
            2 => PackageKind::FraudWitness,
            3 => PackageKind::Audit,
            _ => return Err(ExportError::Malformed),
        };
        let fraud = match (kind, r[1]) {
            (PackageKind::FraudWitness, 1) => Some(FraudKind::FalseCheckpoint),
            (PackageKind::FraudWitness, 2) => Some(FraudKind::IllegalInput),
            (PackageKind::FraudWitness, 3) => Some(FraudKind::Equivocation),
            (PackageKind::FraudWitness, _) => return Err(ExportError::Malformed),
            (_, 0) => None,
            _ => return Err(ExportError::Malformed),
        };
        let inputs_disclosed = match r[2] {
            0 => false,
            1 => true,
            _ => return Err(ExportError::Malformed),
        };
        let d = |i: usize| -> Digest {
            r[3 + 32 * i..3 + 32 * (i + 1)]
                .try_into()
                .unwrap_or([0; 32])
        };
        let (match_id, ruleset, roster) = (d(0), d(1), [d(2), d(3)]);
        if roster[0] >= roster[1] {
            return Err(ExportError::Malformed); // canonical: sorted and distinct
        }
        let vk_at = 3 + 32 * 4;
        for (i, id) in roster.iter().enumerate() {
            let vk = &r[vk_at + i * VK_LEN..vk_at + (i + 1) * VK_LEN];
            if gv_sig::register_key(vk).map_err(|_| ExportError::Malformed)? != *id {
                return Err(ExportError::Invalid);
            }
        }
        let len_at = vk_at + 2 * VK_LEN;
        let len = u64::from_le_bytes(
            r[len_at..len_at + 8]
                .try_into()
                .map_err(|_| ExportError::Malformed)?,
        );
        let len = usize::try_from(len).map_err(|_| ExportError::TooLarge)?;
        if r.len() != fixed + len + 32 {
            return Err(ExportError::Malformed);
        }
        let payload = r[fixed..fixed + len].to_vec();
        if r[fixed + len..] != payload_hash(&payload) {
            return Err(ExportError::Invalid);
        }
        Ok(Self {
            kind,
            fraud,
            match_id,
            ruleset,
            roster,
            inputs_disclosed,
            payload,
        })
    }
}

fn context<R: PublicRules>(rules: &R, roster: [PlayerId; 2]) -> (Digest, [PlayerId; 2]) {
    (rules.ruleset_hash(), sorted(roster))
}

/// Export a complete certified match: everything an independent party needs to replay it.
pub fn export_match<R: PublicRules>(
    rules: &R,
    match_id: MatchId,
    roster: [PlayerId; 2],
    archive: &CertifiedMatch,
    policy: DisclosurePolicy,
) -> Result<Package, ExportError> {
    if !policy.allows_inputs() {
        return Err(ExportError::DisclosureForbidden);
    }
    let (ruleset, roster) = context(rules, roster);
    let payload = archive.encode().map_err(|_| ExportError::Invalid)?;
    Ok(Package {
        kind: PackageKind::MatchArchive,
        fraud: None,
        match_id,
        ruleset,
        roster,
        inputs_disclosed: true,
        payload,
    })
}

/// Export the smallest sufficient fraud witness.
pub enum FraudWitness<'a> {
    FalseCheckpoint(&'a FraudBundle),
    IllegalInput(&'a CheckpointEvidence),
    Equivocation(&'a Evidence),
}

pub fn export_fraud<R: PublicRules>(
    rules: &R,
    match_id: MatchId,
    roster: [PlayerId; 2],
    witness: FraudWitness<'_>,
    policy: DisclosurePolicy,
) -> Result<Package, ExportError> {
    let (ruleset, roster) = context(rules, roster);
    let (fraud, payload, inputs) = match witness {
        FraudWitness::FalseCheckpoint(b) => (
            FraudKind::FalseCheckpoint,
            b.encode().map_err(|_| ExportError::Invalid)?,
            true,
        ),
        FraudWitness::IllegalInput(e) => (
            FraudKind::IllegalInput,
            e.encode().map_err(|_| ExportError::Invalid)?,
            true,
        ),
        FraudWitness::Equivocation(e) => (
            FraudKind::Equivocation,
            e.encode().map_err(|_| ExportError::Invalid)?,
            matches!(e, Evidence::ConflictingBatches(..)),
        ),
    };
    if inputs && !policy.allows_inputs() {
        return Err(ExportError::DisclosureForbidden);
    }
    Ok(Package {
        kind: PackageKind::FraudWitness,
        fraud: Some(fraud),
        match_id,
        ruleset,
        roster,
        inputs_disclosed: inputs,
        payload,
    })
}

/// Signed audit records for a match.
#[derive(Clone, Debug, Default)]
pub struct AuditExport {
    pub authenticators: Vec<Authenticator>,
    pub segments: Vec<Segment>,
    pub challenges: Vec<Challenge>,
    pub responses: Vec<Response>,
    pub evidence: Vec<Evidence>,
}

fn put_list(o: &mut Vec<u8>, items: Vec<Vec<u8>>) -> Result<(), ExportError> {
    if items.len() > MAX_AUDIT_ITEMS {
        return Err(ExportError::TooLarge);
    }
    o.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for i in items {
        o.extend_from_slice(&(i.len() as u32).to_le_bytes());
        o.extend_from_slice(&i);
    }
    Ok(())
}

struct Rd<'a>(&'a [u8]);
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ExportError> {
        if self.0.len() < n {
            return Err(ExportError::Malformed);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u32(&mut self) -> Result<usize, ExportError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ExportError::Malformed)?,
        ) as usize)
    }
    fn list(&mut self) -> Result<Vec<&'a [u8]>, ExportError> {
        let n = self.u32()?;
        if n > MAX_AUDIT_ITEMS {
            return Err(ExportError::TooLarge);
        }
        (0..n)
            .map(|_| {
                let l = self.u32()?;
                self.take(l)
            })
            .collect()
    }
}

impl AuditExport {
    pub fn encode(&self) -> Result<Vec<u8>, ExportError> {
        let mut o = AUDIT_MAGIC.to_vec();
        put_list(
            &mut o,
            self.authenticators
                .iter()
                .map(Authenticator::encode)
                .collect(),
        )?;
        put_list(&mut o, self.segments.iter().map(Segment::encode).collect())?;
        put_list(
            &mut o,
            self.challenges.iter().map(Challenge::encode).collect(),
        )?;
        put_list(
            &mut o,
            self.responses.iter().map(Response::encode).collect(),
        )?;
        let mut ev = Vec::new();
        for e in &self.evidence {
            ev.push(e.encode().map_err(|_| ExportError::Invalid)?);
        }
        put_list(&mut o, ev)?;
        if o.len() > MAX_AUDIT_BYTES {
            return Err(ExportError::TooLarge);
        }
        Ok(o)
    }
    pub fn decode(b: &[u8]) -> Result<Self, ExportError> {
        if b.len() > MAX_AUDIT_BYTES {
            return Err(ExportError::TooLarge);
        }
        let mut r = Rd(b.strip_prefix(AUDIT_MAGIC).ok_or(ExportError::Malformed)?);
        let authenticators = r
            .list()?
            .into_iter()
            .map(|x| Authenticator::decode(x).map_err(|_| ExportError::Invalid))
            .collect::<Result<_, _>>()?;
        let segments = r
            .list()?
            .into_iter()
            .map(|x| Segment::decode(x).map_err(|_| ExportError::Invalid))
            .collect::<Result<_, _>>()?;
        let challenges = r
            .list()?
            .into_iter()
            .map(|x| Challenge::decode(x).map_err(|_| ExportError::Invalid))
            .collect::<Result<_, _>>()?;
        let responses = r
            .list()?
            .into_iter()
            .map(|x| Response::decode(x).map_err(|_| ExportError::Invalid))
            .collect::<Result<_, _>>()?;
        let evidence = r
            .list()?
            .into_iter()
            .map(|x| Evidence::decode(x).map_err(|_| ExportError::Invalid))
            .collect::<Result<_, _>>()?;
        if !r.0.is_empty() {
            return Err(ExportError::Malformed);
        }
        Ok(Self {
            authenticators,
            segments,
            challenges,
            responses,
            evidence,
        })
    }
}

/// Export audit history. Evidence inside is re-verified on import; nothing is trusted.
pub fn export_audit<R: PublicRules>(
    rules: &R,
    match_id: MatchId,
    roster: [PlayerId; 2],
    audit: &AuditExport,
    policy: DisclosurePolicy,
) -> Result<Package, ExportError> {
    let has_batches = audit
        .evidence
        .iter()
        .any(|e| matches!(e, Evidence::ConflictingBatches(..)));
    if has_batches && !policy.allows_inputs() {
        return Err(ExportError::DisclosureForbidden);
    }
    let (ruleset, roster) = context(rules, roster);
    Ok(Package {
        kind: PackageKind::Audit,
        fraud: None,
        match_id,
        ruleset,
        roster,
        inputs_disclosed: has_batches,
        payload: audit.encode()?,
    })
}

/// Result of independently verifying a package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verified {
    Match {
        ticks: u64,
        /// Epochs the replay advanced over, certified or disputed.
        epochs: usize,
        /// Of those, epochs closed by proven fraud (explicit gaps between certified runs).
        disputed: usize,
        /// Maximal runs of dual-signed epochs.
        segments: usize,
    },
    /// The package proves misbehavior by `accused`.
    Fraud { kind: FraudKind, accused: PlayerId },
    Audit {
        authenticators: usize,
        segments: usize,
        challenges: usize,
        responses: usize,
        /// Players with verified equivocation evidence.
        proven: Vec<PlayerId>,
    },
}

/// Verify a package from bytes with nothing but the pinned anchor and the ruleset.
pub fn verify_package<R: PublicRules + Clone>(
    bytes: &[u8],
    anchor: &TrustAnchor,
    rules: &R,
) -> Result<(Commitment, Verified), ExportError> {
    let pkg = Package::decode(bytes)?;
    if pkg.match_id != anchor.match_id
        || pkg.ruleset != anchor.ruleset
        || pkg.ruleset != rules.ruleset_hash()
        || pkg.roster != sorted(anchor.roster)
    {
        return Err(ExportError::WrongContext);
    }
    let verified = verify_payload(&pkg, anchor, rules)?;
    Ok((pkg.commitment(), verified))
}

fn verify_payload<R: PublicRules + Clone>(
    pkg: &Package,
    anchor: &TrustAnchor,
    rules: &R,
) -> Result<Verified, ExportError> {
    let roster = pkg.roster;
    match pkg.kind {
        PackageKind::MatchArchive => {
            let archive = CertifiedMatch::decode(&pkg.payload).map_err(|_| ExportError::Invalid)?;
            let replica = archive
                .restore(anchor.match_id, roster, rules.clone())
                .map_err(|_| ExportError::Invalid)?;
            Ok(Verified::Match {
                ticks: replica.next_tick(),
                epochs: replica.accepted().len(),
                disputed: archive.disputed(),
                segments: archive.segments(),
            })
        }
        PackageKind::FraudWitness => match pkg.fraud {
            Some(FraudKind::FalseCheckpoint) => {
                let bundle = FraudBundle::decode(&pkg.payload).map_err(|_| ExportError::Invalid)?;
                match bundle.verify(anchor.match_id, roster, rules.clone()) {
                    EvidenceVerdict::ProvenInvalidState => Ok(Verified::Fraud {
                        kind: FraudKind::FalseCheckpoint,
                        accused: bundle_accused(&bundle),
                    }),
                    EvidenceVerdict::Inconclusive(_) => Err(ExportError::Invalid),
                    _ => Err(ExportError::NotAViolation),
                }
            }
            Some(FraudKind::IllegalInput) => {
                let ev =
                    CheckpointEvidence::decode(&pkg.payload).map_err(|_| ExportError::Invalid)?;
                if ev.roster != roster || ev.accused.claim.match_id != anchor.match_id {
                    return Err(ExportError::WrongContext);
                }
                let v = evidence_violations(rules, &ev).map_err(|_| ExportError::Invalid)?;
                let first = v.first().ok_or(ExportError::NotAViolation)?;
                Ok(Verified::Fraud {
                    kind: FraudKind::IllegalInput,
                    accused: first.player,
                })
            }
            Some(FraudKind::Equivocation) => {
                let ev = Evidence::decode(&pkg.payload).map_err(|_| ExportError::Invalid)?;
                if ev.match_id() != anchor.match_id || !roster.contains(&ev.accused()) {
                    return Err(ExportError::WrongContext);
                }
                match ev.verify() {
                    Ok(Proof::Equivocation(p)) => Ok(Verified::Fraud {
                        kind: FraudKind::Equivocation,
                        accused: p,
                    }),
                    Err(_) => Err(ExportError::NotAViolation),
                }
            }
            None => Err(ExportError::Malformed),
        },
        PackageKind::Audit => verify_audit(&AuditExport::decode(&pkg.payload)?, anchor),
    }
}

fn bundle_accused(b: &FraudBundle) -> PlayerId {
    b.allegation.accused.player
}

fn verify_audit(a: &AuditExport, anchor: &TrustAnchor) -> Result<Verified, ExportError> {
    let roster = sorted(anchor.roster);
    let mut heads: BTreeSet<(PlayerId, u64, Digest)> = BTreeSet::new();
    for x in &a.authenticators {
        x.verify().map_err(|_| ExportError::Invalid)?;
        if x.match_id != anchor.match_id
            || x.ruleset != anchor.ruleset
            || !roster.contains(&x.owner)
        {
            return Err(ExportError::WrongContext);
        }
        heads.insert((x.owner, x.seq, x.head));
    }
    for s in &a.segments {
        if s.match_id != anchor.match_id || !roster.contains(&s.owner) {
            return Err(ExportError::WrongContext);
        }
        let end = s.end_head().map_err(|_| ExportError::Invalid)?;
        // A segment is only meaningful if it chains to a signed head included in the export.
        if !heads.contains(&(s.owner, s.end_seq(), end)) {
            return Err(ExportError::Invalid);
        }
    }
    let mut ids = BTreeSet::new();
    for c in &a.challenges {
        if !c.verify()
            || c.match_id != anchor.match_id
            || !roster.contains(&c.challenger)
            || !roster.contains(&c.target)
        {
            return Err(ExportError::Invalid);
        }
        ids.insert(c.id());
    }
    for r in &a.responses {
        if !r.verify() || !ids.contains(&r.challenge_id) || !roster.contains(&r.responder) {
            return Err(ExportError::Invalid);
        }
    }
    let mut proven = BTreeSet::new();
    for e in &a.evidence {
        if e.match_id() != anchor.match_id || !roster.contains(&e.accused()) {
            return Err(ExportError::WrongContext);
        }
        match e.verify() {
            Ok(Proof::Equivocation(p)) => {
                proven.insert(p);
            }
            Err(_) => return Err(ExportError::Invalid),
        }
    }
    Ok(Verified::Audit {
        authenticators: a.authenticators.len(),
        segments: a.segments.len(),
        challenges: a.challenges.len(),
        responses: a.responses.len(),
        proven: proven.into_iter().collect(),
    })
}

/// Event delivered to feed subscribers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportEvent {
    /// New verified evidence; `commitment` identifies the exportable package.
    Evidence {
        accused: PlayerId,
        commitment: Commitment,
    },
    /// A checkpoint both players signed.
    Checkpoint { epoch_start: u64, hash: Digest },
    /// A challenge changed state. Only a cryptographic proof is a cheating verdict; a timeout
    /// is reported as SUSPECTED_NONCOOPERATION or UNAVAILABLE, never as fraud.
    Audit {
        challenge: Digest,
        status: crate::audit::Status,
    },
}

/// Bounded, non-blocking fan-out. A slow subscriber loses events (counted in
/// [`Subscription::dropped`]); publishing never blocks and never allocates unboundedly.
#[derive(Default)]
pub struct EvidenceFeed {
    subs: Vec<(SyncSender<ExportEvent>, Arc<AtomicU64>)>,
}

pub struct Subscription {
    pub events: Receiver<ExportEvent>,
    dropped: Arc<AtomicU64>,
}

impl Subscription {
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

pub const MAX_SUBSCRIBERS: usize = 16;

impl EvidenceFeed {
    pub fn new() -> Self {
        Self::default()
    }
    /// `capacity` is clamped to 1..=4096. Returns `None` past [`MAX_SUBSCRIBERS`].
    pub fn subscribe(&mut self, capacity: usize) -> Option<Subscription> {
        if self.subs.len() >= MAX_SUBSCRIBERS {
            return None;
        }
        let (tx, rx) = sync_channel(capacity.clamp(1, 4096));
        let dropped = Arc::new(AtomicU64::new(0));
        self.subs.push((tx, dropped.clone()));
        Some(Subscription {
            events: rx,
            dropped,
        })
    }
    pub fn publish(&mut self, ev: &ExportEvent) {
        self.subs
            .retain(|(tx, dropped)| match tx.try_send(ev.clone()) {
                Ok(()) => true,
                Err(TrySendError::Full(_)) => {
                    dropped.fetch_add(1, Ordering::Relaxed);
                    true
                }
                Err(TrySendError::Disconnected(_)) => false,
            });
    }
    pub fn subscribers(&self) -> usize {
        self.subs.len()
    }
}
