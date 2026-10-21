use gv_core::{Digest, MatchId, PlayerId};
use gv_edge::audit::Evidence;
use gv_edge::export::{
    export_fraud, Commitment, DisclosurePolicy, ExportError, FraudWitness, Package, PackageKind,
};
use gv_edge::live::ViolationKind;
use gv_edge::{CheckpointEvidence, FraudBundle};
use gv_replay::StateMachine;

/// A `GV-EVIDENCE-PACKAGE/V1`: the one evidence format. Self-contained, chain-agnostic and
/// verifiable offline with [`crate::Verifier`]. Its commitment proves publication of a digest,
/// never fraud by itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidencePackage {
    package: Package,
    bytes: Vec<u8>,
}

impl EvidencePackage {
    pub(crate) fn new(package: Package) -> Result<Self, ExportError> {
        let bytes = package.encode()?;
        Ok(Self { package, bytes })
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ExportError> {
        Ok(Self {
            package: Package::decode(bytes)?,
            bytes: bytes.to_vec(),
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn kind(&self) -> PackageKind {
        self.package.kind()
    }
    pub fn commitment(&self) -> Commitment {
        self.package.commitment()
    }
}

/// What [`crate::AccountableState::export`] packages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportQuery {
    /// The complete certified history (`GV-CERTIFIED-MATCH/V1`), replayable by anyone.
    MatchArchive,
    /// A fraud witness this node produced, by commitment id.
    Fraud(Digest),
    /// Signed log heads and verified accountability evidence this node holds.
    Audit,
}

/// The context every package binds.
pub(crate) struct Context<'a, M> {
    pub machine: &'a M,
    pub match_id: MatchId,
    pub roster: [PlayerId; 2],
    pub disclosure: DisclosurePolicy,
}

impl<M: StateMachine> Context<'_, M> {
    fn fraud(&self, witness: FraudWitness<'_>) -> Option<EvidencePackage> {
        let pkg = export_fraud(
            self.machine,
            self.match_id,
            self.roster,
            witness,
            self.disclosure,
        )
        .ok()?;
        EvidencePackage::new(pkg).ok()
    }
    /// The package for an observed violation, if its evidence is self-sufficient. A false
    /// checkpoint needs `bundle` (it carries the certified history).
    pub fn violation(
        &self,
        kind: ViolationKind,
        raw: &[u8],
        bundle: Option<&FraudBundle>,
    ) -> Option<EvidencePackage> {
        match kind {
            ViolationKind::FalseCheckpoint => self.fraud(FraudWitness::FalseCheckpoint(bundle?)),
            _ => {
                let ev = CheckpointEvidence::decode(raw).ok()?;
                self.fraud(FraudWitness::IllegalInput(&ev))
            }
        }
    }
    pub fn equivocation(&self, evidence: &Evidence) -> Option<EvidencePackage> {
        self.fraud(FraudWitness::Equivocation(evidence))
    }
}
