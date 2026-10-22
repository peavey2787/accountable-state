use gv_core::{ParticipantId, Session};
use gv_edge::export::DisclosurePolicy;
use gv_edge::live::PipelineConfig;
use gv_edge::CertifiedMatch;
use gv_sig::SigningKey;
use std::path::{Path, PathBuf};

/// Where a node keeps everything it must not lose: the write-ahead trust journal, pins, open
/// challenges, the evidence ledger, the signed event feed and the certified archive. There is
/// no in-memory variant: an accountable node without durable storage could sign two histories
/// across a crash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableStorage {
    base: PathBuf,
}

impl DurableStorage {
    /// All files share this path prefix (`base`, `base.feed`, `base.evidence-ledger`, ...).
    pub fn at(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }
    pub fn base(&self) -> &Path {
        &self.base
    }
    pub(crate) fn file(&self, suffix: &str) -> PathBuf {
        let mut name = self.base.clone().into_os_string();
        name.push(suffix);
        name.into()
    }
}

/// Everything [`crate::AccountableState::open`] needs. There is deliberately no `Default`.
pub struct Config {
    pub key: SigningKey,
    /// Who takes part and how: roster (roles, teams), certification and ordering policies, and
    /// the application parameters. Every digest and archive binds it.
    pub session: Session,
    /// Epoch grid, idle input and the optional close and sealed-window policies. The idle input
    /// also fixes the byte width of every action passed to [`crate::AccountableState::submit`].
    pub pipeline: PipelineConfig,
    /// Pinned witnesses. With witnesses, recovery after a restart also waits for their
    /// retained heads (see the anchor trust boundary in docs/39).
    pub witnesses: Vec<ParticipantId>,
    /// What evidence may disclose; stated by the application, never assumed.
    pub disclosure: DisclosurePolicy,
    /// Certified history to resume from (`GV-CERTIFIED-MATCH/V1`, live engine).
    pub resume: Option<CertifiedMatch>,
    pub storage: DurableStorage,
}
