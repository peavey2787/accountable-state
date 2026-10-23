//! From jobs to a match result, and from a result to what the application does about rankings and
//! rewards. The match result lifecycle is separate from the job lifecycle: a result is provisional
//! until the evidence is in, a missing proof holds rewards but never forfeits them, and a violation
//! proven after the result was final is a correction, not a surprise.
use crate::job::{Family, Job, JobState};
use gv_core::{MatchId, ParticipantId};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatchStatus {
    /// Nothing submitted for this match.
    Unknown,
    Pending,
    Processing,
    /// Everything submitted so far checks out, but not all the required evidence is in yet.
    Verified,
    /// All required evidence verified.
    Certified,
    ViolationProven {
        accused: Vec<ParticipantId>,
    },
    /// Some evidence ended without a verdict (cancelled, inconclusive, dependency failed).
    Uncertified,
    /// Some evidence was not verified before its deadline.
    Expired,
    /// Some evidence was unusable.
    Failed,
}

/// Aggregate the jobs of one match. A proven violation outranks everything: evidence of cheating
/// does not become less true because other evidence is still pending.
pub fn match_status<'a>(jobs: impl Iterator<Item = &'a Job>, required: &[Family]) -> MatchStatus {
    let jobs: Vec<&Job> = jobs.collect();
    if jobs.is_empty() {
        return MatchStatus::Unknown;
    }
    let violators = violators(&jobs);
    if !violators.is_empty() {
        return MatchStatus::ViolationProven { accused: violators };
    }
    let has = |s: JobState| jobs.iter().any(|j| j.state == s);
    [
        (JobState::Processing, MatchStatus::Processing),
        (JobState::Pending, MatchStatus::Pending),
        (JobState::Failed, MatchStatus::Failed),
        (JobState::Expired, MatchStatus::Expired),
        (JobState::Uncertified, MatchStatus::Uncertified),
    ]
    .into_iter()
    .find(|(s, _)| has(*s))
    .map_or_else(
        || {
            if covered(&jobs, required) {
                MatchStatus::Certified
            } else {
                MatchStatus::Verified
            }
        },
        |(_, status)| status,
    )
}

fn violators(jobs: &[&Job]) -> Vec<ParticipantId> {
    let mut v: Vec<ParticipantId> = jobs
        .iter()
        .filter(|j| j.state == JobState::ViolationProven)
        .filter_map(|j| j.accused)
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

fn covered(jobs: &[&Job], required: &[Family]) -> bool {
    required.iter().all(|f| {
        jobs.iter()
            .any(|j| j.spec.family == *f && j.state.satisfies_dependency())
    })
}

/// Where a match's ranking and rewards stand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settlement {
    /// Ranked, but rewards not yet released.
    Provisional,
    /// The evidence did not complete (no verdict either way): rewards wait. Not a penalty.
    Held,
    /// Certified: ranking is final and rewards were released.
    Final,
    /// A violation was proven before release: rewards of the accused are forfeited.
    Forfeited,
    /// A violation was proven after the result was final: rewards are clawed back and the
    /// ranking is recomputed without the accused.
    Corrected,
}

impl Settlement {
    fn code(self) -> u8 {
        self as u8
    }
    fn from_code(v: u8) -> Option<Self> {
        [
            Self::Provisional,
            Self::Held,
            Self::Final,
            Self::Forfeited,
            Self::Corrected,
        ]
        .get(usize::from(v))
        .copied()
    }
}

/// What the application should do now. Each action is idempotent per match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Nothing,
    ReleaseRewards,
    HoldRewards,
    Forfeit { accused: Vec<ParticipantId> },
    Correct { accused: Vec<ParticipantId> },
}

/// The one settlement rule. Total over (state, status) so replaying statuses after a restart
/// cannot reach an unhandled combination.
pub fn decide(prev: Settlement, status: &MatchStatus) -> (Settlement, Action) {
    use Settlement::{Corrected, Final, Forfeited, Held, Provisional};
    match (prev, status) {
        (Forfeited | Corrected, _) => (prev, Action::Nothing),
        (Final, MatchStatus::ViolationProven { accused }) => (
            Corrected,
            Action::Correct {
                accused: accused.clone(),
            },
        ),
        (_, MatchStatus::ViolationProven { accused }) => (
            Forfeited,
            Action::Forfeit {
                accused: accused.clone(),
            },
        ),
        (Provisional | Held, MatchStatus::Certified) => (Final, Action::ReleaseRewards),
        (Provisional, MatchStatus::Uncertified | MatchStatus::Expired | MatchStatus::Failed) => {
            (Held, Action::HoldRewards)
        }
        _ => (prev, Action::Nothing),
    }
}

/// Settlement per match. Persist it with the application's own state (`encode`) so a violation
/// proven after a restart is still recognized as late.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    matches: BTreeMap<MatchId, Settlement>,
}

impl Ledger {
    pub fn get(&self, m: &MatchId) -> Settlement {
        self.matches
            .get(m)
            .copied()
            .unwrap_or(Settlement::Provisional)
    }

    /// Apply the latest status of a match; returns what to do about it.
    pub fn update(&mut self, m: MatchId, status: &MatchStatus) -> Action {
        let (next, action) = decide(self.get(&m), status);
        self.matches.insert(m, next);
        action
    }

    pub fn encode(&self) -> Vec<u8> {
        self.matches
            .iter()
            .flat_map(|(m, s)| m.iter().copied().chain([s.code()]))
            .collect()
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() % 33 != 0 {
            return None;
        }
        let matches = b
            .chunks_exact(33)
            .map(|c| Some((c[..32].try_into().ok()?, Settlement::from_code(c[32])?)))
            .collect::<Option<_>>()?;
        Some(Self { matches })
    }
}
