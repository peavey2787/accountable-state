//! Who takes part in a session and under which agreement: roster (participants, teams, roles),
//! how many signatures certify an epoch, and the within-tick event order.
use crate::{Digest, MatchId, ParticipantId};
use sha2::{Digest as _, Sha256};

pub const MAX_PARTICIPANTS: usize = 64;
pub const MAX_PARAMS_BYTES: usize = 64 * 1024;
const SESSION_DOMAIN: &[u8] = b"gv/session/v1\0";
const PARTICIPANT_WIRE: usize = 32 + 2 + 1;
/// Largest canonical session encoding: match id, roster, policy and parameters.
pub const MAX_SESSION_BYTES: usize =
    32 + 2 + MAX_PARTICIPANTS * PARTICIPANT_WIRE + 8 + MAX_PARAMS_BYTES;

/// What a participant may do. Witnesses are a separate, optional layer and are not roster members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Submits events and co-signs checkpoints.
    Player,
    /// A trusted orderer or dedicated server: submits events and co-signs, and may be required
    /// by the certification policy.
    Authority,
    /// Receives and verifies; submits nothing and signs nothing.
    Spectator,
}

impl Role {
    fn tag(self) -> u8 {
        match self {
            Self::Player => 0,
            Self::Authority => 1,
            Self::Spectator => 2,
        }
    }
    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Player),
            1 => Some(Self::Authority),
            2 => Some(Self::Spectator),
            _ => None,
        }
    }
    pub fn submits(self) -> bool {
        self != Self::Spectator
    }
    pub fn signs(self) -> bool {
        self != Self::Spectator
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Participant {
    pub id: ParticipantId,
    pub team: u16,
    pub role: Role,
}

impl Participant {
    pub fn player(id: ParticipantId, team: u16) -> Self {
        Self {
            id,
            team,
            role: Role::Player,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterError {
    Empty,
    TooMany,
    Duplicate,
    NoSigner,
    Truncated,
    BadRole,
    NonCanonical,
}

/// Participants in canonical (ascending id) order; the index is the stable slot used everywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster {
    participants: Vec<Participant>,
}

impl Roster {
    pub fn new(mut participants: Vec<Participant>) -> Result<Self, RosterError> {
        if participants.is_empty() {
            return Err(RosterError::Empty);
        }
        if participants.len() > MAX_PARTICIPANTS {
            return Err(RosterError::TooMany);
        }
        participants.sort_by_key(|p| p.id);
        if participants.windows(2).any(|w| w[0].id == w[1].id) {
            return Err(RosterError::Duplicate);
        }
        if !participants.iter().any(|p| p.role.signs()) {
            return Err(RosterError::NoSigner);
        }
        Ok(Self { participants })
    }
    /// A roster of players, each on a team of their own, in canonical order.
    pub fn players(ids: &[ParticipantId]) -> Result<Self, RosterError> {
        let participants = ids
            .iter()
            .enumerate()
            .map(|(i, id)| Participant::player(*id, i as u16))
            .collect();
        Self::new(participants)
    }
    pub fn len(&self) -> usize {
        self.participants.len()
    }
    pub fn is_empty(&self) -> bool {
        self.participants.is_empty()
    }
    pub fn participants(&self) -> &[Participant] {
        &self.participants
    }
    pub fn get(&self, slot: usize) -> Option<&Participant> {
        self.participants.get(slot)
    }
    pub fn index_of(&self, id: &ParticipantId) -> Option<usize> {
        self.participants.binary_search_by(|p| p.id.cmp(id)).ok()
    }
    pub fn find(&self, id: &ParticipantId) -> Option<&Participant> {
        self.index_of(id).map(|i| &self.participants[i])
    }
    pub fn contains(&self, id: &ParticipantId) -> bool {
        self.index_of(id).is_some()
    }
    /// Slots of participants that submit events, in canonical order.
    pub fn submitters(&self) -> Vec<usize> {
        self.slots_where(|p| p.role.submits())
    }
    /// Slots of participants whose signature counts toward certification.
    pub fn signers(&self) -> Vec<usize> {
        self.slots_where(|p| p.role.signs())
    }
    pub fn authorities(&self) -> Vec<usize> {
        self.slots_where(|p| p.role == Role::Authority)
    }
    fn slots_where(&self, keep: impl Fn(&Participant) -> bool) -> Vec<usize> {
        self.participants
            .iter()
            .enumerate()
            .filter(|(_, p)| keep(p))
            .map(|(i, _)| i)
            .collect()
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.participants.len() * PARTICIPANT_WIRE);
        out.extend_from_slice(&(self.participants.len() as u16).to_le_bytes());
        for p in &self.participants {
            out.extend_from_slice(&p.id);
            out.extend_from_slice(&p.team.to_le_bytes());
            out.push(p.role.tag());
        }
        out
    }
    /// Decode and return the bytes consumed. Only the canonical encoding is accepted.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), RosterError> {
        let count = bytes
            .get(..2)
            .map(|b| usize::from(u16::from_le_bytes([b[0], b[1]])))
            .ok_or(RosterError::Truncated)?;
        if count > MAX_PARTICIPANTS {
            return Err(RosterError::TooMany);
        }
        let end = 2 + count * PARTICIPANT_WIRE;
        let body = bytes.get(2..end).ok_or(RosterError::Truncated)?;
        let participants = body
            .chunks_exact(PARTICIPANT_WIRE)
            .map(Self::decode_participant)
            .collect::<Result<Vec<_>, _>>()?;
        let roster = Self::new(participants)?;
        if roster.encode() != bytes[..end] {
            return Err(RosterError::NonCanonical);
        }
        Ok((roster, end))
    }
    fn decode_participant(chunk: &[u8]) -> Result<Participant, RosterError> {
        let mut id = [0u8; 32];
        id.copy_from_slice(&chunk[..32]);
        Ok(Participant {
            id,
            team: u16::from_le_bytes([chunk[32], chunk[33]]),
            role: Role::from_tag(chunk[34]).ok_or(RosterError::BadRole)?,
        })
    }
}

/// How many signatures make an epoch certified. Fraud evidence never depends on this: it is
/// verifiable by anyone, and it is not global consensus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Certification {
    /// Every signer in the roster.
    Unanimous,
    /// At least `min` signers.
    Threshold { min: u16 },
    /// Every authority plus at least `min` signers overall.
    Authority { min: u16 },
}

impl Certification {
    fn encode(self, out: &mut Vec<u8>) {
        let (tag, min) = match self {
            Self::Unanimous => (0u8, 0u16),
            Self::Threshold { min } => (1, min),
            Self::Authority { min } => (2, min),
        };
        out.push(tag);
        out.extend_from_slice(&min.to_le_bytes());
    }
    fn decode(tag: u8, min: u16) -> Option<Self> {
        match (tag, min) {
            (0, 0) => Some(Self::Unanimous),
            (1, m) => Some(Self::Threshold { min: m }),
            (2, m) => Some(Self::Authority { min: m }),
            _ => None,
        }
    }
    /// Does this set of signer slots certify an epoch of `roster`?
    pub fn satisfied(self, roster: &Roster, signed: &[usize]) -> bool {
        let signers = roster.signers();
        let mut distinct: Vec<usize> = signed
            .iter()
            .filter(|s| signers.contains(s))
            .copied()
            .collect();
        distinct.sort_unstable();
        distinct.dedup();
        match self {
            Self::Unanimous => distinct.len() == signers.len(),
            Self::Threshold { min } => distinct.len() >= usize::from(min),
            Self::Authority { min } => {
                roster.authorities().iter().all(|a| distinct.contains(a))
                    && distinct.len() >= usize::from(min)
            }
        }
    }
    /// A policy no honest set can satisfy would stall every epoch; reject it at session start.
    fn achievable(self, roster: &Roster) -> bool {
        let signers = roster.signers().len();
        match self {
            Self::Unanimous => true,
            Self::Threshold { min } | Self::Authority { min } => {
                min >= 1 && usize::from(min) <= signers
            }
        }
    }
}

/// The deterministic order in which participants' events are applied within one tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ordering {
    /// Ascending participant id.
    Roster,
    /// Authorities first, then ascending id.
    AuthorityFirst,
    /// Start at slot `tick mod n`, wrapping: no participant is permanently first.
    Rotating,
}

impl Ordering {
    fn tag(self) -> u8 {
        match self {
            Self::Roster => 0,
            Self::AuthorityFirst => 1,
            Self::Rotating => 2,
        }
    }
    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Roster),
            1 => Some(Self::AuthorityFirst),
            2 => Some(Self::Rotating),
            _ => None,
        }
    }
    /// Slots of the submitters in the order their events apply at `tick`.
    pub fn order(self, roster: &Roster, tick: u64) -> Vec<usize> {
        let mut slots = roster.submitters();
        match self {
            Self::Roster => {}
            Self::AuthorityFirst => {
                slots.sort_by_key(|s| roster.get(*s).map(|p| p.role != Role::Authority));
            }
            Self::Rotating => {
                let n = slots.len().max(1);
                slots.rotate_left((tick % n as u64) as usize);
            }
        }
        slots
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    Roster(RosterError),
    Policy,
    ParamsTooLarge,
    /// Not the canonical encoding (truncated, trailing bytes, unknown tag).
    Malformed,
}

impl From<RosterError> for SessionError {
    fn from(e: RosterError) -> Self {
        Self::Roster(e)
    }
}

/// Everything honest nodes must agree on before a single event: the context `genesis` and
/// every checkpoint bind. `params` is opaque application configuration (map, mode, limits).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub match_id: MatchId,
    pub roster: Roster,
    pub certification: Certification,
    pub ordering: Ordering,
    pub params: Vec<u8>,
}

impl Session {
    pub fn new(
        match_id: MatchId,
        roster: Roster,
        certification: Certification,
        ordering: Ordering,
        params: Vec<u8>,
    ) -> Result<Self, SessionError> {
        if params.len() > MAX_PARAMS_BYTES {
            return Err(SessionError::ParamsTooLarge);
        }
        if !certification.achievable(&roster) {
            return Err(SessionError::Policy);
        }
        Ok(Self {
            match_id,
            roster,
            certification,
            ordering,
            params,
        })
    }
    /// Unanimous certification, roster order, no parameters.
    pub fn unanimous(match_id: MatchId, ids: &[ParticipantId]) -> Result<Self, SessionError> {
        Self::new(
            match_id,
            Roster::players(ids)?,
            Certification::Unanimous,
            Ordering::Roster,
            Vec::new(),
        )
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.match_id.to_vec();
        out.extend_from_slice(&self.roster.encode());
        self.certification.encode(&mut out);
        out.push(self.ordering.tag());
        out.extend_from_slice(&(self.params.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.params);
        out
    }
    /// Decode the canonical encoding; anything else, including trailing bytes, is refused.
    pub fn decode(bytes: &[u8]) -> Result<Self, SessionError> {
        let id: MatchId = bytes
            .get(..32)
            .and_then(|b| b.try_into().ok())
            .ok_or(SessionError::Malformed)?;
        let (roster, used) = Roster::decode(&bytes[32..])?;
        let rest = &bytes[32 + used..];
        let policy = rest.get(..4).ok_or(SessionError::Malformed)?;
        let certification =
            Certification::decode(policy[0], u16::from_le_bytes([policy[1], policy[2]]))
                .ok_or(SessionError::Malformed)?;
        let ordering = Ordering::from_tag(policy[3]).ok_or(SessionError::Malformed)?;
        let len: [u8; 4] = rest
            .get(4..8)
            .and_then(|b| b.try_into().ok())
            .ok_or(SessionError::Malformed)?;
        let params = rest
            .get(8..)
            .filter(|p| p.len() == u32::from_le_bytes(len) as usize)
            .ok_or(SessionError::Malformed)?;
        Self::new(id, roster, certification, ordering, params.to_vec())
    }
    pub fn digest(&self) -> Digest {
        let mut h = Sha256::new();
        h.update(SESSION_DOMAIN);
        h.update(self.encode());
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: u8) -> Vec<ParticipantId> {
        (1..=n).map(|i| [i; 32]).collect()
    }

    #[test]
    fn roster_is_canonical_and_rejects_bad_input() {
        let a = Roster::players(&[[2; 32], [1; 32], [3; 32]]).unwrap();
        assert_eq!(a.index_of(&[1; 32]), Some(0));
        assert_eq!(a.index_of(&[9; 32]), None);
        assert_eq!(Roster::players(&[]), Err(RosterError::Empty));
        assert_eq!(
            Roster::players(&[[1; 32], [1; 32]]),
            Err(RosterError::Duplicate)
        );
        let spectators = vec![Participant {
            id: [1; 32],
            team: 0,
            role: Role::Spectator,
        }];
        assert_eq!(Roster::new(spectators), Err(RosterError::NoSigner));
        let many = (0..=MAX_PARTICIPANTS)
            .map(|i| Participant::player([i as u8 + 1; 32], 0))
            .collect();
        assert_eq!(Roster::new(many), Err(RosterError::TooMany));
    }

    #[test]
    fn roster_round_trips_and_rejects_noncanonical() {
        let roster = Roster::new(vec![
            Participant::player([3; 32], 1),
            Participant {
                id: [1; 32],
                team: 0,
                role: Role::Authority,
            },
        ])
        .unwrap();
        let bytes = roster.encode();
        assert_eq!(Roster::decode(&bytes).unwrap(), (roster, bytes.len()));
        // Participants out of order are not a canonical encoding.
        let mut swapped = bytes.clone();
        let first = swapped[2..37].to_vec();
        let second = swapped[37..72].to_vec();
        swapped[2..37].copy_from_slice(&second);
        swapped[37..72].copy_from_slice(&first);
        assert_eq!(Roster::decode(&swapped), Err(RosterError::NonCanonical));
        assert_eq!(
            Roster::decode(&bytes[..bytes.len() - 1]),
            Err(RosterError::Truncated)
        );
    }

    #[test]
    fn certification_policies() {
        let roster = Roster::new(vec![
            Participant {
                id: [1; 32],
                team: 0,
                role: Role::Authority,
            },
            Participant::player([2; 32], 0),
            Participant::player([3; 32], 1),
            Participant {
                id: [4; 32],
                team: 1,
                role: Role::Spectator,
            },
        ])
        .unwrap();
        assert!(Certification::Unanimous.satisfied(&roster, &[0, 1, 2]));
        assert!(!Certification::Unanimous.satisfied(&roster, &[0, 1]));
        // A spectator's slot and repeated slots never count.
        assert!(!Certification::Threshold { min: 3 }.satisfied(&roster, &[0, 1, 1, 3]));
        assert!(Certification::Threshold { min: 2 }.satisfied(&roster, &[1, 2]));
        assert!(!Certification::Authority { min: 2 }.satisfied(&roster, &[1, 2]));
        assert!(Certification::Authority { min: 2 }.satisfied(&roster, &[0, 2]));
    }

    #[test]
    fn unachievable_policy_is_rejected_at_session_start() {
        let roster = Roster::players(&ids(3)).unwrap();
        let too_many = Session::new(
            [0; 32],
            roster.clone(),
            Certification::Threshold { min: 4 },
            Ordering::Roster,
            vec![],
        );
        assert_eq!(too_many, Err(SessionError::Policy));
        let zero = Session::new(
            [0; 32],
            roster,
            Certification::Threshold { min: 0 },
            Ordering::Roster,
            vec![],
        );
        assert_eq!(zero, Err(SessionError::Policy));
    }

    #[test]
    fn ordering_policies_are_deterministic() {
        let roster = Roster::new(vec![
            Participant::player([1; 32], 0),
            Participant::player([2; 32], 1),
            Participant {
                id: [3; 32],
                team: 0,
                role: Role::Authority,
            },
        ])
        .unwrap();
        assert_eq!(Ordering::Roster.order(&roster, 7), vec![0, 1, 2]);
        assert_eq!(Ordering::AuthorityFirst.order(&roster, 7), vec![2, 0, 1]);
        assert_eq!(Ordering::Rotating.order(&roster, 1), vec![1, 2, 0]);
        assert_eq!(Ordering::Rotating.order(&roster, 3), vec![0, 1, 2]);
    }

    #[test]
    fn digest_binds_every_field() {
        let base = Session::unanimous([9; 32], &ids(2)).unwrap();
        let mut other = base.clone();
        other.params = vec![1];
        assert_ne!(base.digest(), other.digest());
        let mut other = base.clone();
        other.ordering = Ordering::Rotating;
        assert_ne!(base.digest(), other.digest());
        let mut other = base.clone();
        other.match_id = [8; 32];
        assert_ne!(base.digest(), other.digest());
        assert_eq!(base.digest(), base.clone().digest());
    }

    #[test]
    fn session_round_trips_and_rejects_malformed() {
        let roster = Roster::players(&ids(3)).unwrap();
        let session = Session::new(
            [7; 32],
            roster,
            Certification::Threshold { min: 2 },
            Ordering::Rotating,
            vec![1, 2, 3],
        )
        .unwrap();
        let bytes = session.encode();
        assert_eq!(Session::decode(&bytes).unwrap(), session);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(Session::decode(&trailing), Err(SessionError::Malformed));
        assert_eq!(
            Session::decode(&bytes[..bytes.len() - 1]),
            Err(SessionError::Malformed)
        );
        let mut bad_policy = bytes.clone();
        let tag_at = 32 + session.roster.encode().len();
        bad_policy[tag_at] = 9;
        assert_eq!(Session::decode(&bad_policy), Err(SessionError::Malformed));
    }
}
