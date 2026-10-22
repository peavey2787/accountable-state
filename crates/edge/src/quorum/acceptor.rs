//! Witness side of the head register: one durable `{promised, accepted}` cell per owner.
//!
//! The cell is persisted *before* any promise or receipt that depends on it is returned, so a
//! witness that crashes and restarts can never contradict an answer it already gave. A cell that
//! cannot be persisted yields no answer at all (fail closed).
use super::set::Ballot;
use super::wire::{Claim, Nack, Promise, QuorumMsg, Receipt, Recover};
use gv_core::{MatchId, ParticipantId};
use gv_sig::SigningKey;

/// Why a `Store` was not receipted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Same ballot and sequence but a different head: the owner signed two heads.
    Conflict,
    /// An older sequence than the one already accepted under this ballot.
    Stale,
}

/// Durable per-owner state. Opaque bytes to the caller; see [`Cell::encode`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cell {
    promised: Option<Ballot>,
    accepted: Option<Claim>,
}

impl Cell {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        match &self.promised {
            Some(b) => {
                o.push(1);
                o.extend_from_slice(&b.bytes());
            }
            None => o.push(0),
        }
        if let Some(c) = &self.accepted {
            o.extend_from_slice(&c.encode());
        }
        o
    }
    /// `None` means the bytes are corrupt: the caller must treat the witness as failed for this
    /// owner rather than start from an empty cell.
    pub fn decode(b: &[u8]) -> Option<Self> {
        let (&flag, rest) = b.split_first()?;
        let (promised, rest) = match flag {
            0 => (None, rest),
            1 if rest.len() >= Ballot::WIRE => {
                let (p, r) = rest.split_at(Ballot::WIRE);
                (Some(Ballot::from_bytes(p.try_into().ok()?)), r)
            }
            _ => return None,
        };
        let accepted = if rest.is_empty() {
            None
        } else {
            Some(Claim::decode(rest).ok()?)
        };
        Some(Self { promised, accepted })
    }
    pub fn promised(&self) -> Option<Ballot> {
        self.promised
    }
    pub fn accepted(&self) -> Option<&Claim> {
        self.accepted.as_ref()
    }
    fn floor(&self) -> Option<Ballot> {
        self.promised
    }
    fn promise(&mut self, ballot: Ballot) -> bool {
        if self.floor().is_some_and(|p| p > ballot) {
            return false;
        }
        self.promised = Some(ballot);
        true
    }
    fn admit(&self, claim: &Claim) -> Result<(), Refusal> {
        let Some(held) = &self.accepted else {
            return Ok(());
        };
        if claim.ballot != held.ballot {
            return Ok(());
        }
        match claim.auth.seq.cmp(&held.auth.seq) {
            std::cmp::Ordering::Greater => Ok(()),
            std::cmp::Ordering::Less => Err(Refusal::Stale),
            std::cmp::Ordering::Equal if claim.auth.head != held.auth.head => {
                Err(Refusal::Conflict)
            }
            std::cmp::Ordering::Equal if claim.through_tick >= held.through_tick => Ok(()),
            std::cmp::Ordering::Equal => Err(Refusal::Stale),
        }
    }
}

/// Persists a cell; returns false if the write did not reach durable storage.
pub type Persist<'a> = &'a mut dyn FnMut(&MatchId, &ParticipantId, &[u8]) -> bool;

pub struct Acceptor {
    key: SigningKey,
}

impl Acceptor {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }
    pub fn id(&self) -> ParticipantId {
        self.key.id()
    }

    /// Handle an owner's `Recover` or `Store`. Returns the signed reply, or `None` when the
    /// request is invalid, refused as a conflict, or could not be made durable.
    pub fn handle(
        &self,
        cell: &mut Cell,
        msg: &QuorumMsg,
        persist: Persist<'_>,
    ) -> Option<QuorumMsg> {
        match msg {
            QuorumMsg::Recover(r) => self.recover(cell, r, persist),
            QuorumMsg::Store(c) => self.store(cell, c, persist),
            _ => None,
        }
    }

    fn recover(&self, cell: &mut Cell, r: &Recover, persist: Persist<'_>) -> Option<QuorumMsg> {
        r.verify().ok()?;
        let before = cell.clone();
        if !cell.promise(r.ballot) {
            return Some(self.nack(r.match_id, r.owner, r.ballot, before.promised?));
        }
        if !persist(&r.match_id, &r.owner, &cell.encode()) {
            *cell = before;
            return None;
        }
        Some(QuorumMsg::Promise(Promise::sign(
            r.match_id,
            r.owner,
            r.ballot,
            cell.accepted.clone(),
            &self.key,
        )))
    }

    fn store(&self, cell: &mut Cell, c: &Claim, persist: Persist<'_>) -> Option<QuorumMsg> {
        c.verify().ok()?;
        let (m, o) = (c.auth.match_id, c.owner());
        if let Some(p) = cell.promised.filter(|p| *p > c.ballot) {
            return Some(self.nack(m, o, c.ballot, p));
        }
        cell.admit(c).ok()?;
        let before = cell.clone();
        cell.promised = Some(c.ballot);
        cell.accepted = Some(c.clone());
        if !persist(&m, &o, &cell.encode()) {
            *cell = before;
            return None;
        }
        Some(QuorumMsg::Receipt(Receipt::sign(c, &self.key)))
    }

    fn nack(&self, m: MatchId, o: ParticipantId, refused: Ballot, promised: Ballot) -> QuorumMsg {
        QuorumMsg::Nack(Nack::sign(m, o, refused, promised, &self.key))
    }

    /// Answer a `HeldReq`: the accepted claim if it is at least `seq`, with this witness's receipt.
    pub fn held(&self, cell: &Cell, seq: u64) -> Option<QuorumMsg> {
        let claim = cell.accepted.as_ref().filter(|c| c.auth.seq >= seq)?;
        Some(QuorumMsg::Held {
            claim: claim.clone(),
            receipt: Receipt::sign(claim, &self.key),
        })
    }
}
