//! The witness side of the register: one durable [`Cell`] per owner, written before any reply.
use super::acceptor::{Acceptor, Cell};
use super::wire::QuorumMsg;
use crate::audit::fsync::replace_file;
use gv_core::{MatchId, ParticipantId};
use gv_sig::SigningKey;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::PathBuf;

/// Durable storage for acceptor cells. `save` returns only once the bytes survive a crash.
pub trait CellStore {
    /// `Ok(None)`: this owner has never been seen. `Err`: the record exists but is unreadable.
    fn load(&self, match_id: &MatchId, owner: &ParticipantId) -> io::Result<Option<Vec<u8>>>;
    fn save(&mut self, match_id: &MatchId, owner: &ParticipantId, bytes: &[u8]) -> io::Result<()>;
}

/// One atomically replaced file per (match, owner) under a directory.
pub struct FileCellStore {
    dir: PathBuf,
}

impl FileCellStore {
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }
    fn path(&self, m: &MatchId, o: &ParticipantId) -> PathBuf {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        self.dir
            .join(format!("{}-{}.cell", hex(&m[..8]), hex(&o[..16])))
    }
}

impl CellStore for FileCellStore {
    fn load(&self, m: &MatchId, o: &ParticipantId) -> io::Result<Option<Vec<u8>>> {
        match std::fs::read(self.path(m, o)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn save(&mut self, m: &MatchId, o: &ParticipantId, bytes: &[u8]) -> io::Result<()> {
        replace_file(&self.path(m, o), bytes)
    }
}

/// The acceptor role of a witness process. Fails closed: an unreadable or unwritable cell means
/// no reply for that owner, never a reply from reconstructed or forgotten state.
pub struct RegisterWitness<S: CellStore> {
    acceptor: Acceptor,
    store: S,
    cells: BTreeMap<(MatchId, ParticipantId), Cell>,
    poisoned: BTreeSet<(MatchId, ParticipantId)>,
}

impl<S: CellStore> RegisterWitness<S> {
    pub fn new(key: SigningKey, store: S) -> Self {
        Self {
            acceptor: Acceptor::new(key),
            store,
            cells: BTreeMap::new(),
            poisoned: BTreeSet::new(),
        }
    }

    pub fn id(&self) -> ParticipantId {
        self.acceptor.id()
    }

    /// Owners whose stored cell could not be trusted.
    pub fn poisoned(&self) -> usize {
        self.poisoned.len()
    }

    /// Answer an owner's request. Empty when the request is invalid, refused, or could not be
    /// made durable.
    pub fn handle(&mut self, match_id: MatchId, msg: &QuorumMsg) -> Vec<QuorumMsg> {
        let owner = match msg {
            QuorumMsg::Recover(r) => r.owner,
            QuorumMsg::Store(c) => c.owner(),
            QuorumMsg::HeldReq { owner, .. } => *owner,
            _ => return Vec::new(),
        };
        let key = (match_id, owner);
        if !self.load(&key) {
            return Vec::new();
        }
        let Some(cell) = self.cells.get_mut(&key) else {
            return Vec::new();
        };
        if let QuorumMsg::HeldReq { seq, .. } = msg {
            return self.acceptor.held(cell, *seq);
        }
        let store = &mut self.store;
        let mut persist = |m: &MatchId, o: &ParticipantId, b: &[u8]| store.save(m, o, b).is_ok();
        self.acceptor
            .handle(cell, msg, &mut persist)
            .into_iter()
            .collect()
    }

    fn load(&mut self, key: &(MatchId, ParticipantId)) -> bool {
        if self.cells.contains_key(key) {
            return true;
        }
        if self.poisoned.contains(key) {
            return false;
        }
        let cell = match self.store.load(&key.0, &key.1) {
            Ok(None) => Some(Cell::default()),
            Ok(Some(b)) => Cell::decode(&b),
            Err(_) => None,
        };
        match cell {
            Some(c) => {
                self.cells.insert(*key, c);
                true
            }
            None => {
                self.poisoned.insert(*key);
                false
            }
        }
    }
}
