//! Authenticated, persistent evidence event stream.
//!
//! Every published event gets a monotonically increasing persistent id and an ML-DSA-65
//! signature by the publishing participant, and is appended (and synced) to a record file before
//! it is offered to any live subscriber. A subscriber that was slow, absent or restarted notices
//! a gap in ids and recovers the missed events from the store with [`FeedStore::since`] (in
//! process) or [`read_since`] (from another process). Events are announcements: the exportable,
//! independently verifiable package that an `Evidence` event commits to remains authoritative.
//! A feed event is never a verdict by itself and carries no timeout-derived accusation.
use crate::audit::store::RecordFile;
use crate::audit::Status;
use crate::export::{Commitment, ExportEvent};
use gv_core::{MatchId, ParticipantId};
use gv_sig::{verify, Signature, SigningKey, SIG_LEN};
use std::io;
use std::path::Path;

pub const EVENT_MAGIC: &[u8; 17] = b"GV-FEED-EVENT/V1\0";
const LABEL: &str = "GV-FEED-EVENT/V1";
/// Events kept in memory for fast replay; older ones are read back from the file.
const MEMORY: usize = 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum FeedError {
    Malformed,
    BadSignature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedEvent {
    pub publisher: ParticipantId,
    pub match_id: MatchId,
    /// Persistent, strictly increasing, gap-free per publisher and match.
    pub id: u64,
    pub event: ExportEvent,
    pub signature: Signature,
}

fn status_byte(s: Status) -> u8 {
    s as u8
}
fn status_of(b: u8) -> Option<Status> {
    use Status::*;
    [
        Pending,
        Cleared,
        Inconclusive,
        Unavailable,
        SuspectedNonCooperation,
        ProvenFraud,
        ProvenEquivocation,
    ]
    .into_iter()
    .find(|s| status_byte(*s) == b)
}

fn event_body(e: &ExportEvent) -> Vec<u8> {
    let mut o = Vec::new();
    match e {
        ExportEvent::Evidence {
            accused,
            commitment,
        } => {
            o.push(1);
            o.extend_from_slice(accused);
            o.extend_from_slice(&commitment.encode());
        }
        ExportEvent::Checkpoint { epoch_start, hash } => {
            o.push(2);
            o.extend_from_slice(&epoch_start.to_le_bytes());
            o.extend_from_slice(hash);
        }
        ExportEvent::Audit { challenge, status } => {
            o.push(3);
            o.extend_from_slice(challenge);
            o.push(status_byte(*status));
        }
    }
    o
}

fn event_from(b: &[u8]) -> Result<ExportEvent, FeedError> {
    let (&tag, r) = b.split_first().ok_or(FeedError::Malformed)?;
    match tag {
        1 if r.len() == 32 + Commitment::WIRE_SIZE => Ok(ExportEvent::Evidence {
            accused: r[..32].try_into().map_err(|_| FeedError::Malformed)?,
            commitment: Commitment::decode(&r[32..]).map_err(|_| FeedError::Malformed)?,
        }),
        2 if r.len() == 8 + 32 => Ok(ExportEvent::Checkpoint {
            epoch_start: u64::from_le_bytes(r[..8].try_into().map_err(|_| FeedError::Malformed)?),
            hash: r[8..].try_into().map_err(|_| FeedError::Malformed)?,
        }),
        3 if r.len() == 33 => Ok(ExportEvent::Audit {
            challenge: r[..32].try_into().map_err(|_| FeedError::Malformed)?,
            status: status_of(r[32]).ok_or(FeedError::Malformed)?,
        }),
        _ => Err(FeedError::Malformed),
    }
}

impl SignedEvent {
    fn signed_body(
        publisher: &ParticipantId,
        match_id: &MatchId,
        id: u64,
        e: &ExportEvent,
    ) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(publisher);
        o.extend_from_slice(match_id);
        o.extend_from_slice(&id.to_le_bytes());
        o.extend_from_slice(&event_body(e));
        o
    }
    pub fn sign(key: &SigningKey, match_id: MatchId, id: u64, event: ExportEvent) -> Self {
        let publisher = key.id();
        let signature = key.sign(LABEL, &Self::signed_body(&publisher, &match_id, id, &event));
        Self {
            publisher,
            match_id,
            id,
            event,
            signature,
        }
    }
    /// Check the signature against the publisher's key (which the verifier must already know,
    /// for example from its pinned roster file).
    pub fn verify(&self) -> Result<(), FeedError> {
        verify(
            &self.publisher,
            LABEL,
            &Self::signed_body(&self.publisher, &self.match_id, self.id, &self.event),
            &self.signature,
        )
        .map_err(|_| FeedError::BadSignature)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut o = EVENT_MAGIC.to_vec();
        o.extend_from_slice(&Self::signed_body(
            &self.publisher,
            &self.match_id,
            self.id,
            &self.event,
        ));
        o.extend_from_slice(self.signature.as_bytes());
        o
    }
    pub fn decode(b: &[u8]) -> Result<Self, FeedError> {
        let r = b
            .strip_prefix(EVENT_MAGIC.as_slice())
            .ok_or(FeedError::Malformed)?;
        if r.len() < 32 + 32 + 8 + 1 + SIG_LEN {
            return Err(FeedError::Malformed);
        }
        let (head, sig) = r.split_at(r.len() - SIG_LEN);
        let publisher: ParticipantId = head[..32].try_into().map_err(|_| FeedError::Malformed)?;
        let match_id: MatchId = head[32..64].try_into().map_err(|_| FeedError::Malformed)?;
        let id = u64::from_le_bytes(head[64..72].try_into().map_err(|_| FeedError::Malformed)?);
        let event = event_from(&head[72..])?;
        let me = Self {
            publisher,
            match_id,
            id,
            event,
            signature: Signature::from_slice(sig).map_err(|_| FeedError::Malformed)?,
        };
        // Canonical form: re-encoding must give the same bytes.
        if me.encode() != b {
            return Err(FeedError::Malformed);
        }
        Ok(me)
    }
}

/// Persist-then-publish store. Events are appended and synced here before any subscriber sees
/// them, so a subscriber's "last id seen" is always recoverable.
pub struct FeedStore {
    file: RecordFile,
    key: SigningKey,
    match_id: MatchId,
    next_id: u64,
    recent: std::collections::VecDeque<SignedEvent>,
}

impl FeedStore {
    /// Open (creating if needed). Ids continue after the last intact stored event of this
    /// publisher and match, so they stay persistent across restarts.
    pub fn open(path: &Path, key: SigningKey, match_id: MatchId) -> io::Result<Self> {
        let (file, records) = RecordFile::open(path)?;
        let mut next_id = 1;
        let mut recent = std::collections::VecDeque::new();
        for r in records {
            if let Ok(e) = SignedEvent::decode(&r) {
                if e.publisher == key.id()
                    && e.match_id == match_id
                    && e.id == next_id
                    && e.verify().is_ok()
                {
                    next_id += 1;
                    recent.push_back(e);
                    if recent.len() > MEMORY {
                        recent.pop_front();
                    }
                }
            }
        }
        Ok(Self {
            file,
            key,
            match_id,
            next_id,
            recent,
        })
    }
    /// Sign, persist (synced), and return the event for live fan-out.
    pub fn append(&mut self, event: ExportEvent) -> io::Result<SignedEvent> {
        let e = SignedEvent::sign(&self.key, self.match_id, self.next_id, event);
        self.file.append(&e.encode())?;
        self.next_id += 1;
        self.recent.push_back(e.clone());
        if self.recent.len() > MEMORY {
            self.recent.pop_front();
        }
        Ok(e)
    }
    pub fn last_id(&self) -> u64 {
        self.next_id - 1
    }
    /// Events with id greater than `after`, oldest first, at most `limit` (overflow recovery).
    pub fn since(&self, after: u64, limit: usize) -> Vec<SignedEvent> {
        if self.recent.front().is_none_or(|f| f.id <= after + 1) {
            return self
                .recent
                .iter()
                .filter(|e| e.id > after)
                .take(limit)
                .cloned()
                .collect();
        }
        read_since(self.file.path(), after, limit)
    }
}

/// Read events with id greater than `after` from a feed file, from any process. Returns only
/// events that decode and verify, in id order.
pub fn read_since(path: &Path, after: u64, limit: usize) -> Vec<SignedEvent> {
    let Ok(records) = RecordFile::read_all(path) else {
        return Vec::new();
    };
    records
        .iter()
        .filter_map(|r| SignedEvent::decode(r).ok())
        .filter(|e| e.id > after && e.verify().is_ok())
        .take(limit)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::{Commitment, FraudKind, PackageKind};

    const M: MatchId = [4; 32];
    fn key() -> SigningKey {
        SigningKey::from_seed([5; 32])
    }
    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("gv-feed-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn cp(i: u64) -> ExportEvent {
        ExportEvent::Checkpoint {
            epoch_start: i,
            hash: [i as u8; 32],
        }
    }
    fn evidence() -> ExportEvent {
        ExportEvent::Evidence {
            accused: [9; 32],
            commitment: Commitment {
                alg: 1,
                kind: PackageKind::FraudWitness,
                fraud: Some(FraudKind::Equivocation),
                match_id: M,
                ruleset: [1; 32],
                id: [2; 32],
            },
        }
    }

    #[test]
    fn events_are_signed_canonical_and_tamper_evident() {
        let e = SignedEvent::sign(&key(), M, 1, evidence());
        let bytes = e.encode();
        let back = SignedEvent::decode(&bytes).unwrap();
        assert_eq!(back, e);
        assert!(back.verify().is_ok());
        // Any flipped byte is rejected: by framing, canonical form or signature.
        for i in (0..bytes.len()).step_by(37) {
            let mut b = bytes.clone();
            b[i] ^= 1;
            let ok = SignedEvent::decode(&b)
                .map(|d| d.verify().is_ok())
                .unwrap_or(false);
            assert!(!ok, "byte {i}");
        }
        let mut wrong_id = e.clone();
        wrong_id.id = 2;
        assert!(wrong_id.verify().is_err(), "id is covered by the signature");
        assert!(SignedEvent::decode(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn ids_persist_across_restart_and_a_late_reader_resumes_from_its_cursor() {
        let d = dir("recover");
        let path = d.join("feed");
        let mut feed = FeedStore::open(&path, key(), M).unwrap();
        for i in 0..50 {
            feed.append(if i % 10 == 0 { evidence() } else { cp(i) })
                .unwrap();
        }
        let got = feed.since(0, usize::MAX);
        assert_eq!(got.len(), 50);
        assert!(got
            .iter()
            .enumerate()
            .all(|(i, e)| e.id == i as u64 + 1 && e.verify().is_ok()));
        assert_eq!(
            feed.since(45, 2).iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![46, 47]
        );
        drop(feed);
        // Restart: ids continue, nothing is renumbered, an external process can read them.
        let mut feed = FeedStore::open(&path, key(), M).unwrap();
        assert_eq!(feed.last_id(), 50);
        assert_eq!(feed.append(evidence()).unwrap().id, 51);
        let external = read_since(&path, 48, 100);
        assert_eq!(
            external.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![49, 50, 51]
        );
        assert!(external.iter().all(|e| e.verify().is_ok()));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn forged_and_foreign_records_in_the_file_are_ignored() {
        let d = dir("forged");
        let path = d.join("feed");
        {
            let mut s = FeedStore::open(&path, key(), M).unwrap();
            s.append(cp(1)).unwrap();
        }
        let other = SigningKey::from_seed([6; 32]);
        {
            let (mut f, _) = RecordFile::open(&path).unwrap();
            // Right id, wrong signer: a different participant's event.
            f.append(&SignedEvent::sign(&other, M, 2, cp(2)).encode())
                .unwrap();
            // A valid-looking record with a corrupted signature.
            let mut bad = SignedEvent::sign(&key(), M, 2, cp(2)).encode();
            let n = bad.len();
            bad[n - 5] ^= 1;
            f.append(&bad).unwrap();
        }
        let out = read_since(&path, 0, 100);
        assert_eq!(
            out.len(),
            2,
            "the foreign event verifies as its own publisher's; the corrupted one does not"
        );
        assert!(out.iter().all(|e| e.verify().is_ok()));
        // The owner's store skips both and keeps numbering from its own last valid event.
        let s = FeedStore::open(&path, key(), M).unwrap();
        assert_eq!(s.last_id(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }
}
