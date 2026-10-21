//! Checkpoint-driven recovery: never trust a disk receipt without independent
//! replay from a pinned genesis or already authenticated checkpoint.
#![forbid(unsafe_code)]
use super::{
    verify_checkpoint_evidence_with, CertifiedEpoch, CheckpointEvidence, EdgeError,
    EvidenceVerdict, MatchReplica, StateMachine,
};
use gv_core::{MatchId, PlayerId};

const MAGIC: &[u8] = b"GV-CERTIFIED-MATCH/V1\0";
const MAX_CERTIFICATES: usize = 16384;
const MAX_BYTES: usize = 512 * 1024 * 1024;

/// Append-only encoder with the exact layout of [`CertifiedMatch::encode`].
/// A long match certifies thousands of epochs; re-encoding the whole archive
/// after each one is quadratic, so each epoch is encoded once and appended.
pub struct ArchiveBuilder {
    bytes: Vec<u8>,
    /// Items (certified epochs and disputed epochs).
    count: usize,
    /// Certified epochs so far: where the next dispute is anchored.
    certified: usize,
    magic_len: usize,
}
const ITEM_CERTIFIED: u8 = 0;
const ITEM_DISPUTED: u8 = 1;
impl ArchiveBuilder {
    pub fn new(existing: &CertifiedMatch) -> Result<Self, EdgeError> {
        let bytes = existing.encode()?;
        Ok(Self {
            magic_len: MAGIC.len() + 1,
            count: existing.epochs.len() + existing.disputes.len(),
            certified: existing.epochs.len(),
            bytes,
        })
    }
    pub fn push(&mut self, epoch: &CertifiedEpoch) -> Result<(), EdgeError> {
        let body = epoch.encode().map_err(|_| EdgeError::BadCheckpoint)?;
        self.append_item(ITEM_CERTIFIED, &body)?;
        self.certified += 1;
        Ok(())
    }
    /// Record an epoch closed by proven fraud (no dual signature exists for it). The proof, with
    /// both players' signed inputs, lets a verifier replay the epoch and carry on from it.
    pub fn push_dispute(&mut self, proof: &CheckpointEvidence) -> Result<(), EdgeError> {
        let body = proof.encode().map_err(|_| EdgeError::BadCheckpoint)?;
        self.append_item(ITEM_DISPUTED, &body)
    }
    /// Number of certified epochs recorded (disputed epochs are separate).
    pub fn certified(&self) -> usize {
        self.certified
    }
    fn append_item(&mut self, tag: u8, body: &[u8]) -> Result<(), EdgeError> {
        if self.count >= MAX_CERTIFICATES {
            return Err(EdgeError::ResourceLimit);
        }
        let len = u32::try_from(body.len()).map_err(|_| EdgeError::ResourceLimit)?;
        if self.bytes.len().saturating_add(5 + body.len()) > MAX_BYTES {
            return Err(EdgeError::ResourceLimit);
        }
        self.bytes.push(tag);
        self.bytes.extend_from_slice(&len.to_le_bytes());
        self.bytes.extend_from_slice(body);
        self.count += 1;
        let at = self.magic_len;
        self.bytes[at..at + 4].copy_from_slice(&(self.count as u32).to_le_bytes());
        Ok(())
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn len(&self) -> usize {
        self.count
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// An epoch that was closed by proven fraud instead of two matching signatures. It stays in the
/// archive as an explicit, independently checkable gap: `proof` shows a signed claim that replay
/// of both players' signed inputs refutes, and the honest replay result is what the next
/// certified epoch links to.
#[derive(Clone, Debug)]
pub struct Dispute {
    /// Certified epochs that precede it (its position in the sequence).
    pub after: usize,
    pub proof: CheckpointEvidence,
}

#[derive(Clone, Debug)]
pub struct CertifiedMatch {
    pub epochs: Vec<CertifiedEpoch>,
    /// Disputed epochs in order, each anchored by how many certified epochs precede it.
    pub disputes: Vec<Dispute>,
    /// Produced by the live engine (sanitized replay).
    pub live: bool,
}
impl CertifiedMatch {
    pub fn encode(&self) -> Result<Vec<u8>, EdgeError> {
        if self.epochs.len() + self.disputes.len() > MAX_CERTIFICATES
            || self.disputes.iter().any(|d| d.after > self.epochs.len())
            || self.disputes.windows(2).any(|w| w[0].after > w[1].after)
        {
            return Err(EdgeError::ResourceLimit);
        }
        // Mode byte: 1 = produced by the live engine (replayed with illegal
        // controls neutralized), 0 = strict replay.
        let mut b = MAGIC.to_vec();
        b.push(u8::from(self.live));
        b.extend_from_slice(&((self.epochs.len() + self.disputes.len()) as u32).to_le_bytes());
        let item = |b: &mut Vec<u8>, tag: u8, bytes: Vec<u8>| -> Result<(), EdgeError> {
            let len = u32::try_from(bytes.len()).map_err(|_| EdgeError::ResourceLimit)?;
            if b.len()
                .checked_add(5 + bytes.len())
                .is_none_or(|n| n > MAX_BYTES)
            {
                return Err(EdgeError::ResourceLimit);
            }
            b.push(tag);
            b.extend_from_slice(&len.to_le_bytes());
            b.extend_from_slice(&bytes);
            Ok(())
        };
        let mut next_dispute = 0;
        for (i, epoch) in self.epochs.iter().enumerate() {
            while next_dispute < self.disputes.len() && self.disputes[next_dispute].after == i {
                let bytes = self.disputes[next_dispute]
                    .proof
                    .encode()
                    .map_err(|_| EdgeError::BadCheckpoint)?;
                item(&mut b, ITEM_DISPUTED, bytes)?;
                next_dispute += 1;
            }
            let bytes = epoch.encode().map_err(|_| EdgeError::BadCheckpoint)?;
            item(&mut b, ITEM_CERTIFIED, bytes)?;
        }
        for d in &self.disputes[next_dispute..] {
            let bytes = d.proof.encode().map_err(|_| EdgeError::BadCheckpoint)?;
            item(&mut b, ITEM_DISPUTED, bytes)?;
        }
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self, EdgeError> {
        if b.len() > MAX_BYTES || !b.starts_with(MAGIC) {
            return Err(EdgeError::BadCheckpoint);
        }
        let live = match b.get(MAGIC.len()) {
            Some(0) => false,
            Some(1) => true,
            _ => return Err(EdgeError::BadCheckpoint),
        };
        let mut pos = MAGIC.len() + 1;
        fn take<'a>(b: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], EdgeError> {
            let end = pos.checked_add(n).ok_or(EdgeError::BadCheckpoint)?;
            let part = b.get(*pos..end).ok_or(EdgeError::BadCheckpoint)?;
            *pos = end;
            Ok(part)
        }
        let count = u32::from_le_bytes(
            take(b, &mut pos, 4)?
                .try_into()
                .map_err(|_| EdgeError::BadCheckpoint)?,
        ) as usize;
        if count > MAX_CERTIFICATES {
            return Err(EdgeError::ResourceLimit);
        }
        let mut epochs = Vec::new();
        let mut disputes = Vec::new();
        for _ in 0..count {
            let tag = take(b, &mut pos, 1)?[0];
            let n = u32::from_le_bytes(
                take(b, &mut pos, 4)?
                    .try_into()
                    .map_err(|_| EdgeError::BadCheckpoint)?,
            ) as usize;
            if n > 4_000_000 {
                return Err(EdgeError::ResourceLimit);
            }
            let body = take(b, &mut pos, n)?;
            match tag {
                ITEM_CERTIFIED => {
                    epochs.push(CertifiedEpoch::decode(body).map_err(|_| EdgeError::BadCheckpoint)?)
                }
                ITEM_DISPUTED => disputes.push(Dispute {
                    after: epochs.len(),
                    proof: CheckpointEvidence::decode(body)
                        .map_err(|_| EdgeError::BadCheckpoint)?,
                }),
                _ => return Err(EdgeError::BadCheckpoint),
            }
        }
        if pos != b.len() {
            return Err(EdgeError::BadCheckpoint);
        }
        let me = Self {
            epochs,
            disputes,
            live,
        };
        // Canonical: re-encoding must reproduce the input.
        if me.encode()? != b {
            return Err(EdgeError::BadCheckpoint);
        }
        Ok(me)
    }
    /// Replay from a match ID, known ruleset and authenticated player roster.
    /// This accepts NO unauthenticated snapshots and validates EVERY predecessor.
    pub fn restore<R: StateMachine>(
        &self,
        match_id: MatchId,
        roster: [PlayerId; 2],
        rules: R,
    ) -> Result<MatchReplica<R>, EdgeError> {
        let mut replica = MatchReplica::new(match_id, roster, rules)?;
        if self.live {
            replica = replica.live();
        }
        let mut next_dispute = 0;
        for (i, cert) in self.epochs.iter().enumerate() {
            while next_dispute < self.disputes.len() && self.disputes[next_dispute].after == i {
                self.apply_dispute(&mut replica, match_id, &self.disputes[next_dispute].proof)?;
                next_dispute += 1;
            }
            let witnesses = &cert.witnesses;
            let claim = &witnesses[0].accused.claim;
            if claim.match_id != match_id
                || claim.epoch_start != replica.next_tick()
                || claim.previous_checkpoint != replica.previous_checkpoint()
                || witnesses[0].roster != replica.roster
                || cert.verify_with(
                    &replica.rules,
                    replica.previous_checkpoint(),
                    gv_commitments::commit_state(&gv_core::StateOpening {
                        bytes: replica.state().to_vec(),
                        nonce: [0; 32],
                    }),
                    self.live,
                ) != EvidenceVerdict::ValidClaim
            {
                return Err(EdgeError::BadCheckpoint);
            }
            for batch in &witnesses[0].player_batches {
                replica.admit(batch.clone())?;
            }
            if replica.candidate()?.checkpoint != *claim {
                return Err(EdgeError::BadCheckpoint);
            }
            let signatures = [witnesses[0].accused.clone(), witnesses[1].accused.clone()];
            replica.finalize(signatures)?;
        }
        for d in &self.disputes[next_dispute..] {
            self.apply_dispute(&mut replica, match_id, &d.proof)?;
        }
        Ok(replica)
    }
    /// Advance over a disputed epoch: the proof must show a signed claim for exactly this
    /// position that replay of the signed inputs refutes. The honest replay result becomes the
    /// chain head, so the continuation is linked to it and not to anything either player signed.
    fn apply_dispute<R: StateMachine>(
        &self,
        replica: &mut MatchReplica<R>,
        match_id: MatchId,
        proof: &CheckpointEvidence,
    ) -> Result<(), EdgeError> {
        let claim = &proof.accused.claim;
        if claim.match_id != match_id
            || claim.epoch_start != replica.next_tick()
            || claim.previous_checkpoint != replica.previous_checkpoint()
            || proof.roster != replica.roster
            || proof.trusted_previous_checkpoint != replica.previous_checkpoint()
            || proof.trusted_previous_state
                != gv_commitments::commit_state(&gv_core::StateOpening {
                    bytes: replica.state().to_vec(),
                    nonce: [0; 32],
                })
            || verify_checkpoint_evidence_with(&replica.rules, proof, self.live)
                != EvidenceVerdict::ProvenInvalidState
        {
            return Err(EdgeError::BadCheckpoint);
        }
        for batch in &proof.player_batches {
            replica.admit(batch.clone())?;
        }
        if replica.candidate()?.checkpoint == *claim {
            return Err(EdgeError::BadCheckpoint);
        }
        replica.finalize_disputed()?;
        Ok(())
    }
    /// Disputed epochs recorded in this archive.
    pub fn disputed(&self) -> usize {
        self.disputes.len()
    }
    /// Maximal runs of certified epochs between disputed ones (the continuation segments).
    pub fn segments(&self) -> usize {
        let mut cuts: Vec<usize> = self.disputes.iter().map(|d| d.after).collect();
        cuts.push(self.epochs.len());
        let mut prev = 0;
        let mut n = 0;
        for c in cuts {
            if c > prev {
                n += 1;
            }
            prev = c;
        }
        n
    }
}
