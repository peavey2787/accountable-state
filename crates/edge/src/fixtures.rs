//! Shared builders for the protocol tests: a cast of keyed participants in roster order and
//! signed Held batches of grid controls (a change at offset 1 only when it differs).
use crate::testkit::GridRules;
use crate::{CertifiedEpoch, MatchReplica};
use gv_codec::{EventBatch, EventBody, HeldChange, SignedEventBatch};
use gv_core::{Certification, Digest, MatchId, Ordering, Participant, Roster, Session};
use gv_sig::SigningKey;

pub(crate) const EPOCH: u32 = 4;

/// Keys sorted into roster order, so `keys[slot]` signs for roster slot `slot`.
pub(crate) struct Cast {
    pub keys: Vec<SigningKey>,
    pub session: Session,
}

impl Cast {
    pub fn new(n: u8, match_id: MatchId) -> Self {
        Self::with_policy(n, match_id, Certification::Unanimous)
    }
    pub fn with_policy(n: u8, match_id: MatchId, certification: Certification) -> Self {
        let mut keys: Vec<SigningKey> = (0..n)
            .map(|i| SigningKey::from_seed([31 + i * 10; 32]))
            .collect();
        keys.sort_by_key(SigningKey::id);
        let roster = Roster::new(
            keys.iter()
                .map(|k| Participant::player(k.id(), 0))
                .collect(),
        )
        .expect("roster");
        let session = Session::new(
            match_id,
            roster,
            certification,
            Ordering::Roster,
            Vec::new(),
        )
        .expect("session");
        Self { keys, session }
    }
    pub fn replica(&self) -> MatchReplica<GridRules> {
        MatchReplica::new(self.session.clone(), GridRules).expect("replica")
    }
}

pub(crate) fn controls(c: u16) -> Vec<u8> {
    c.to_le_bytes().to_vec()
}

/// A four-tick batch holding `initial`, switching to `then` at tick offset 1.
pub(crate) fn batch(
    key: &SigningKey,
    match_id: MatchId,
    start: u64,
    prev: Digest,
    initial: u16,
    then: u16,
) -> SignedEventBatch {
    SignedEventBatch::sign(
        EventBatch {
            match_id,
            participant: key.id(),
            previous_batch_hash: prev,
            start_tick: start,
            tick_count: EPOCH,
            body: EventBody::Held {
                initial: controls(initial),
                changes: if initial == then {
                    Vec::new()
                } else {
                    vec![HeldChange {
                        offset: 1,
                        payload: controls(then),
                    }]
                },
            },
        },
        key,
    )
    .expect("batch")
}

/// One batch per slot for the replica's next epoch, chained to each participant's last batch.
pub(crate) fn next_batches(
    cast: &Cast,
    replica: &MatchReplica<GridRules>,
    initial: u16,
    then: u16,
) -> Vec<Option<SignedEventBatch>> {
    cast.keys
        .iter()
        .map(|k| {
            let prev = replica.next_batch_head(k.id()).expect("head");
            Some(batch(
                k,
                cast.session.match_id,
                replica.next_tick(),
                prev,
                initial,
                then,
            ))
        })
        .collect()
}

/// Admit, sign by every participant and finalize one epoch directly (public play).
pub(crate) fn certify(
    cast: &Cast,
    replica: &mut MatchReplica<GridRules>,
    inputs: Vec<Option<SignedEventBatch>>,
) -> CertifiedEpoch {
    for b in inputs.into_iter().flatten() {
        replica.admit(b).expect("admit");
    }
    let sigs: Vec<_> = cast
        .keys
        .iter()
        .map(|k| replica.sign_candidate(k).expect("sign"))
        .collect();
    replica.finalize(sigs).expect("finalize");
    CertifiedEpoch::from_accepted(replica.accepted().last().expect("epoch"), &cast.session)
        .expect("certified")
}
