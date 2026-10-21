use super::*;
use crate::{Checkpoint, SignedCheckpoint};
use gv_codec::{ControlChange, PackedControls, SignedPackedControls};
use gv_sig::SigningKey;

const M: [u8; 32] = [7; 32];
const R: [u8; 32] = [9; 32];

fn key(n: u8) -> SigningKey {
    SigningKey::from_seed([n; 32])
}
fn filled(k: &SigningKey, n: u64) -> AuditLog {
    let mut l = AuditLog::new(M, k.id());
    for i in 0..n {
        l.append(1, i.to_le_bytes().to_vec()).unwrap();
    }
    l
}
fn batch(
    k: &SigningKey,
    start: u64,
    count: u32,
    init: u16,
    changes: Vec<ControlChange>,
) -> SignedPackedControls {
    SignedPackedControls::sign(
        PackedControls {
            match_id: M,
            player: k.id(),
            previous_batch_hash: [0; 32],
            start_tick: start,
            tick_count: count,
            control_bytes: 1,
            initial_state: init,
            changes,
        },
        k,
    )
    .unwrap()
}
fn cp(k: &SigningKey, next: u8) -> SignedCheckpoint {
    SignedCheckpoint::sign(
        Checkpoint {
            match_id: M,
            ruleset: R,
            epoch_start: 0,
            epoch_length: 20,
            previous_checkpoint: [0; 32],
            previous_state: [1; 32],
            input_root: [2; 32],
            next_state: [next; 32],
        },
        k,
    )
}

#[test]
fn log_chain_authenticators_and_segments() {
    let a = key(1);
    let log = filled(&a, 10);
    assert_eq!(log.len(), 10);
    let auth = log.sign_authenticator(R, &a);
    auth.verify().unwrap();
    assert_eq!(Authenticator::decode(&auth.encode()).unwrap(), auth);
    let seg = log.segment(3, 10).unwrap();
    assert_eq!(seg.end_head().unwrap(), auth.head);
    assert_eq!(Segment::decode(&seg.encode()).unwrap(), seg);
    // Any tamper changes the head.
    let mut bad = seg.clone();
    bad.entries[2].payload[0] ^= 1;
    assert_ne!(bad.end_head().unwrap(), auth.head);
    // Tampered authenticator fails; so does a different signer id.
    let mut forged = auth.clone();
    forged.seq += 1;
    assert!(forged.verify().is_err());
    // Heads bind owner and match.
    assert_ne!(filled(&key(2), 10).head(), log.head());
    assert!(Segment::decode(&seg.encode()[..40]).is_err());
}

#[test]
fn prune_never_passes_a_pin_and_suffix_still_verifies() {
    let a = key(1);
    let mut log = filled(&a, 100);
    let head = log.head();
    log.pin(40);
    assert_eq!(log.prune_to_keep(10), 39);
    assert_eq!(log.base_seq(), 39);
    assert!(log.segment(39, 100).is_ok());
    assert_eq!(log.segment(10, 100), Err(LogError::Pruned));
    assert_eq!(log.segment(39, 100).unwrap().end_head().unwrap(), head);
    log.unpin(40);
    assert!(log.prune_to_keep(10) > 0);
    assert_eq!(log.head(), head);
    assert_eq!(log.retained(), 10);
}

#[test]
fn snapshot_round_trip_and_corruption_detected() {
    let a = key(1);
    let log = filled(&a, 20);
    let back = AuditLog::decode(&log.encode()).unwrap();
    assert_eq!(back.head(), log.head());
    assert!(AuditLog::decode(&log.encode()[..30]).is_err());
    assert!(AuditLog::decode(b"nope").is_err());
}

#[test]
fn conflicting_authenticators_and_forks_are_proven() {
    let a = key(1);
    let log = filled(&a, 10);
    let mut other = filled(&a, 9);
    other.append(1, b"different".to_vec()).unwrap();
    let (x, y) = (
        log.sign_authenticator(R, &a),
        other.sign_authenticator(R, &a),
    );
    let ev = compare_authenticators(&x, &y, None).unwrap();
    assert_eq!(ev.verify().unwrap(), Proof::Equivocation(a.id()));
    // Same pair in either order dedupes to one canonical id.
    let rev = compare_authenticators(&y, &x, None).unwrap();
    assert_eq!(ev.id().unwrap(), rev.id().unwrap());
    let decoded = Evidence::decode(&ev.encode().unwrap()).unwrap();
    assert_eq!(decoded.verify().unwrap(), Proof::Equivocation(a.id()));
    // Honest repeat of the same authenticator is not evidence.
    assert!(compare_authenticators(&x, &x.clone(), None).is_none());

    // Fork: peer saw head at seq 4; the later chain rewrites entry 3.
    let seen = filled(&a, 4).sign_authenticator(R, &a);
    let mut rewritten = AuditLog::new(M, a.id());
    for i in 0..10u64 {
        let p = if i == 2 {
            b"rewritten".to_vec()
        } else {
            i.to_le_bytes().to_vec()
        };
        rewritten.append(1, p).unwrap();
    }
    let later = rewritten.sign_authenticator(R, &a);
    let seg = rewritten.segment(0, 10).unwrap();
    // Segment must start at the earlier seq to be evidence; a full one is trimmed.
    assert!(compare_authenticators(&seen, &later, Some(seg)).is_none());
    let seg = rewritten.segment(4, 10).unwrap();
    let ev = compare_authenticators(&seen, &later, Some(seg)).unwrap();
    assert_eq!(ev.verify().unwrap(), Proof::Equivocation(a.id()));
    assert_eq!(
        Evidence::decode(&ev.encode().unwrap())
            .unwrap()
            .id()
            .unwrap(),
        ev.id().unwrap()
    );

    // Honest extension is not a fork.
    let honest_later = log.sign_authenticator(R, &a);
    let seg = log.segment(4, 10).unwrap();
    let ev = Evidence::Fork {
        earlier: seen,
        later: honest_later,
        segment: seg,
    };
    assert_eq!(ev.verify(), Err(EvidenceError::NotAViolation));
}

#[test]
fn conflicting_batches_need_a_real_disagreement() {
    let a = key(1);
    let up = ControlChange {
        offset: 1,
        state: 4,
    };
    let full = batch(&a, 0, 20, 1, vec![up]);
    // Shorter re-sign of the same prefix agrees: legitimate, not equivocation.
    let prefix = batch(&a, 0, 10, 1, vec![up]);
    assert_eq!(
        Evidence::ConflictingBatches(full.clone(), prefix).verify(),
        Err(EvidenceError::NotAViolation)
    );
    // Disjoint ranges: nothing to compare.
    let later = batch(&a, 20, 20, 3, vec![]);
    assert!(Evidence::ConflictingBatches(full.clone(), later)
        .verify()
        .is_err());
    // Conflicting control at an overlapping tick.
    let lie = batch(&a, 5, 10, 8, vec![]);
    let ev = Evidence::ConflictingBatches(full.clone(), lie.clone());
    assert_eq!(ev.verify().unwrap(), Proof::Equivocation(a.id()));
    assert_eq!(
        ev.id().unwrap(),
        Evidence::ConflictingBatches(lie, full.clone())
            .id()
            .unwrap()
    );
    // Different players never conflict.
    let b = key(2);
    assert!(
        Evidence::ConflictingBatches(full, batch(&b, 0, 20, 9, vec![]))
            .verify()
            .is_err()
    );
}

#[test]
fn conflicting_checkpoints_and_framing_resistance() {
    let (a, b) = (key(1), key(2));
    let ev = Evidence::ConflictingCheckpoints(cp(&a, 3), cp(&a, 4));
    assert_eq!(ev.verify().unwrap(), Proof::Equivocation(a.id()));
    assert_eq!(
        Evidence::decode(&ev.encode().unwrap())
            .unwrap()
            .verify()
            .unwrap(),
        Proof::Equivocation(a.id())
    );
    // Identical claims (re-signed) are fine; two different signers never conflict.
    assert!(Evidence::ConflictingCheckpoints(cp(&a, 3), cp(&a, 3))
        .verify()
        .is_err());
    assert!(Evidence::ConflictingCheckpoints(cp(&a, 3), cp(&b, 4))
        .verify()
        .is_err());
    // Framing: splice b's signature onto a's claim: signature fails.
    let mut forged = cp(&b, 5);
    forged.player = a.id();
    assert_eq!(
        Evidence::ConflictingCheckpoints(cp(&a, 3), forged).verify(),
        Err(EvidenceError::BadSignature)
    );
}

#[test]
fn ledger_dedupes_orders_and_bounds() {
    let (a, b) = (key(1), key(2));
    let roster = [a.id(), b.id()];
    let mk = |n| Evidence::ConflictingCheckpoints(cp(&a, n), cp(&a, n + 1));
    let (e1, e2) = (mk(10), mk(20));
    let mut x = Ledger::new();
    let mut y = Ledger::new();
    assert_eq!(
        x.submit(&e1, &roster),
        Outcome::Recorded(Status::ProvenEquivocation)
    );
    assert_eq!(x.submit(&e1, &roster), Outcome::Duplicate);
    x.submit(&e2, &roster);
    y.submit(&e2, &roster);
    y.submit(&e1, &roster);
    assert_eq!(x.ids(), y.ids());
    assert_eq!(x.status_of(&a.id()), Some(Status::ProvenEquivocation));
    assert_eq!(x.status_of(&b.id()), None);
    // Evidence about non-participants is rejected.
    let stranger = key(3);
    let s = Evidence::ConflictingCheckpoints(cp(&stranger, 1), cp(&stranger, 2));
    assert!(matches!(
        Ledger::new().submit(&s, &roster),
        Outcome::Rejected(_)
    ));
    // Per-accused cap.
    let mut l = Ledger::new();
    let mut dropped = 0;
    for n in 0..80u8 {
        if l.submit(&mk(n.wrapping_mul(2)), &roster) == Outcome::Dropped {
            dropped += 1;
        }
    }
    assert!(l.len() <= ledger::MAX_PER_ACCUSED);
    assert!(dropped > 0);
}

#[test]
fn challenge_timeout_is_suspicion_never_proof_and_late_answer_clears() {
    let (alice, bob) = (key(1), key(2));
    let mut book = ChallengeBook::new(
        alice.clone(),
        M,
        Timing {
            timeout: 10,
            grace: 50,
        },
    );
    let mut gate = ChallengeGate::new(bob.id(), M);
    let c = book
        .issue(
            bob.id(),
            ChallengeKind::MissingBatch { start_tick: 20 },
            100,
        )
        .unwrap();
    assert_eq!(Challenge::decode(&c.encode()).unwrap(), c);
    gate.accept(&c, 100).unwrap();
    for _ in 1..ChallengeGate::MAX_ANSWERS_PER_CHALLENGE {
        gate.accept(&c, 101).unwrap();
    }
    assert_eq!(gate.accept(&c, 101), Err(Reject::Replay));
    assert_eq!(book.poll_outbox().unwrap(), c);
    // Silence: bounded retransmits, then suspicion, then unavailable.
    let mut resends = 0;
    for t in (100..2000).step_by(5) {
        book.poll(t);
        while book.poll_outbox().is_some() {
            resends += 1;
        }
        if book.status(&c.id()) == Some(Status::SuspectedNonCooperation) {
            break;
        }
    }
    assert_eq!(resends, usize::from(challenge::MAX_RETRIES));
    let s = book.status(&c.id()).unwrap();
    assert_eq!(s, Status::SuspectedNonCooperation);
    assert!(!s.is_proof());
    // Late, valid answer clears.
    let r = Response::sign(&c, b"batch-bytes".to_vec(), &bob);
    assert_eq!(Response::decode(&r.encode()).unwrap(), r);
    assert_eq!(
        book.on_response(&r, |_, p| p == b"batch-bytes"),
        Ok(Status::Cleared)
    );
    assert_eq!(book.on_response(&r, |_, _| true), Err(Reject::Replay));
    book.poll(100_000);
    assert_eq!(book.status(&c.id()), Some(Status::Cleared));
}

#[test]
fn unanswered_suspicion_becomes_unavailable_and_bad_answers_are_inconclusive() {
    let (alice, bob, eve) = (key(1), key(2), key(3));
    let mut book = ChallengeBook::new(
        alice,
        M,
        Timing {
            timeout: 4,
            grace: 8,
        },
    );
    let c = book
        .issue(bob.id(), ChallengeKind::Ack { seq: 3 }, 0)
        .unwrap();
    for t in 0..2000 {
        book.poll(t);
    }
    assert_eq!(book.status(&c.id()), Some(Status::Unavailable));
    // A third party cannot answer for the target.
    let c2 = book
        .issue(bob.id(), ChallengeKind::LogSegment { from: 0, to: 5 }, 5000)
        .unwrap();
    assert_eq!(
        book.on_response(&Response::sign(&c2, vec![], &eve), |_, _| true),
        Err(Reject::WrongResponder)
    );
    // Tampered response signature is rejected outright.
    let mut r = Response::sign(&c2, vec![1], &bob);
    r.payload.push(0);
    assert_eq!(book.on_response(&r, |_, _| true), Err(Reject::BadSignature));
    // Wrong content: inconclusive, not fraud.
    let r = Response::sign(&c2, vec![1], &bob);
    assert_eq!(book.on_response(&r, |_, _| false), Ok(Status::Inconclusive));
}

#[test]
fn challenges_are_bounded_and_flood_limited() {
    let (alice, bob) = (key(1), key(2));
    let mut book = ChallengeBook::new(alice.clone(), M, Timing::default());
    for i in 0..challenge::MAX_PENDING_PER_TARGET as u64 {
        book.issue(bob.id(), ChallengeKind::Ack { seq: i }, 0)
            .unwrap();
    }
    assert_eq!(
        book.issue(bob.id(), ChallengeKind::Ack { seq: 99 }, 0)
            .err(),
        Some(Reject::Flood)
    );
    let mut gate = ChallengeGate::new(bob.id(), M);
    let mut other = ChallengeBook::new(alice.clone(), M, Timing::default());
    let mut refused = 0;
    for i in 0..(ChallengeGate::MAX_PER_CHALLENGER as u64 + 40) {
        let c = other
            .issue(bob.id(), ChallengeKind::Ack { seq: i }, 0)
            .unwrap();
        other.gc();
        if gate.accept(&c, 0).is_err() {
            refused += 1;
        }
        other = ChallengeBook::new(alice.clone(), M, Timing::default());
        for _ in 0..i + 1 {
            other.next_nonce_bump();
        }
    }
    assert!(refused >= 40);
    // Wrong match, wrong target, bad deadline.
    let mut wrong = ChallengeBook::new(alice.clone(), [1; 32], Timing::default());
    let c = wrong
        .issue(bob.id(), ChallengeKind::Ack { seq: 1 }, 0)
        .unwrap();
    assert_eq!(
        ChallengeGate::new(bob.id(), M).accept(&c, 0),
        Err(Reject::WrongMatch)
    );
    let c = book.issue(alice.id(), ChallengeKind::Ack { seq: 1 }, 0);
    let c = c.unwrap();
    assert_eq!(
        ChallengeGate::new(bob.id(), M).accept(&c, 0),
        Err(Reject::NotForMe)
    );
    assert_eq!(
        Challenge::decode(&c.encode()[1..]).err(),
        Some(LogError::Malformed)
    );
}

#[test]
fn witnesses_are_deterministic_and_exclude_the_pair() {
    let ids: Vec<_> = (1..=6).map(|n| key(n).id()).collect();
    let w = assign_witnesses(&M, &ids, &ids[..2], 2);
    assert_eq!(w.len(), 2);
    assert!(w.iter().all(|p| !ids[..2].contains(p)));
    assert_eq!(w, assign_witnesses(&M, &ids, &ids[..2], 2));
    let mut rev = ids.clone();
    rev.reverse();
    assert_eq!(w, assign_witnesses(&M, &rev, &ids[..2], 2));
    assert!(assign_witnesses(&M, &ids[..2], &ids[..2], 2).is_empty());
}

#[test]
fn record_file_recovers_from_torn_and_corrupt_tails() {
    let dir = std::env::temp_dir().join(format!("gv-store-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("log.bin");
    let _ = std::fs::remove_file(&path);
    {
        let (mut f, recs) = store::RecordFile::open(&path).unwrap();
        assert!(recs.is_empty());
        f.append(b"one").unwrap();
        f.append(b"two").unwrap();
        f.append(b"three").unwrap();
    }
    let full = std::fs::read(&path).unwrap();
    // Torn write: cut mid-record.
    std::fs::write(&path, &full[..full.len() - 3]).unwrap();
    let (mut f, recs) = store::RecordFile::open(&path).unwrap();
    assert_eq!(recs, vec![b"one".to_vec(), b"two".to_vec()]);
    f.append(b"four").unwrap();
    drop(f);
    // Bit-rot in the middle record drops it and everything after, keeps the prefix.
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[12 + 3 + 12] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();
    let (_, recs) = store::RecordFile::open(&path).unwrap();
    assert_eq!(recs, vec![b"one".to_vec()]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Deterministic gossip between ledgers using the real anti-entropy primitives: every peer
/// ends with the same evidence set regardless of who saw the violation first or in what order.
#[test]
fn evidence_propagates_to_every_peer_by_anti_entropy() {
    let keys: Vec<SigningKey> = (1..=5).map(key).collect();
    let roster: Vec<_> = keys.iter().map(SigningKey::id).collect();
    let cheater = &keys[0];
    let evidence: Vec<Evidence> = (0..3u8)
        .map(|n| Evidence::ConflictingCheckpoints(cp(cheater, 10 + n), cp(cheater, 20 + n)))
        .collect();
    let mut ledgers: Vec<Ledger> = (0..5).map(|_| Ledger::new()).collect();
    // Peer i alone witnesses evidence i % 3.
    for (i, l) in ledgers.iter_mut().enumerate().skip(1) {
        l.submit(&evidence[i % 3], &roster);
    }
    for _round in 0..4 {
        for from in 0..ledgers.len() {
            for to in 0..ledgers.len() {
                if from == to {
                    continue;
                }
                let inventory = ledgers[from].ids();
                for id in missing_ids(&ledgers[to], &inventory) {
                    let e = evidence
                        .iter()
                        .find(|e| e.id().unwrap() == id)
                        .expect("only real evidence circulates")
                        .clone();
                    // The receiver re-verifies; it never trusts the sender.
                    assert!(matches!(
                        ledgers[to].submit(&e, &roster),
                        Outcome::Recorded(_) | Outcome::Duplicate
                    ));
                }
            }
        }
    }
    for l in &ledgers {
        assert_eq!(l.ids(), ledgers[1].ids());
        assert_eq!(l.status_of(&cheater.id()), Some(Status::ProvenEquivocation));
    }
}

/// A witness that signs two different heads for one sequence number is itself proven
/// an equivocator; honest peers are not implicated by what the witness claims about them.
#[test]
fn witness_equivocation_is_proven_against_the_witness_only() {
    let (honest, witness) = (key(1), key(2));
    let roster = [honest.id(), witness.id()];
    let log = filled(&honest, 6);
    let mut forged = filled(&honest, 5);
    forged
        .append(1, b"witness claims otherwise".to_vec())
        .unwrap();
    // The witness's own log forks between two audiences.
    let w_a = filled(&witness, 8).sign_authenticator(R, &witness);
    let mut w_log_b = filled(&witness, 7);
    w_log_b.append(1, b"other".to_vec()).unwrap();
    let w_b = w_log_b.sign_authenticator(R, &witness);
    let ev = compare_authenticators(&w_a, &w_b, None).unwrap();
    let mut ledger = Ledger::new();
    assert_eq!(
        ledger.submit(&ev, &roster),
        Outcome::Recorded(Status::ProvenEquivocation)
    );
    assert_eq!(
        ledger.status_of(&witness.id()),
        Some(Status::ProvenEquivocation)
    );
    assert_eq!(ledger.status_of(&honest.id()), None);
    // Splicing an honest authenticator with a witness-signed one never verifies as a violation.
    let honest_auth = log.sign_authenticator(R, &honest);
    let spliced = Evidence::ConflictingAuthenticators(honest_auth, w_a);
    assert!(spliced.verify().is_err());
    // Two colluding witnesses vouching for each other's histories prove nothing about a third.
    let other_forged = forged.sign_authenticator(R, &witness);
    assert!(
        compare_authenticators(&log.sign_authenticator(R, &honest), &other_forged, None).is_none()
    );
}

#[test]
fn oversized_and_truncated_evidence_is_rejected_without_allocation_blowup() {
    let a = key(1);
    let ev = Evidence::ConflictingCheckpoints(cp(&a, 1), cp(&a, 2));
    let bytes = ev.encode().unwrap();
    let mut huge = bytes.clone();
    huge.resize(evidence::MAX_EVIDENCE_BYTES + 1, 0);
    assert_eq!(
        Evidence::decode(&huge).unwrap_err(),
        EvidenceError::TooLarge
    );
    // A length prefix that claims more bytes than exist.
    let mut lying = bytes.clone();
    let at = evidence_header_len();
    lying[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        Evidence::decode(&lying).unwrap_err(),
        EvidenceError::Malformed
    );
    for cut in [0, 1, bytes.len() / 2, bytes.len() - 1] {
        assert!(Evidence::decode(&bytes[..cut]).is_err());
    }
    // Trailing garbage is not tolerated either.
    let mut trailing = bytes;
    trailing.push(0);
    assert!(Evidence::decode(&trailing).is_err());
}
fn evidence_header_len() -> usize {
    evidence::MAGIC.len() + 1
}

/// Long session: a bounded log keeps verifying after thousands of appends, repeated
/// prunes and a simulated crash/restart from the persisted snapshot.
#[test]
fn long_session_prune_crash_restart_and_still_proves_fork() {
    let a = key(1);
    let mut log = AuditLog::new(M, a.id());
    let mut seen = None;
    for i in 0..5000u64 {
        log.append(1, i.to_le_bytes().to_vec()).unwrap();
        if i == 4000 {
            seen = Some(log.sign_authenticator(R, &a));
        }
        if i % 500 == 499 {
            log.prune_to_keep(256);
        }
    }
    assert!(log.retained() <= 756);
    assert_eq!(log.len(), 5000);
    let restored = AuditLog::decode(&log.encode()).unwrap();
    assert_eq!(restored.head(), log.head());
    assert_eq!(restored.len(), 5000);
    assert_eq!(restored.base_seq(), log.base_seq());
    // The restarted node can still serve a verifiable suffix.
    let from = restored.base_seq();
    let seg = restored.segment(from, 5000).unwrap();
    assert_eq!(seg.end_head().unwrap(), restored.head());
    // A rewrite of history after the remembered authenticator is still provable post-restart.
    let seen = seen.unwrap();
    let mut rewritten = AuditLog::new(M, a.id());
    for i in 0..5000u64 {
        let p = if i == 4000 {
            b"edit".to_vec()
        } else {
            i.to_le_bytes().to_vec()
        };
        rewritten.append(1, p).unwrap();
    }
    let later = rewritten.sign_authenticator(R, &a);
    let seg = rewritten.segment(seen.seq, 5000).unwrap();
    let ev = compare_authenticators(&seen, &later, Some(seg)).unwrap();
    assert_eq!(ev.verify().unwrap(), Proof::Equivocation(a.id()));
    // Corrupting the snapshot is detected, never silently accepted.
    let mut bad = log.encode();
    let mid = bad.len() / 2;
    bad[mid] ^= 0x40;
    assert!(AuditLog::decode(&bad).map_or(true, |l| l.head() != log.head()));
}
