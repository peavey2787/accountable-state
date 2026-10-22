use super::netsim::{busy, config, held, net, net_with, reference, Net, MATCH};
use super::*;
use crate::audit::{ChallengeKind, Status};
use crate::fixtures::{controls, Cast};
use crate::testkit::{self as grid, GridRules, GridState};
use gv_core::Certification;
use gv_replay::StateMachine;

fn ids(n: &Net) -> Vec<gv_core::ParticipantId> {
    n.cast.keys.iter().map(|k| k.id()).collect()
}
fn scripts_of(n: &Net) -> Vec<Vec<u16>> {
    n.peers.iter().map(|p| p.script.clone()).collect()
}
fn assert_matches_reference(n: &Net, peer: usize) {
    let t = n.peers[peer].pipe.verified_tick();
    assert_eq!(
        n.peers[peer].pipe.verified_state(),
        reference(&n.cast, &scripts_of(n), t).as_slice(),
        "peer {peer} at tick {t}"
    );
}
fn sent_count(n: &Net) -> usize {
    n.peers.iter().map(|p| p.sent.len()).sum()
}
fn sealed_config() -> PipelineConfig {
    let mut cfg = config();
    cfg.seal = Some(SealPolicy::default());
    cfg
}

#[test]
fn nobody_sends_anything_while_everyone_is_idle() {
    for peers in [2usize, 3, 4] {
        let mut n = net(vec![vec![]; peers], config(), 2);
        n.run(1200);
        assert!(n.peers.iter().all(|p| p.sent.is_empty()), "idle = silent");
        assert_eq!(n.peers[0].pipe.verified_tick(), 0);
    }
}

#[test]
fn one_active_player_proposes_the_idle_ones_answer_and_everyone_certifies() {
    let scripts = vec![held(grid::UP, 5, 9, 200), vec![], vec![]];
    let mut n = net(scripts, config(), 3);
    n.run(200);
    let a = n.finalized(0);
    assert!(!a.is_empty(), "an epoch was certified");
    assert!(n.agree(&[0, 1, 2]), "all certified identical epochs");
    assert_eq!(a[0], (0, 20, false), "first epoch ends on the 20-tick grid");
    assert_matches_reference(&n, 0);
    // An idle player only ever answers once; it never opens an epoch of its own.
    let batches = n.peers[1]
        .sent
        .iter()
        .filter(|(_, o)| matches!(o.msg, PipeMsg::Batch(_)))
        .count();
    assert_eq!(batches, 1);
    // Once certified, nothing more is exchanged.
    let before = sent_count(&n);
    n.run(600);
    assert_eq!(sent_count(&n), before);
}

#[test]
fn players_active_at_different_times_agree_on_the_shortest_epoch() {
    let scripts = vec![
        held(grid::RIGHT, 45, 50, 300),
        held(grid::LEFT, 22, 26, 300),
        held(grid::UP, 70, 75, 300),
    ];
    for delay in [0, 1, 5, 12, 25] {
        let mut n = net(scripts.clone(), config(), delay);
        n.run(300 + 6 * delay);
        assert!(n.agree(&[0, 1, 2]), "delay {delay}");
        assert!(
            n.finalized(0).len() >= 2,
            "delay {delay}: {:?}",
            n.finalized(0)
        );
        assert_matches_reference(&n, 0);
        assert!((0..3).all(|i| n.violations(i).is_empty()), "delay {delay}");
    }
}

#[test]
fn a_false_checkpoint_is_proven_by_every_honest_peer_and_play_continues() {
    let scripts = vec![
        held(grid::UP, 3, 60, 300),
        held(grid::DOWN, 10, 40, 300),
        held(grid::LEFT, 20, 50, 300),
    ];
    let mut n = net(scripts, config(), 2);
    n.run(10);
    n.peers[1].pipe.inject_cheat();
    n.run(290);
    let liar = ids(&n)[1];
    for i in 0..3 {
        let v = n.violations(i);
        assert_eq!(
            v.len(),
            1,
            "peer {i}: {:?}",
            v.iter().map(|x| x.kind).collect::<Vec<_>>()
        );
        assert_eq!(v[0].kind, ViolationKind::FalseCheckpoint);
        assert_eq!(v[0].accused, liar);
        assert!(!v[0].evidence.is_empty());
    }
    assert!(n.agree(&[0, 1, 2]));
    assert!(
        n.finalized(0).iter().any(|e| e.2),
        "unanimous certification became unreachable: closed by evidence"
    );
    assert!(
        n.finalized(0).iter().filter(|e| !e.2).count() >= 2,
        "play re-agreed"
    );
    assert_matches_reference(&n, 0);
}

#[test]
fn a_threshold_session_certifies_past_a_proven_liar_without_a_dispute() {
    let cast = Cast::with_policy(4, MATCH, Certification::Threshold { min: 3 });
    let scripts = vec![
        held(grid::UP, 3, 60, 300),
        held(grid::DOWN, 10, 40, 300),
        held(grid::LEFT, 20, 50, 300),
        held(grid::RIGHT, 5, 30, 300),
    ];
    let mut n = net_with(cast, scripts, config(), 2);
    n.run(10);
    n.peers[2].pipe.inject_cheat();
    n.run(290);
    let liar = ids(&n)[2];
    for i in [0, 1, 3] {
        let v = n.violations(i);
        assert!(v
            .iter()
            .all(|x| x.accused == liar && x.kind == ViolationKind::FalseCheckpoint));
        assert!(v.len() <= 1, "peer {i}");
    }
    let proofs: usize = [0, 1, 3].iter().map(|&i| n.violations(i).len()).sum();
    assert!(
        proofs >= 1,
        "the late, false claim is proven by whoever still judges it"
    );
    assert!(n.agree(&[0, 1, 3]));
    assert!(
        n.finalized(0).iter().all(|e| !e.2),
        "three honest signers met the policy"
    );
    assert_matches_reference(&n, 0);
}

#[test]
fn a_false_accusation_of_a_false_checkpoint_needs_replay_proof() {
    // An honest checkpoint is never judged false: nobody cheats, nothing is reported.
    let scripts = vec![busy(3, 400), busy(4, 400), busy(5, 400)];
    let mut n = net(scripts, config(), 3);
    n.run(400);
    assert!((0..3).all(|i| n.violations(i).is_empty()));
    assert!(n.agree(&[0, 1, 2]));
}

#[test]
fn a_signed_illegal_input_is_neutralized_proven_and_does_not_stall() {
    let mut a = held(grid::RIGHT, 2, 6, 200);
    for x in &mut a[10..14] {
        *x = 128; // unsupported control word
    }
    a[30] = grid::LEFT | grid::RIGHT; // contradictory
    let scripts = vec![a, held(grid::DOWN, 4, 8, 200), held(grid::UP, 6, 9, 200)];
    let mut n = net(scripts, config(), 2);
    n.run(200);
    let cheater = ids(&n)[0];
    for i in 0..3 {
        let v = n.violations(i);
        assert!(!v.is_empty(), "peer {i} saw the violation");
        assert!(v
            .iter()
            .all(|x| x.kind == ViolationKind::IllegalInput && x.accused == cheater));
    }
    assert_eq!(n.violations(0).len(), n.violations(1).len());
    assert!(n.agree(&[0, 1, 2]));
    assert!(
        n.finalized(0).iter().all(|e| !e.2),
        "both replayed the same sanitized epoch"
    );
    assert!(n.peers[0].pipe.verified_tick() >= 40);
    assert_matches_reference(&n, 0);
    // The evidence is portable and checkable by a third party.
    let ev = crate::CheckpointEvidence::decode(&n.violations(1)[0].evidence).unwrap();
    assert_eq!(
        crate::verify_checkpoint_evidence_with(&GridRules, &ev, true),
        crate::EvidenceVerdict::ValidClaim
    );
    // It exports as a self-verifying package checked with pinned facts only.
    use crate::export::*;
    let session = &n.cast.session;
    let anchor = TrustAnchor {
        match_id: MATCH,
        ruleset: GridRules.ruleset_hash(),
        session: session.digest(),
    };
    let pkg = export_fraud(
        &GridRules,
        session,
        FraudWitness::IllegalInput(&ev),
        DisclosurePolicy::PUBLIC,
    )
    .unwrap();
    let bytes = pkg.encode().unwrap();
    let (_, v) = verify_package(&bytes, &anchor, &GridRules).unwrap();
    assert_eq!(
        v,
        Verified::Fraud {
            kind: FraudKind::IllegalInput,
            accused: cheater
        }
    );
    let mut bad = bytes.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 1;
    assert!(verify_package(&bad, &anchor, &GridRules).is_err());
}

#[test]
fn a_sealed_window_commits_locks_and_reveals_and_leaks_nothing_until_the_end() {
    let scripts = vec![busy(11, 1000), busy(23, 1000), busy(31, 1000)];
    for delay in [0, 3, 9] {
        let mut n = net(scripts.clone(), sealed_config(), delay);
        n.run(100);
        n.peers[0].pipe.request_seal(100).unwrap();
        let (h0, h1) = (140u64, 440u64);
        n.run(1000);
        let owner = ids(&n)[0];
        // 1. No plaintext batch or reveal for the sealed ticks reached the wire before the end.
        for (at, o) in &n.peers[0].sent {
            match &o.msg {
                PipeMsg::Batch(b) => {
                    let (s, e) = (
                        b.record.start_tick,
                        b.record.start_tick + u64::from(b.record.tick_count),
                    );
                    assert!(
                        e <= h0 || s >= h1,
                        "delay {delay}: plaintext batch {s}..{e} at {at}"
                    );
                }
                PipeMsg::Reveal(b) => assert!(
                    *at >= h1,
                    "delay {delay}: early reveal at {at}: {}",
                    b.batch.record.start_tick
                ),
                _ => {}
            }
        }
        // 2. Commitments and locks flowed during the window.
        let commits = n.peers[0]
            .sent
            .iter()
            .filter(|(at, o)| matches!(o.msg, PipeMsg::Commit(_)) && *at < h1)
            .count();
        assert!(
            commits >= 10,
            "delay {delay}: progressive commitments: {commits}"
        );
        assert!(n.peers[0]
            .sent
            .iter()
            .any(|(_, o)| matches!(o.msg, PipeMsg::Lock { .. })));
        // 3. Observers learned nothing about the sealed inputs before the end.
        for obs in [1, 2] {
            for (at, e) in &n.peers[obs].events {
                if let PipeEvent::RemoteInputs {
                    participant,
                    from_tick,
                    ..
                } = e
                {
                    let sealed = participant == &owner && (h0..h1).contains(from_tick);
                    assert!(
                        !sealed || *at >= h1,
                        "delay {delay}: leaked tick {from_tick} at {at}"
                    );
                }
            }
        }
        // 4. After the reveal everything certifies and matches the replay.
        for i in 0..3 {
            let seen = |f: fn(&PipeEvent) -> bool| n.peers[i].events.iter().any(|(_, e)| f(e));
            assert!(
                seen(|e| matches!(e, PipeEvent::SealScheduled { .. })),
                "delay {delay}"
            );
            assert!(
                seen(|e| matches!(e, PipeEvent::SealRevealed { .. })),
                "delay {delay} peer {i}"
            );
            assert!(n.violations(i).is_empty(), "delay {delay} peer {i}");
        }
        assert!(n.agree(&[0, 1, 2]), "delay {delay}");
        assert!(n.peers[0].pipe.verified_tick() >= h1);
        assert_matches_reference(&n, 0);
        assert!(GridState::decode(n.peers[0].pipe.verified_state()).is_ok());
        // 5. Cooldown, then a second window is allowed.
        assert!(matches!(
            n.peers[0].pipe.request_seal(500),
            Err(SealError::Cooldown { .. })
        ));
        let after = n.peers[0].pipe.seal_cooldown_until();
        n.peers[0]
            .pipe
            .request_seal(after)
            .expect("allowed again after the cooldown");
    }
}

#[test]
fn sealed_windows_are_refused_without_a_policy_and_by_non_submitters() {
    let mut n = net(vec![vec![], vec![]], config(), 1);
    assert_eq!(n.peers[0].pipe.request_seal(0), Err(SealError::Disabled));
    let seal = {
        let mut sealed = net(vec![vec![], vec![]], sealed_config(), 1);
        sealed.peers[0].pipe.request_seal(0).unwrap();
        sealed.peers[0].pipe.poll_outbox().unwrap().msg
    };
    // A peer without a policy rejects the announcement instead of opening a window.
    n.inject(1, 0, seal);
    assert!(n.peers[1].pipe.seal_window().is_none());
}

#[test]
fn a_withheld_reveal_is_only_a_suspicion_and_stalls_only_the_certified_chain() {
    let scripts = vec![busy(5, 1900), busy(6, 1900), busy(7, 1900)];
    let mut n = net(scripts, sealed_config(), 2);
    n.drop = Box::new(|from, _, o| from == 0 && matches!(o.msg, PipeMsg::Reveal(_)));
    n.run(100);
    n.peers[0].pipe.request_seal(100).unwrap();
    n.run(1800);
    let owner = ids(&n)[0];
    for obs in [1, 2] {
        let suspected = n.peers[obs].events.iter().any(|(_, e)| {
            matches!(e, PipeEvent::Suspicion(s) if s.kind == SuspicionKind::WithheldReveal && s.subject == owner)
        });
        assert!(suspected, "peer {obs}");
        assert!(n.violations(obs).is_empty(), "withholding is never proof");
        assert!(
            n.peers[obs].pipe.verified_tick() <= 140,
            "sealed epochs cannot certify without a reveal"
        );
    }
}

#[test]
fn a_reveal_that_does_not_match_its_commitment_is_a_suspicion_not_proof() {
    use gv_codec::{EventBody, HeldChange, SignedEventBatch};
    let scripts = vec![busy(8, 1000), busy(9, 1000), busy(10, 1000)];
    let mut n = net(scripts, sealed_config(), 2);
    n.run(100);
    n.peers[0].pipe.request_seal(100).unwrap();
    n.drop = Box::new(|from, _, o| from == 0 && matches!(o.msg, PipeMsg::Reveal(_)));
    n.run(500);
    let reveals: Vec<_> = n.peers[0]
        .sent
        .iter()
        .filter_map(|(_, o)| match &o.msg {
            PipeMsg::Reveal(b) => Some(b.clone()),
            _ => None,
        })
        .collect();
    assert!(!reveals.is_empty());
    let key = n.cast.keys[0].clone();
    for b in reveals {
        let mut rec = b.batch.record.clone();
        rec.body = EventBody::Held {
            initial: controls(grid::ACT),
            changes: Vec::<HeldChange>::new(),
        };
        let lie = SignedEventBatch::sign(rec, &key).unwrap();
        n.inject(
            1,
            0,
            PipeMsg::Reveal(Opening {
                batch: lie,
                blind: b.blind,
            }),
        );
    }
    n.run(1);
    let bad = n.peers[1]
        .events
        .iter()
        .any(|(_, e)| matches!(e, PipeEvent::Suspicion(s) if s.kind == SuspicionKind::BadReveal));
    assert!(bad);
    assert!(
        n.violations(1).is_empty(),
        "an unauthenticated blind proves nothing"
    );
}

#[test]
fn a_lagging_responder_still_pairs_without_waiting_for_more_traffic() {
    let scripts = vec![held(grid::RIGHT, 45, 50, 400), vec![], vec![]];
    for skew in 1..=9u64 {
        for delay in [0, 2, 7] {
            let mut n = net(scripts.clone(), config(), delay);
            n.skew = vec![0, skew, skew / 2];
            n.run(260);
            assert!(
                !n.finalized(0).is_empty(),
                "skew {skew} delay {delay}: nothing certified"
            );
            assert!(n.agree(&[0, 1, 2]), "skew {skew} delay {delay}");
        }
    }
    let mut a = held(grid::UP, 3, 9, 400);
    a[100] = 128;
    let scripts = vec![a, held(grid::LEFT, 4, 7, 400), held(grid::DOWN, 5, 8, 400)];
    for skew in [[0, 3, 0], [3, 0, 1], [2, 5, 4]] {
        let mut n = net(scripts.clone(), config(), 4);
        n.skew = skew.to_vec();
        n.run(400);
        assert!(n.agree(&[0, 1, 2]), "skew {skew:?}");
        assert!(
            n.finalized(0).len() >= 2,
            "skew {skew:?}: {:?}",
            n.finalized(0)
        );
        assert_eq!(
            n.violations(0).len(),
            n.violations(1).len(),
            "skew {skew:?}"
        );
    }
}

#[test]
fn a_silent_member_is_closed_out_by_the_rotating_coordinator() {
    let cast = Cast::with_policy(4, MATCH, Certification::Threshold { min: 3 });
    let mut cfg = config();
    cfg.close_after_ticks = Some(60);
    let scripts = vec![busy(1, 600), busy(2, 600), busy(3, 600), busy(4, 600)];
    let mut n = net_with(cast, scripts, cfg, 2);
    n.offline[3] = true;
    n.run(600);
    assert!(n.agree(&[0, 1, 2]));
    assert!(
        n.peers[0].pipe.verified_tick() >= 100,
        "play went on without the silent member"
    );
    let silent = ids(&n)[3];
    let suspected = n.peers[0].events.iter().any(|(_, e)| {
        matches!(e, PipeEvent::Suspicion(s) if s.kind == SuspicionKind::Unresponsive && s.subject == silent)
    });
    assert!(suspected, "silence is a suspicion");
    assert!(n.violations(0).is_empty(), "never a conclusive verdict");
}

// ---- accountability (PeerReview-style) ------------------------------------

fn statuses(n: &Net, i: usize) -> Vec<Status> {
    n.peers[i]
        .events
        .iter()
        .filter_map(|(_, e)| match e {
            PipeEvent::Audit(AuditEvent::Challenge { status, .. }) => Some(*status),
            _ => None,
        })
        .collect()
}
fn busy_trio() -> Vec<Vec<u16>> {
    vec![
        held(grid::UP, 0, 3000, 3000),
        held(grid::LEFT, 0, 3000, 3000),
        held(grid::DOWN, 0, 3000, 3000),
    ]
}

#[test]
fn a_dishonest_peer_showing_two_histories_is_proven_offline() {
    let mut n = net(busy_trio(), config(), 2);
    n.run(120);
    n.peers[0]
        .pipe
        .auditor_mut()
        .equivocate_next_authenticator();
    n.run(400);
    let cheat = ids(&n)[0];
    let proofs: Vec<_> = n
        .violations(1)
        .into_iter()
        .filter(|v| v.kind == ViolationKind::LogEquivocation)
        .collect();
    assert!(!proofs.is_empty(), "equivocation detected");
    for v in &proofs {
        let ev = crate::audit::Evidence::decode(&v.evidence).unwrap();
        assert_eq!(
            ev.verify().unwrap(),
            crate::audit::Proof::Equivocation(v.accused)
        );
        assert_eq!(v.accused, cheat);
    }
    for i in 0..3 {
        assert!(
            n.violations(i).iter().all(|v| v.accused == cheat),
            "only the cheat is accused"
        );
    }
    assert!(
        n.finalized(1).len() > 10 && n.agree(&[0, 1, 2]),
        "play never stopped"
    );
}

#[test]
fn withholding_is_only_suspicion_and_a_late_answer_clears_it() {
    let mut n = net(busy_trio(), config(), 2);
    n.run(100);
    n.peers[0]
        .pipe
        .auditor_mut()
        .withhold_answers_until(100 + 700);
    let (now, target) = (n.now, ids(&n)[0]);
    n.peers[1]
        .pipe
        .auditor_mut()
        .challenge(target, ChallengeKind::Ack { seq: 1 }, now)
        .unwrap();
    n.run(1200);
    let s = statuses(&n, 1);
    assert!(s.contains(&Status::SuspectedNonCooperation), "{s:?}");
    assert_eq!(s.last(), Some(&Status::Cleared), "{s:?}");
    assert!(
        (0..3).all(|i| n.violations(i).is_empty()),
        "delay is never a cheating verdict"
    );
    assert_eq!(n.peers[1].pipe.auditor().stats().pending, 0);
}

#[test]
fn a_false_accusation_and_forged_evidence_prove_nothing() {
    let mut n = net(busy_trio(), config(), 2);
    n.run(200);
    let victim = n.peers[1]
        .sent
        .iter()
        .find_map(|(_, o)| match &o.msg {
            PipeMsg::Checkpoint(c) => Some(c.clone()),
            _ => None,
        })
        .unwrap();
    let (now, framed) = (n.now, ids(&n)[1]);
    n.peers[0]
        .pipe
        .auditor_mut()
        .send_forged_accusation(&victim);
    n.peers[0]
        .pipe
        .auditor_mut()
        .accuse_missing_batch(framed, 0, now);
    n.run(300);
    assert!(n.violations(1).is_empty(), "honest peer not framed");
    assert!(n.peers[1].pipe.auditor().stats().rejected_evidence >= 1);
    assert!(
        statuses(&n, 0).contains(&Status::Cleared),
        "the accused answers with the signed batch"
    );
    assert!(!statuses(&n, 0).contains(&Status::SuspectedNonCooperation));
}

#[test]
fn a_lossy_network_never_produces_a_cheating_verdict() {
    for seed in 0u64..4 {
        let mut n = net(busy_trio(), config(), 3);
        n.drop = Box::new(move |from, now, o| {
            matches!(
                o.msg,
                PipeMsg::Auth(_) | PipeMsg::Challenge(_) | PipeMsg::Response(_)
            ) && now
                .wrapping_mul(2654435761)
                .wrapping_add(seed * 7 + from as u64)
                % 3
                == 0
        });
        n.run(1500);
        for i in 0..3 {
            assert!(n.violations(i).is_empty(), "seed {seed} peer {i}");
        }
        assert!(n.finalized(0).len() > 20);
    }
}

#[test]
fn partition_then_heal_ends_cleared_not_accused() {
    let mut n = net(busy_trio(), config(), 2);
    n.run(100);
    n.drop = Box::new(|_, now, o| {
        matches!(o.msg, PipeMsg::Challenge(_) | PipeMsg::Response(_)) && (100..900).contains(&now)
    });
    let (now, target) = (n.now, ids(&n)[0]);
    n.peers[1]
        .pipe
        .auditor_mut()
        .challenge(target, ChallengeKind::Replay { epoch_start: 0 }, now)
        .unwrap();
    n.run(1800);
    assert_eq!(statuses(&n, 1).last(), Some(&Status::Cleared));
    assert!(n.violations(1).is_empty());
}

#[test]
fn audit_traffic_is_bounded_and_flooding_is_dropped() {
    use crate::audit::{ChallengeBook, Timing};
    let mut n = net(busy_trio(), config(), 2);
    n.run(60);
    let flooder = n.cast.keys[0].clone();
    let victim = ids(&n)[1];
    let mut spam = ChallengeBook::new(flooder.clone(), MATCH, Timing::default());
    let mut sent = 0;
    for i in 0..5000u64 {
        if let Ok(c) = spam.issue(victim, ChallengeKind::Ack { seq: i }, n.now) {
            let msg = PipeMsg::Challenge(c);
            n.inject_wire(1, 0, msg.encode().unwrap());
            sent += 1;
        }
        spam.gc();
        let _ = spam.poll_outbox();
        if i % 8 == 7 {
            spam = ChallengeBook::new(flooder.clone(), MATCH, Timing::default());
            for _ in 0..=i {
                spam.next_nonce_bump();
            }
        }
    }
    assert!(sent > 1000);
    n.run(120);
    let answered = n.peers[1].pipe.auditor().stats().challenges_answered;
    assert!(
        answered <= crate::audit::ChallengeGate::MAX_PER_CHALLENGER as u64 + 4,
        "answered {answered}"
    );
    assert!((0..3).all(|i| n.violations(i).is_empty()));
}

#[test]
fn auditor_restart_restores_log_and_reverifies_persisted_evidence() {
    use crate::audit::{AuditLog, Evidence};
    use crate::{Checkpoint, SignedCheckpoint};
    use gv_core::Roster;
    use gv_sig::SigningKey;
    let (a, b) = (
        SigningKey::from_seed([1; 32]),
        SigningKey::from_seed([2; 32]),
    );
    let (m, r) = ([7u8; 32], [9u8; 32]);
    let roster = Roster::players(&[a.id(), b.id()]).unwrap();
    let mut auditor = super::Auditor::new(a.clone(), &roster, m, r).unwrap();
    auditor.use_ephemeral_store_for_tests();
    let mut log = AuditLog::new(m, a.id());
    for i in 0..10u64 {
        log.append(1, i.to_le_bytes().to_vec()).unwrap();
    }
    let cp = |n: u8| {
        SignedCheckpoint::sign(
            Checkpoint {
                match_id: m,
                session: [3; 32],
                ruleset: r,
                epoch_start: 0,
                epoch_length: 20,
                previous_checkpoint: [0; 32],
                previous_state: [1; 32],
                input_root: [2; 32],
                next_state: [n; 32],
            },
            &b,
        )
    };
    let good = Evidence::ConflictingCheckpoints(cp(1), cp(2))
        .encode()
        .unwrap();
    let stored = vec![good, b"torn garbage".to_vec()];
    let anchor = log.sign_authenticator(r, &a);
    let report = auditor.restore(Some(log.clone()), &[anchor], &stored);
    assert!(matches!(
        report.recovery,
        crate::audit::trust::Recovery::Resumed { .. }
    ));
    assert_eq!(
        report.evidence_restored, 1,
        "only evidence that still verifies is restored"
    );
    assert_eq!(auditor.log().head(), log.head());
    assert_eq!(auditor.ledger().proven_total(), 1);
    let foreign = AuditLog::new(m, b.id());
    assert!(!auditor.restore(Some(foreign), &[], &[]).recovery.may_sign());
}

/// Build the archive as the host does: certified epochs as receipts, a disputed epoch as an
/// explicit gap carrying the fraud proof.
fn archive_of(n: &Net, i: usize) -> crate::CertifiedMatch {
    use crate::{ArchiveBuilder, CertifiedEpoch, CertifiedMatch, CheckpointEvidence};
    let empty = CertifiedMatch {
        epochs: vec![],
        disputes: vec![],
        live: true,
    };
    let mut b = ArchiveBuilder::new(&empty).unwrap();
    let proofs: Vec<CheckpointEvidence> = n
        .violations(i)
        .iter()
        .filter(|v| v.kind == ViolationKind::FalseCheckpoint)
        .map(|v| CheckpointEvidence::decode(&v.evidence).unwrap())
        .collect();
    for e in n.peers[i].pipe.replica().accepted() {
        if e.signatures.is_some() {
            b.push(&CertifiedEpoch::from_accepted(e, &n.cast.session).unwrap())
                .unwrap();
        } else {
            let p = proofs
                .iter()
                .find(|p| p.accused.claim.epoch_start == e.checkpoint.epoch_start)
                .expect("a disputed epoch has its proof");
            b.push_dispute(p).unwrap();
        }
    }
    CertifiedMatch::decode(b.as_bytes()).unwrap()
}

#[test]
fn archive_continues_past_a_disputed_epoch_and_verifies_independently() {
    use crate::export::{export_match, verify_package, DisclosurePolicy, TrustAnchor, Verified};
    let scripts = vec![
        held(grid::UP, 3, 60, 400),
        held(grid::DOWN, 10, 40, 400),
        held(grid::LEFT, 12, 44, 400),
    ];
    let mut n = net(scripts, config(), 2);
    n.run(10);
    n.peers[1].pipe.inject_cheat();
    n.run(390);
    let session = n.cast.session.clone();
    for i in 0..3 {
        let archive = archive_of(&n, i);
        assert_eq!(archive.disputed(), 1, "peer {i}");
        assert!(
            archive.epochs.len() >= 2,
            "valid play after the dispute is exported"
        );
        assert!(
            archive.disputes[0].after < archive.epochs.len(),
            "certified epochs follow the gap"
        );
        let replica = archive.restore(session.clone(), GridRules).unwrap();
        assert_eq!(replica.next_tick(), n.peers[i].pipe.verified_tick());
        assert_eq!(replica.state(), n.peers[i].pipe.verified_state());
        assert_eq!(
            replica.previous_checkpoint(),
            n.peers[i].pipe.replica().previous_checkpoint()
        );
        let pkg = export_match(&GridRules, &session, &archive, DisclosurePolicy::PUBLIC).unwrap();
        let anchor = TrustAnchor {
            match_id: MATCH,
            ruleset: GridRules.ruleset_hash(),
            session: session.digest(),
        };
        let (_, v) = verify_package(&pkg.encode().unwrap(), &anchor, &GridRules).unwrap();
        match v {
            Verified::Match {
                disputed, segments, ..
            } => {
                assert_eq!(disputed, 1);
                assert!(segments >= 1);
            }
            other => panic!("{other:?}"),
        }
        let restores = |a: &crate::CertifiedMatch| a.restore(session.clone(), GridRules).is_ok();
        let mut dropped = archive.clone();
        dropped.disputes.clear();
        assert!(!restores(&dropped), "gap removed");
        let mut moved = archive.clone();
        moved.disputes[0].after += 1;
        assert!(!restores(&moved), "gap moved");
        let mut doubled = archive.clone();
        doubled.disputes.push(crate::Dispute {
            after: doubled.epochs.len(),
            proof: archive.disputes[0].proof.clone(),
        });
        assert!(!restores(&doubled), "proof reused");
        let mut reordered = archive.clone();
        reordered.epochs.swap(0, 1);
        assert!(!restores(&reordered));
        let enc = archive.encode().unwrap();
        for cut in [1usize, 17, enc.len() / 2] {
            assert!(crate::CertifiedMatch::decode(&enc[..enc.len() - cut]).is_err());
        }
    }
}

#[test]
fn an_honest_epoch_cannot_be_relabelled_as_disputed() {
    let scripts = vec![
        held(grid::UP, 3, 60, 200),
        held(grid::DOWN, 10, 40, 200),
        vec![],
    ];
    let mut n = net(scripts, config(), 2);
    n.run(200);
    let honest = archive_of(&n, 0);
    assert_eq!(honest.disputed(), 0);
    let mut fake = honest.clone();
    fake.disputes.push(crate::Dispute {
        after: 0,
        proof: honest.epochs[0].evidence.clone(),
    });
    assert!(fake.restore(n.cast.session.clone(), GridRules).is_err());
}
