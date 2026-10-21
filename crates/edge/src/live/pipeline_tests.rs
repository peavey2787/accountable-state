#![allow(clippy::needless_range_loop)]
use super::*;
use crate::arena::{self, ArenaRules, ArenaState};
use crate::{apply_tick, MatchReplica, PublicRules};
use gv_core::PlayerId;
use gv_sig::SigningKey;
use std::collections::VecDeque;

const MATCH: [u8; 32] = [7; 32];

struct Peer {
    pipe: Pipeline<ArenaRules>,
    script: Vec<u16>,
    events: Vec<(u64, PipeEvent)>,
    sent: Vec<(u64, PipeMsg)>,
}
type DropRule = Box<dyn Fn(usize, u64, &PipeMsg) -> bool>;
struct Net {
    peers: [Peer; 2],
    wire: [VecDeque<(u64, Vec<u8>)>; 2], // wire[i] = messages travelling TO peer i
    delay: u64,
    now: u64,
    /// Peer i's local tick is `now - skew[i]`: its clock runs a little behind.
    skew: [u64; 2],
    /// Drop predicate on (sender index, message).
    drop: DropRule,
}

fn keys() -> [SigningKey; 2] {
    [
        SigningKey::from_seed([1; 32]),
        SigningKey::from_seed([2; 32]),
    ]
}
fn roster() -> [PlayerId; 2] {
    let mut r = keys().map(|k| k.id());
    r.sort();
    r
}

fn net(scripts: [Vec<u16>; 2], cfg: PipelineConfig, delay: u64) -> Net {
    let roster = roster();
    let rules = ArenaRules::new(roster);
    let mk = |i: usize, script: Vec<u16>| Peer {
        pipe: Pipeline::new(
            keys()[i].clone(),
            roster,
            MATCH,
            rules.clone(),
            MatchReplica::new(MATCH, roster, rules.clone()).unwrap(),
            cfg.clone(),
        )
        .unwrap(),
        script,
        events: Vec::new(),
        sent: Vec::new(),
    };
    let [s0, s1] = scripts;
    Net {
        peers: [mk(0, s0), mk(1, s1)],
        wire: [VecDeque::new(), VecDeque::new()],
        delay,
        now: 0,
        skew: [0, 0],
        drop: Box::new(|_, _, _| false),
    }
}

impl Net {
    fn run(&mut self, ticks: u64) {
        for _ in 0..ticks {
            self.now += 1;
            for i in 0..2 {
                let now = self.now.saturating_sub(self.skew[i]);
                let script = self.peers[i].script.clone();
                let own = move |from: u64, to: u64| -> Option<Vec<u16>> {
                    (to <= now).then(|| {
                        (from..to)
                            .map(|k| script.get(k as usize).copied().unwrap_or(0))
                            .collect()
                    })
                };
                self.peers[i].pipe.tick(now, &own);
                self.flush(i, now);
                // deliver everything due to peer i
                // Wire time is global; only the pipeline's own tick lags.
                while self.wire[i].front().is_some_and(|(at, _)| *at <= self.now) {
                    let (_, bytes) = self.wire[i].pop_front().unwrap();
                    let msg = PipeMsg::decode(&bytes).expect("wire message decodes");
                    self.peers[i].pipe.on_message(msg, now, &own);
                    self.flush(i, now);
                }
            }
        }
    }
    fn flush(&mut self, i: usize, now: u64) {
        while let Some(m) = self.peers[i].pipe.poll_outbox() {
            if !(self.drop)(i, now, &m) {
                let bytes = m.encode().expect("encodes");
                let _ = now;
                self.wire[1 - i].push_back((self.now + self.delay, bytes));
            }
            self.peers[i].sent.push((now, m));
        }
        while let Some(e) = self.peers[i].pipe.poll_event() {
            self.peers[i].events.push((now, e));
        }
    }
    fn violations(&self, i: usize) -> Vec<&Violation> {
        self.peers[i]
            .events
            .iter()
            .filter_map(|(_, e)| {
                if let PipeEvent::Violation(v) = e {
                    Some(v)
                } else {
                    None
                }
            })
            .collect()
    }
    fn finalized(&self, i: usize) -> Vec<(u64, u64, bool)> {
        self.peers[i]
            .events
            .iter()
            .filter_map(|(_, e)| match e {
                PipeEvent::Finalized {
                    start,
                    end,
                    disputed,
                    ..
                } => Some((*start, *end, *disputed)),
                _ => None,
            })
            .collect()
    }
}

fn reference(scripts: &[Vec<u16>; 2], ticks: u64) -> Vec<u8> {
    let roster = roster();
    let rules = ArenaRules::new(roster);
    let mut state = rules.genesis(&roster);
    let ctl = |p: usize, t: u64| {
        let key = keys()[p].id();
        let idx = roster.iter().position(|r| *r == key).unwrap();
        let _ = idx;
        scripts[p].get(t as usize).copied().unwrap_or(0)
    };
    for t in 0..ticks {
        for (slot, id) in roster.iter().enumerate() {
            let p = keys().iter().position(|k| k.id() == *id).unwrap();
            let _ = slot;
            state = apply_tick(&rules, &state, id, t, ctl(p, t), true)
                .unwrap()
                .0;
        }
    }
    state
}

fn held(c: u16, from: usize, to: usize, len: usize) -> Vec<u16> {
    let mut v = vec![0; len];
    for x in &mut v[from..to] {
        *x = c;
    }
    v
}

#[test]
fn nobody_sends_anything_while_both_players_are_idle() {
    let mut n = net([vec![], vec![]], PipelineConfig::default(), 2);
    n.run(1200);
    assert!(
        n.peers[0].sent.is_empty() && n.peers[1].sent.is_empty(),
        "idle = silent"
    );
    assert_eq!(n.peers[0].pipe.verified_tick(), 0);
}

#[test]
fn one_active_player_proposes_the_idle_one_answers_and_both_certify() {
    let scripts = [held(arena::UP, 5, 9, 200), vec![]];
    let mut n = net(scripts.clone(), PipelineConfig::default(), 3);
    n.run(200);
    let (a, b) = (n.finalized(0), n.finalized(1));
    assert!(!a.is_empty(), "an epoch was certified");
    assert_eq!(a, b, "both certified identical epochs");
    assert_eq!(a[0], (0, 20, false), "first epoch ends on the 20-tick grid");
    assert_eq!(
        n.peers[0].pipe.verified_state(),
        n.peers[1].pipe.verified_state()
    );
    let t = n.peers[0].pipe.verified_tick();
    assert_eq!(
        n.peers[0].pipe.verified_state(),
        reference(&scripts, t).as_slice()
    );
    // The idle player only ever answered; it never opened an epoch of its own.
    let b_batches = n.peers[1]
        .sent
        .iter()
        .filter(|(_, m)| matches!(m, PipeMsg::Batch(_)))
        .count();
    assert_eq!(b_batches, 1);
    // Once certified, nothing more is exchanged.
    let sent_before = n.peers[0].sent.len() + n.peers[1].sent.len();
    n.run(600);
    assert_eq!(n.peers[0].sent.len() + n.peers[1].sent.len(), sent_before);
}

#[test]
fn both_active_at_different_times_agree_on_the_shorter_epoch() {
    // A acts in cell 2 (ticks 40-59); B acts in cell 1 (ticks 20-39).
    let scripts = [
        held(arena::RIGHT, 45, 50, 300),
        held(arena::LEFT, 22, 26, 300),
    ];
    for delay in [0, 1, 5, 12, 25] {
        let mut n = net(scripts.clone(), PipelineConfig::default(), delay);
        n.run(300);
        assert_eq!(n.finalized(0), n.finalized(1), "delay {delay}");
        assert!(
            n.finalized(0).len() >= 2,
            "delay {delay}: {:?}",
            n.finalized(0)
        );
        assert_eq!(
            n.peers[0].pipe.verified_state(),
            n.peers[1].pipe.verified_state()
        );
        let t = n.peers[0].pipe.verified_tick();
        assert_eq!(
            n.peers[0].pipe.verified_state(),
            reference(&scripts, t).as_slice(),
            "delay {delay}"
        );
        assert!(
            n.violations(0).is_empty() && n.violations(1).is_empty(),
            "delay {delay}"
        );
    }
}

#[test]
fn a_false_signed_checkpoint_is_proven_on_both_sides_and_play_continues() {
    let scripts = [held(arena::UP, 3, 60, 300), held(arena::DOWN, 10, 40, 300)];
    let mut n = net(scripts.clone(), PipelineConfig::default(), 2);
    n.run(10);
    n.peers[1].pipe.inject_cheat();
    n.run(290);
    for i in 0..2 {
        let v = n.violations(i);
        assert_eq!(
            v.len(),
            1,
            "peer {i}: {:?}",
            v.iter().map(|x| x.kind).collect::<Vec<_>>()
        );
        assert_eq!(v[0].kind, ViolationKind::FalseCheckpoint);
        assert_eq!(v[0].accused, keys()[1].id());
        assert!(!v[0].evidence.is_empty());
    }
    assert_eq!(n.finalized(0), n.finalized(1));
    assert!(
        n.finalized(0).iter().any(|e| e.2),
        "the disputed epoch closed by evidence"
    );
    assert!(
        n.finalized(0).iter().filter(|e| !e.2).count() >= 2,
        "play continued and re-agreed"
    );
    assert_eq!(
        n.peers[0].pipe.verified_state(),
        n.peers[1].pipe.verified_state()
    );
    let t = n.peers[0].pipe.verified_tick();
    assert_eq!(
        n.peers[0].pipe.verified_state(),
        reference(&scripts, t).as_slice()
    );
}

#[test]
fn a_signed_illegal_input_is_neutralized_proven_and_does_not_stall() {
    let mut a = held(arena::RIGHT, 2, 6, 200);
    for x in &mut a[10..14] {
        *x = 128; // unsupported control word
    }
    a[30] = arena::LEFT | arena::RIGHT; // contradictory
    let scripts = [a, held(arena::DOWN, 4, 8, 200)];
    let mut n = net(scripts.clone(), PipelineConfig::default(), 2);
    n.run(200);
    for i in 0..2 {
        let v = n.violations(i);
        assert!(!v.is_empty(), "peer {i} saw the violation");
        assert!(v.iter().all(|x| x.kind == ViolationKind::IllegalInput));
        assert!(v.iter().all(|x| x.accused == keys()[0].id()));
    }
    assert_eq!(n.violations(0).len(), n.violations(1).len());
    assert_eq!(n.finalized(0), n.finalized(1));
    assert!(
        n.finalized(0).iter().all(|e| !e.2),
        "no dispute: both replayed the same sanitized epoch"
    );
    let t = n.peers[0].pipe.verified_tick();
    assert!(t >= 40);
    assert_eq!(
        n.peers[0].pipe.verified_state(),
        reference(&scripts, t).as_slice()
    );
    // The evidence is a portable, independently checkable artifact.
    let ev = crate::CheckpointEvidence::decode(&n.violations(1)[0].evidence).unwrap();
    assert_eq!(
        crate::verify_checkpoint_evidence_with(&ArenaRules::new(roster()), &ev, true),
        crate::EvidenceVerdict::ValidClaim
    );
    // ... and exports as a self-verifying package that a third party checks with pinned facts only.
    {
        use crate::export::*;
        use gv_replay::GameRules as _;
        let rules = ArenaRules::new(roster());
        let anchor = TrustAnchor {
            match_id: ev.accused.claim.match_id,
            ruleset: rules.ruleset_hash(),
            roster: roster(),
        };
        let pkg = export_fraud(
            &rules,
            anchor.match_id,
            roster(),
            FraudWitness::IllegalInput(&ev),
            DisclosurePolicy::PUBLIC,
        )
        .unwrap();
        let bytes = pkg.encode().unwrap();
        let (_, v) = verify_package(&bytes, &anchor, &rules).unwrap();
        assert_eq!(
            v,
            Verified::Fraud {
                kind: FraudKind::IllegalInput,
                accused: keys()[0].id()
            }
        );
        let mut bad = bytes.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 1;
        assert!(verify_package(&bad, &anchor, &rules).is_err());
    }
}

fn busy(seed: u64, ticks: usize) -> Vec<u16> {
    let mut s = seed | 1;
    let pool = [
        0,
        arena::LEFT,
        arena::RIGHT,
        arena::UP,
        arena::DOWN,
        arena::ATTACK,
        arena::GUARD,
        0,
        0,
    ];
    let mut out = Vec::new();
    while out.len() < ticks {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let c = pool[(s % pool.len() as u64) as usize];
        for _ in 0..1 + (s >> 20) % 12 {
            out.push(c);
        }
    }
    out.truncate(ticks);
    out
}

#[test]
fn hidden_window_uses_commit_lock_reveal_and_leaks_nothing_until_the_end() {
    // Both players go quiet at tick 1000 so the network drains before we compare.
    let scripts = [busy(11, 1000), busy(23, 1000)];
    for delay in [0, 3, 9] {
        let mut n = net(scripts.clone(), PipelineConfig::default(), delay);
        n.run(100);
        n.peers[0].pipe.request_hide(100).unwrap();
        let (h0, h1) = (140u64, 440u64);
        n.run(1000);
        let hider = keys()[0].id();
        // 1. The hider never put a plaintext batch or reveal on the wire for
        //    the hidden ticks before the window closed.
        for (at, m) in &n.peers[0].sent {
            match m {
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
                    "delay {delay}: early reveal at {at} of {}",
                    b.batch.record.start_tick
                ),
                _ => {}
            }
        }
        // 2. Commitments and locks did flow during the window.
        let commits = n.peers[0]
            .sent
            .iter()
            .filter(|(at, m)| matches!(m, PipeMsg::Commit(_)) && *at < h1)
            .count();
        assert!(
            commits >= 10,
            "delay {delay}: hider committed progressively: {commits}"
        );
        assert!(n.peers[0]
            .sent
            .iter()
            .any(|(_, m)| matches!(m, PipeMsg::Lock(_))));
        // 3. The observer learned nothing about the hidden inputs before h1.
        for (at, e) in &n.peers[1].events {
            if let PipeEvent::RemoteInputs { from_tick, .. } = e {
                assert!(
                    !(*from_tick >= h0 && *from_tick < h1) || *at >= h1,
                    "delay {delay}: leaked tick {from_tick} at {at}"
                );
            }
        }
        // 4. After the reveal everything certifies and both agree with the replay.
        for i in 0..2 {
            assert!(
                n.peers[i].events.iter().any(
                    |(_, e)| matches!(e, PipeEvent::HideScheduled { hider: h, .. } if *h == hider)
                ),
                "delay {delay}"
            );
            assert!(
                n.peers[i]
                    .events
                    .iter()
                    .any(|(_, e)| matches!(e, PipeEvent::HideRevealed { .. })),
                "delay {delay} peer {i}"
            );
            assert!(
                n.violations(i).is_empty(),
                "delay {delay} peer {i}: {:?}",
                n.violations(i).iter().map(|v| v.kind).collect::<Vec<_>>()
            );
        }
        assert_eq!(n.finalized(0), n.finalized(1), "delay {delay}");
        assert!(n.peers[0].pipe.verified_tick() >= h1, "delay {delay}");
        assert_eq!(
            n.peers[0].pipe.verified_state(),
            n.peers[1].pipe.verified_state()
        );
        let t = n.peers[0].pipe.verified_tick();
        assert_eq!(
            n.peers[0].pipe.verified_state(),
            reference(&scripts, t).as_slice(),
            "delay {delay}"
        );
        assert!(ArenaState::decode(n.peers[0].pipe.verified_state()).is_ok());
        // 5. Cooldown, then a second hide is allowed.
        assert!(
            matches!(
                n.peers[0].pipe.request_hide(500),
                Err(HideError::Cooldown { .. })
            ),
            "cooldown after a hide"
        );
        let after = n.peers[0].pipe.hide_cooldown_until();
        n.peers[0]
            .pipe
            .request_hide(after)
            .expect("allowed again after the cooldown");
    }
}

#[test]
fn a_withheld_reveal_is_reported_and_stalls_only_the_certified_chain() {
    let scripts = [busy(5, 1900), busy(6, 1900)];
    let mut n = net(scripts, PipelineConfig::default(), 2);
    n.drop = Box::new(|from, _, m| from == 0 && matches!(m, PipeMsg::Reveal(_)));
    n.run(100);
    n.peers[0].pipe.request_hide(100).unwrap();
    n.run(1800);
    let hider = keys()[0].id();
    let v = n.violations(1);
    assert!(
        v.iter()
            .any(|x| x.kind == ViolationKind::WithheldReveal && x.accused == hider),
        "{:?}",
        v.iter().map(|x| x.kind).collect::<Vec<_>>()
    );
    assert!(
        n.peers[1].pipe.verified_tick() <= 140,
        "the hidden epochs cannot be certified without a reveal"
    );
}

#[test]
fn a_reveal_that_does_not_match_its_commitment_is_rejected() {
    let scripts = [busy(8, 1000), busy(9, 1000)];
    let mut n = net(scripts, PipelineConfig::default(), 2);
    n.run(100);
    n.peers[0].pipe.request_hide(100).unwrap();
    // Corrupt every reveal the hider sends: re-sign different inputs.
    let key = keys()[0].clone();
    n.drop = Box::new(|from, _, m| from == 0 && matches!(m, PipeMsg::Reveal(_)));
    n.run(500);
    let mut forged = 0;
    let reveals: Vec<_> = n.peers[0]
        .sent
        .iter()
        .filter_map(|(_, m)| {
            if let PipeMsg::Reveal(b) = m {
                Some(b.clone())
            } else {
                None
            }
        })
        .collect();
    for b in reveals {
        let mut rec = b.batch.record.clone();
        rec.initial_state ^= arena::ATTACK;
        rec.changes.clear();
        let lie = gv_codec::SignedPackedControls::sign(rec, &key).unwrap();
        let now = n.now;
        let script = n.peers[1].script.clone();
        let own = move |f: u64, t: u64| {
            (t <= now).then(|| {
                (f..t)
                    .map(|k| script.get(k as usize).copied().unwrap_or(0))
                    .collect()
            })
        };
        n.peers[1].pipe.on_message(
            PipeMsg::Reveal(crate::live::Opening {
                batch: lie,
                blind: b.blind,
            }),
            now,
            &own,
        );
        forged += 1;
    }
    while let Some(e) = n.peers[1].pipe.poll_event() {
        n.peers[1].events.push((n.now, e));
    }
    assert!(forged > 0);
    assert!(
        n.violations(1)
            .iter()
            .any(|v| v.kind == ViolationKind::BadReveal),
        "{:?}",
        n.violations(1).iter().map(|v| v.kind).collect::<Vec<_>>()
    );
}

#[test]
fn a_responder_whose_clock_lags_still_pairs_without_waiting_for_more_traffic() {
    // Regression: the lagging peer answers an "owed" proposal later, and that
    // answer alone must complete the pair. Previously it waited for unrelated
    // traffic, so one illegal-input tap stalled certification indefinitely.
    let scripts = [held(arena::RIGHT, 45, 50, 400), vec![]];
    for skew in 1..=9u64 {
        for delay in [0, 2, 7] {
            let mut n = net(scripts.clone(), PipelineConfig::default(), delay);
            n.skew = [0, skew];
            n.run(260);
            assert!(
                !n.finalized(0).is_empty(),
                "skew {skew} delay {delay}: nothing certified"
            );
            assert_eq!(n.finalized(0), n.finalized(1), "skew {skew} delay {delay}");
        }
    }
    // Both lagging in either direction, both active, with an illegal word too.
    let mut a = held(arena::UP, 3, 9, 400);
    a[100] = 128;
    let scripts = [a, held(arena::LEFT, 4, 7, 400)];
    for skew in [[0, 3], [3, 0], [2, 5]] {
        let mut n = net(scripts.clone(), PipelineConfig::default(), 4);
        n.skew = skew;
        n.run(400);
        assert_eq!(n.finalized(0), n.finalized(1), "skew {skew:?}");
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

// ---- accountability (PeerReview-style) ------------------------------------

fn audit_events(n: &Net, i: usize) -> Vec<&AuditEvent> {
    n.peers[i]
        .events
        .iter()
        .filter_map(|(_, e)| match e {
            PipeEvent::Audit(a) => Some(a),
            _ => None,
        })
        .collect()
}
fn statuses(n: &Net, i: usize) -> Vec<crate::audit::Status> {
    audit_events(n, i)
        .into_iter()
        .filter_map(|a| match a {
            AuditEvent::Challenge { status, .. } => Some(*status),
            _ => None,
        })
        .collect()
}
fn busy_pair() -> [Vec<u16>; 2] {
    [
        held(arena::UP, 0, 3000, 3000),
        held(arena::LEFT, 0, 3000, 3000),
    ]
}

#[test]
fn a_dishonest_peer_showing_two_histories_is_proven_offline() {
    let mut n = net(busy_pair(), PipelineConfig::default(), 2);
    n.run(120);
    n.peers[0]
        .pipe
        .auditor_mut()
        .equivocate_next_authenticator();
    n.run(400);
    // The victim holds exportable proof, and it verifies from bytes alone.
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
    }
    assert_eq!(proofs[0].accused, keys()[0].id());
    // The proof is relayed to the accused's own ledger too (propagation), but the
    // honest peer is never accused of anything.
    assert!(n.violations(0).iter().all(|v| v.accused != keys()[1].id()));
    assert!(n.violations(1).iter().all(|v| v.accused != keys()[1].id()));
    // Play never stopped: both sides kept certifying.
    assert!(n.finalized(0).len() > 10 && n.finalized(0) == n.finalized(1));
}

#[test]
fn withholding_is_only_suspicion_and_a_late_answer_clears_it() {
    use crate::audit::{ChallengeKind, Status};
    let mut n = net(busy_pair(), PipelineConfig::default(), 2);
    n.run(100);
    n.peers[0]
        .pipe
        .auditor_mut()
        .withhold_answers_until(100 + 700);
    let now = n.now;
    n.peers[1]
        .pipe
        .auditor_mut()
        .challenge(ChallengeKind::Ack { seq: 1 }, now)
        .unwrap();
    n.run(1200);
    let s = statuses(&n, 1);
    assert!(s.contains(&Status::SuspectedNonCooperation), "{s:?}");
    assert_eq!(s.last(), Some(&Status::Cleared), "{s:?}");
    // Delay is never a cheating verdict.
    assert!(n.violations(0).is_empty() && n.violations(1).is_empty());
    assert_eq!(n.peers[1].pipe.auditor().stats().pending, 0);
}

#[test]
fn a_false_accusation_and_forged_evidence_prove_nothing() {
    let mut n = net(busy_pair(), PipelineConfig::default(), 2);
    n.run(200);
    let victim = n.peers[1]
        .sent
        .iter()
        .find_map(|(_, m)| match m {
            PipeMsg::Checkpoint(c) => Some(c.clone()),
            _ => None,
        })
        .unwrap();
    let now = n.now;
    // Peer 0 frames peer 1 with a forged checkpoint pair and claims a missing batch
    // that was in fact delivered.
    n.peers[0]
        .pipe
        .auditor_mut()
        .send_forged_accusation(&victim);
    n.peers[0].pipe.auditor_mut().accuse_missing_batch(0, now);
    n.run(300);
    assert!(n.violations(1).is_empty(), "honest peer not framed");
    assert!(n.peers[1].pipe.auditor().stats().rejected_evidence >= 1);
    // The accused answers the accusation with the signed batch: counterproof.
    assert!(statuses(&n, 0).contains(&crate::audit::Status::Cleared));
    assert!(!statuses(&n, 0).contains(&crate::audit::Status::SuspectedNonCooperation));
}

#[test]
fn a_lossy_reordering_network_never_produces_a_cheating_verdict() {
    for seed in 0u64..4 {
        let mut n = net(busy_pair(), PipelineConfig::default(), 3);
        // Drop accountability traffic pseudo-randomly; reliable layer still carries play.
        n.drop = Box::new(move |from, now, m| {
            matches!(
                m,
                PipeMsg::Auth(_) | PipeMsg::Challenge(_) | PipeMsg::Response(_)
            ) && (now
                .wrapping_mul(2654435761)
                .wrapping_add(seed * 7 + from as u64))
                % 3
                == 0
        });
        n.run(1500);
        assert!(
            n.violations(0).is_empty(),
            "seed {seed}: {:?}",
            n.violations(0)
        );
        assert!(n.violations(1).is_empty(), "seed {seed}");
        assert!(n.finalized(0).len() > 20);
    }
}

#[test]
fn partition_then_heal_ends_cleared_not_accused() {
    use crate::audit::{ChallengeKind, Status};
    let mut n = net(busy_pair(), PipelineConfig::default(), 2);
    n.run(100);
    // Accountability traffic is cut for 10 s; play continues (separate reliable path).
    n.drop = Box::new(|_, now, m| {
        matches!(m, PipeMsg::Challenge(_) | PipeMsg::Response(_)) && (100..900).contains(&now)
    });
    let now = n.now;
    n.peers[1]
        .pipe
        .auditor_mut()
        .challenge(ChallengeKind::Replay { epoch_start: 0 }, now)
        .unwrap();
    n.run(1800);
    let s = statuses(&n, 1);
    assert_eq!(s.last(), Some(&Status::Cleared), "{s:?}");
    assert!(n.violations(1).is_empty());
}

#[test]
fn audit_traffic_is_bounded_and_flooding_is_dropped() {
    use crate::audit::{Challenge, ChallengeBook, ChallengeKind, Timing};
    let mut n = net(busy_pair(), PipelineConfig::default(), 2);
    n.run(60);
    let mut spam = ChallengeBook::new(keys()[0].clone(), MATCH, Timing::default());
    let mut sent = 0;
    for i in 0..5000u64 {
        if let Ok(c) = spam.issue(keys()[1].id(), ChallengeKind::Ack { seq: i }, n.now) {
            n.wire[1].push_back((n.now, PipeMsg::Challenge(c).encode().unwrap()));
            sent += 1;
        }
        spam.gc();
        let _: Option<Challenge> = spam.poll_outbox();
        if i % 8 == 7 {
            spam = ChallengeBook::new(keys()[0].clone(), MATCH, Timing::default());
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
    assert!(n.violations(0).is_empty() && n.violations(1).is_empty());
}

#[test]
fn auditor_restart_restores_log_and_reverifies_persisted_evidence() {
    use crate::audit::{AuditLog, Evidence};
    use crate::{Checkpoint, SignedCheckpoint};
    use gv_sig::SigningKey;
    let (a, b) = (
        SigningKey::from_seed([1; 32]),
        SigningKey::from_seed([2; 32]),
    );
    let (m, r) = ([7u8; 32], [9u8; 32]);
    let mut auditor = super::Auditor::new(a.clone(), [a.id(), b.id()], m, r).unwrap();
    let mut log = AuditLog::new(m, a.id());
    for i in 0..10u64 {
        log.append(1, i.to_le_bytes().to_vec()).unwrap();
    }
    let cp = |n: u8| {
        SignedCheckpoint::sign(
            Checkpoint {
                match_id: m,
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
    let restored = report.evidence_restored;
    assert_eq!(restored, 1, "only evidence that still verifies is restored");
    assert_eq!(auditor.log().head(), log.head());
    assert_eq!(auditor.ledger().proven_total(), 1);
    // A log for another owner or match is never adopted.
    let foreign = AuditLog::new(m, b.id());
    assert!(!auditor.restore(Some(foreign), &[], &[]).recovery.may_sign());
}

/// Build the archive exactly as the host does: certified epochs as receipts, the disputed epoch
/// as an explicit gap carrying the fraud proof.
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
            b.push(&CertifiedEpoch::from_accepted(e, roster()).unwrap())
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
    use gv_replay::GameRules as _;
    let scripts = [held(arena::UP, 3, 60, 400), held(arena::DOWN, 10, 40, 400)];
    let mut n = net(scripts.clone(), PipelineConfig::default(), 2);
    n.run(10);
    n.peers[1].pipe.inject_cheat();
    n.run(390);
    let rules = ArenaRules::new(roster());
    for i in 0..2 {
        let archive = archive_of(&n, i);
        assert_eq!(archive.disputed(), 1, "peer {i}");
        assert!(
            archive.epochs.len() >= 2,
            "valid play after the dispute is exported"
        );
        let first_after = archive.disputes[0].after;
        assert!(
            first_after < archive.epochs.len(),
            "certified epochs follow the gap"
        );
        // Independent replay from genesis reaches the live verified head exactly.
        let replica = archive.restore(MATCH, roster(), rules.clone()).unwrap();
        assert_eq!(replica.next_tick(), n.peers[i].pipe.verified_tick());
        assert_eq!(replica.state(), n.peers[i].pipe.verified_state());
        assert_eq!(
            replica.previous_checkpoint(),
            n.peers[i].pipe.replica().previous_checkpoint()
        );
        // And as a package, with only pinned facts.
        let pkg =
            export_match(&rules, MATCH, roster(), &archive, DisclosurePolicy::PUBLIC).unwrap();
        let anchor = TrustAnchor {
            match_id: MATCH,
            ruleset: rules.ruleset_hash(),
            roster: roster(),
        };
        let (_, v) = verify_package(&pkg.encode().unwrap(), &anchor, &rules).unwrap();
        match v {
            Verified::Match {
                disputed, segments, ..
            } => {
                assert_eq!(disputed, 1);
                assert!(segments >= 1);
            }
            other => panic!("{other:?}"),
        }
        // The gap cannot be forged, dropped, moved or reused.
        let mut dropped = archive.clone();
        dropped.disputes.clear();
        assert!(
            dropped.restore(MATCH, roster(), rules.clone()).is_err(),
            "gap removed"
        );
        let mut moved = archive.clone();
        moved.disputes[0].after += 1;
        assert!(
            moved.restore(MATCH, roster(), rules.clone()).is_err(),
            "gap moved"
        );
        let mut doubled = archive.clone();
        doubled.disputes.push(crate::Dispute {
            after: doubled.epochs.len(),
            proof: archive.disputes[0].proof.clone(),
        });
        assert!(
            doubled.restore(MATCH, roster(), rules.clone()).is_err(),
            "proof reused"
        );
        let mut reordered = archive.clone();
        reordered.epochs.swap(0, 1);
        assert!(reordered.restore(MATCH, roster(), rules.clone()).is_err());
        let enc = archive.encode().unwrap();
        for cut in [1usize, 17, enc.len() / 2] {
            assert!(crate::CertifiedMatch::decode(&enc[..enc.len() - cut]).is_err());
        }
    }
}

#[test]
fn an_honest_epoch_cannot_be_relabelled_as_disputed() {
    // A proof must show a claim that replay refutes; a valid, co-signed claim is not one.
    let scripts = [held(arena::UP, 3, 60, 200), held(arena::DOWN, 10, 40, 200)];
    let mut n = net(scripts, PipelineConfig::default(), 2);
    n.run(200);
    let rules = ArenaRules::new(roster());
    let honest = archive_of(&n, 0);
    assert_eq!(honest.disputed(), 0);
    let first = &honest.epochs[0];
    let mut fake = honest.clone();
    fake.disputes.push(crate::Dispute {
        after: 0,
        proof: first.witnesses[0].clone(),
    });
    assert!(fake.restore(MATCH, roster(), rules).is_err());
}

/// Long-running adversarial soak (ignored by default):
///   GV_SOAK_SECS=3600 cargo test -p gv-edge --release soak_ -- --ignored --nocapture
/// Back-to-back 60 Hz matches between two honest pipelines on a hostile in-process network
/// (random loss of accountability traffic, duplication, reordering, variable delay), with
/// pruning, repeated challenges whose answers are withheld and then delivered late, a
/// periodic comparison against the independent replay, and a resource/latency report.
/// Honest peers must never be accused, must keep certifying identical epochs, and the
/// certified state must equal the independent replay at every comparison.
#[test]
#[ignore]
fn soak_honest_pair_under_faults_pruning_and_delayed_challenges() {
    use crate::audit::{ChallengeKind, Status};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    let secs: u64 = std::env::var("GV_SOAK_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let started = std::time::Instant::now();
    let rss_kb = || -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("VmRSS:"))
                    .and_then(|v| v.split_whitespace().next().and_then(|n| n.parse().ok()))
            })
            .unwrap_or(0)
    };
    let (mut matches, mut total_ticks, mut total_epochs) = (0u64, 0u64, 0u64);
    let (mut challenges, mut cleared, mut suspected) = (0u64, 0u64, 0u64);
    let rss_start = rss_kb();
    let mut rss_peak = rss_start;
    let mut finality: Vec<u64> = Vec::new(); // ticks between an epoch's end and its certification
    while started.elapsed().as_secs() < secs {
        matches += 1;
        let seed = 0x9e37_79b9_7f4a_7c15u64.wrapping_mul(matches);
        let ticks_per_match = 120_000u64; // 33 min of play per match
        let rng = Arc::new(AtomicU64::new(seed | 1));
        let next = {
            let rng = rng.clone();
            move || {
                let mut x = rng.load(Ordering::Relaxed);
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                rng.store(x, Ordering::Relaxed);
                x
            }
        };
        let script = |salt: u64| -> Vec<u16> {
            let mut v = Vec::with_capacity(ticks_per_match as usize);
            let mut cur = 0u16;
            let mut x = seed ^ salt;
            for _ in 0..ticks_per_match {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                if x % 37 == 0 {
                    cur = [
                        0,
                        arena::UP,
                        arena::DOWN,
                        arena::LEFT,
                        arena::RIGHT,
                        arena::ATTACK,
                        arena::GUARD,
                    ][(x >> 8) as usize % 7];
                }
                v.push(cur);
            }
            v
        };
        let scripts = [script(1), script(2)];
        let mut n = net(scripts.clone(), PipelineConfig::default(), 3);
        let dropper = next.clone();
        n.drop = Box::new(move |_, _, m| {
            matches!(
                m,
                PipeMsg::Auth(_) | PipeMsg::Challenge(_) | PipeMsg::Response(_)
            ) && dropper() % 5 == 0
        });
        let mut done = 0u64;
        let chunk = 600u64;
        let mut chal_open_at: Option<u64> = None;
        while done < ticks_per_match && started.elapsed().as_secs() < secs {
            n.run(chunk);
            done += chunk;
            // every ~20 s of play: challenge the other side, whose answers are withheld ~7 s
            if done % 1200 == 0 && chal_open_at.is_none() {
                let now = n.now;
                let (asker, target) = if next() % 2 == 0 { (0, 1) } else { (1, 0) };
                n.peers[target]
                    .pipe
                    .auditor_mut()
                    .withhold_answers_until(now + 420);
                if n.peers[asker]
                    .pipe
                    .auditor_mut()
                    .challenge(ChallengeKind::Ack { seq: 1 }, now)
                    .is_some()
                {
                    challenges += 1;
                    chal_open_at = Some(now);
                }
            }
            if let Some(at) = chal_open_at {
                if n.now > at + 1500 {
                    chal_open_at = None;
                }
            }
            if done % 6000 == 0 {
                for p in &mut n.peers {
                    p.pipe.prune_history(64);
                }
            }
            for i in 0..2 {
                assert!(
                    n.violations(i).is_empty(),
                    "match {matches}: honest peer accused at tick {done}: {:?}",
                    n.violations(i)
                );
            }
            assert_eq!(n.finalized(0), n.finalized(1), "certified epochs diverged");
            if done % 12_000 == 0 {
                let t = n.peers[0].pipe.verified_tick();
                assert_eq!(
                    n.peers[0].pipe.verified_tick(),
                    n.peers[1].pipe.verified_tick()
                );
                assert_eq!(
                    n.peers[0].pipe.verified_state(),
                    reference(&scripts, t).as_slice(),
                    "certified state differs from the independent replay at tick {t}"
                );
            }
            let (c, s) = (0..2).fold((0, 0), |(c, s), i| {
                let st = statuses(&n, i);
                (
                    c + st.iter().filter(|x| **x == Status::Cleared).count(),
                    s + st
                        .iter()
                        .filter(|x| **x == Status::SuspectedNonCooperation)
                        .count(),
                )
            });
            cleared += c as u64;
            suspected += s as u64;
            for (end, certified_at) in n.peers[0].events.iter().filter_map(|(at, e)| match e {
                PipeEvent::Finalized { end, .. } => Some((*end, *at)),
                _ => None,
            }) {
                finality.push(certified_at.saturating_sub(end));
            }
            total_epochs += n.finalized(0).len() as u64;
            for p in &mut n.peers {
                p.events.clear();
                p.sent.clear();
            }
            rss_peak = rss_peak.max(rss_kb());
        }
        // Quiesce: no new challenges, let any in-flight one resolve (answers are retried).
        // The scripted late answer may itself have been dropped and be waiting on a backed-off retry.
        for _ in 0..60 {
            n.run(600);
            if (0..2).all(|i| n.peers[i].pipe.auditor().stats().pending == 0) {
                break;
            }
        }
        total_ticks += done;
        // Every challenge opened by the end must have been resolved by a late answer, never a verdict.
        assert_eq!(
            n.peers[0].pipe.auditor().stats().pending,
            0,
            "match {matches}"
        );
        assert_eq!(
            n.peers[1].pipe.auditor().stats().pending,
            0,
            "match {matches}"
        );
        eprintln!(
            "soak: match {matches} done: {done} ticks, rss {} MiB, elapsed {} s",
            rss_kb() / 1024,
            started.elapsed().as_secs()
        );
    }
    finality.sort_unstable();
    let pct = |p: f64| {
        finality
            .get(((finality.len() as f64 * p) as usize).min(finality.len().saturating_sub(1)))
            .copied()
            .unwrap_or(0)
    };
    eprintln!(
        "SOAK SUMMARY: {} s wall, {matches} matches, {total_ticks} ticks ({:.1} h of 60 Hz play), {total_epochs} certified epochs, \
         {challenges} scripted late-answer challenges; challenge status events: {suspected} suspected-non-cooperation, {cleared} cleared; 0 accusations, \
         rss start {} MiB peak {} MiB end {} MiB, finality ticks p50/p95/p99 = {}/{}/{}",
        started.elapsed().as_secs(),
        total_ticks as f64 / 216_000.0,
        rss_start / 1024,
        rss_peak / 1024,
        rss_kb() / 1024,
        pct(0.50),
        pct(0.95),
        pct(0.99)
    );
}
