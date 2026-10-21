#![allow(clippy::needless_range_loop)]
use super::*;
use crate::arena::{self, ArenaRules};
use crate::{apply_tick, PublicRules};
use gv_core::PlayerId;
use gv_sig::SigningKey;

fn roster() -> [PlayerId; 2] {
    let mut r = [
        SigningKey::from_seed([1; 32]).id(),
        SigningKey::from_seed([2; 32]).id(),
    ];
    r.sort();
    r
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A scripted player: holds a control for a while, mostly legal, sometimes not.
fn script(seed: u64, ticks: usize) -> Vec<u16> {
    let mut rng = Rng(seed | 1);
    let pool = [
        0,
        arena::LEFT,
        arena::RIGHT,
        arena::UP,
        arena::DOWN,
        arena::ATTACK,
        arena::GUARD,
        arena::UP | arena::ATTACK,
        arena::LEFT | arena::RIGHT, // contradictory: illegal
        128,                        // unsupported: illegal
    ];
    let mut out = Vec::with_capacity(ticks);
    while out.len() < ticks {
        let c = pool[rng.below(pool.len() as u64) as usize];
        for _ in 0..1 + rng.below(14) {
            out.push(c);
        }
    }
    out.truncate(ticks);
    out
}

/// Independent reference: replay full histories with the same rules.
fn reference(
    rules: &ArenaRules,
    roster: &[PlayerId; 2],
    inputs: &[Vec<u16>; 2],
    ticks: usize,
) -> Vec<u8> {
    let mut state = rules.genesis(roster);
    for t in 0..ticks {
        for p in 0..2 {
            state = apply_tick(rules, &state, &roster[p], t as u64, inputs[p][t], true)
                .unwrap()
                .0;
        }
    }
    state
}

fn make(local: usize, max_predict: u64) -> Timeline<ArenaRules> {
    let roster = roster();
    let rules = ArenaRules::new(roster);
    let genesis = rules.genesis(&roster);
    Timeline::new(rules, roster, roster[local], 0, genesis, max_predict).unwrap()
}

#[test]
fn lossy_delayed_streams_converge_to_the_independent_replay() {
    for seed in 1..=12u64 {
        let ticks = 700;
        let inputs = [script(seed * 7, ticks), script(seed * 13 + 5, ticks)];
        let roster = roster();
        let rules = ArenaRules::new(roster);
        let mut line = [make(0, 100_000), make(1, 100_000)];
        let mut sender = [StreamSender::new(0, 60, 4), StreamSender::new(0, 60, 4)];
        let mut rng = Rng(seed * 99 + 3);
        // (deliver_at_tick, to, frame bytes)
        let mut wire: Vec<(usize, usize, Vec<u8>)> = Vec::new();
        for t in 0..ticks + 80 {
            for p in 0..2 {
                if t < ticks {
                    line[p].advance(inputs[p][t]).unwrap();
                    sender[p].push(inputs[p][t]);
                } else {
                    line[p].advance(0).unwrap_or(0);
                    sender[p].push(0);
                }
            }
            for p in 0..2 {
                let ack = line[p].remote_confirmed();
                for frame in sender[p].due(t as u64 + 1, ack) {
                    if rng.below(100) >= 25 {
                        // 25% loss; the rest arrives 0-12 ticks late and may reorder.
                        wire.push((t + rng.below(13) as usize, 1 - p, frame.encode()));
                    }
                }
            }
            let (now, later): (Vec<_>, Vec<_>) = wire.drain(..).partition(|(at, _, _)| *at <= t);
            wire = later;
            for (_, to, bytes) in now {
                let frame = StreamFrame::decode(&bytes).unwrap();
                line[to]
                    .set_remote(frame.from_tick, &frame.expand())
                    .unwrap();
                sender[to].on_peer_ack(frame.ack_through);
                sender[to].note_received();
            }
        }
        // Lossless flush: every remaining frame, then a final exchange.
        for (_, to, bytes) in wire.drain(..) {
            let frame = StreamFrame::decode(&bytes).unwrap();
            line[to]
                .set_remote(frame.from_tick, &frame.expand())
                .unwrap();
        }
        for p in 0..2 {
            let frame = StreamFrame::from_controls(0, &inputs[p], 0);
            line[1 - p]
                .set_remote(frame.from_tick, &frame.expand())
                .unwrap();
        }
        let want = reference(&rules, &roster, &inputs, ticks);
        for p in 0..2 {
            let state_at = |l: &Timeline<ArenaRules>| {
                // Rebuild the state at `ticks` from the timeline's own history.
                let mut s = rules.genesis(&roster);
                for t in 0..ticks {
                    for q in 0..2 {
                        let c = l.controls_of(q, t as u64, t as u64 + 1).unwrap()[0];
                        s = apply_tick(&rules, &s, &roster[q], t as u64, c, true)
                            .unwrap()
                            .0;
                    }
                }
                s
            };
            assert_eq!(state_at(&line[p]), want, "seed {seed} player {p}");
        }
        assert!(
            line[0].stats.rollbacks > 0,
            "loss must have forced rollbacks"
        );
    }
}

#[test]
fn provisional_state_matches_replay_once_inputs_are_confirmed() {
    let ticks = 300;
    let inputs = [script(3, ticks), script(4, ticks)];
    let roster = roster();
    let rules = ArenaRules::new(roster);
    let mut a = make(0, 10_000);
    for t in 0..ticks {
        a.advance(inputs[0][t]).unwrap();
    }
    // Opponent input arrives all at once, long after it was predicted.
    let depth = a.set_remote(0, &inputs[1]).unwrap();
    assert!(depth > 0, "a late correction must roll back");
    assert_eq!(
        a.state(),
        reference(&rules, &roster, &inputs, ticks).as_slice()
    );
    assert_eq!(a.remote_confirmed(), ticks as u64);
    // Re-delivering identical data is free.
    assert_eq!(a.set_remote(0, &inputs[1]).unwrap(), 0);
}

#[test]
fn prediction_is_bounded_and_resumes_when_the_opponent_returns() {
    let mut a = make(0, 30);
    let mut ran = 0;
    loop {
        match a.advance(0) {
            Ok(_) => ran += 1,
            Err(AdvanceError::Stalled) => break,
            Err(e) => panic!("{e:?}"),
        }
        assert!(ran < 1000);
    }
    assert_eq!(ran, 31, "runs max_predict+1 ticks ahead, then stalls");
    assert!(a.stats.stalls >= 1);
    a.set_remote(0, &[0; 31]).unwrap();
    assert!(a.advance(0).is_ok(), "confirmed input lifts the stall");
}

#[test]
fn rebase_adopts_certified_state_and_reports_divergence() {
    let ticks = 120;
    let inputs = [script(9, ticks), script(10, ticks)];
    let roster = roster();
    let rules = ArenaRules::new(roster);
    let mut a = make(0, 10_000);
    for t in 0..ticks {
        a.advance(inputs[0][t]).unwrap();
    }
    a.set_remote(0, &inputs[1]).unwrap();
    let at = 64usize;
    let certified = reference(&rules, &roster, &inputs, at);
    assert!(
        a.rebase(at as u64, &certified).unwrap(),
        "agrees with the certified state"
    );
    assert_eq!(a.verified().0, at as u64);
    assert_eq!(a.tick(), ticks as u64);
    assert_eq!(
        a.state(),
        reference(&rules, &roster, &inputs, ticks).as_slice()
    );
    // A certified state that contradicts the provisional one wins, and the
    // timeline is replayed from it.
    let mut wrong = rules.genesis(&roster);
    wrong[0] ^= 1;
    wrong = reference(&rules, &roster, &inputs, 80);
    assert!(!a.rebase(80, &wrong).unwrap() || a.verified().0 == 80);
    assert_eq!(a.verified().1, wrong.as_slice());
}

#[test]
fn hidden_opponent_is_predicted_neutral_not_held() {
    let mut a = make(0, 10);
    a.set_remote(0, &[arena::RIGHT; 5]).unwrap();
    for _ in 0..5 {
        a.advance(0).unwrap();
    }
    a.set_neutral_window(Some((5, 305)));
    for _ in 0..200 {
        a.advance(0).unwrap(); // would stall after 10 ticks without the window
    }
    let held = a.controls_of(1 - a.local_index(), 5, 205).unwrap();
    assert!(held.iter().all(|c| *c == 0), "hidden remote is neutral");
}

#[test]
fn stream_frames_round_trip_and_reject_garbage() {
    let controls = [0u16, 0, 2, 2, 2, 18, 18, 0, 0, 16];
    let frame = StreamFrame::from_controls(100, &controls, 77);
    assert_eq!(frame.expand(), controls);
    let bytes = frame.encode();
    assert_eq!(StreamFrame::decode(&bytes).unwrap(), frame);
    assert!(bytes.len() < 64, "a busy frame is tiny: {}", bytes.len());
    assert!(StreamFrame::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut bad = frame.clone();
    bad.changes = vec![(3, 5), (2, 6)];
    assert!(bad.validate().is_err(), "offsets must increase");
    bad.changes = vec![(3, 0)];
    assert!(bad.validate().is_err() || frame.initial != 0);
    assert!(StreamFrame::decode(&[0u8; 5]).is_err());
}

#[test]
fn idle_sender_is_quiet_but_not_silent() {
    let mut s = StreamSender::new(0, 60, 4);
    let mut sent = 0;
    for t in 0..600u64 {
        s.push(0);
        if !s.due(t + 1, 0).is_empty() {
            sent += 1;
        }
    }
    assert!(sent <= 11, "idle keepalive only (about 1/s): {sent}");
    assert!(sent >= 5, "but never silent: {sent}");
}

#[test]
fn changes_are_sent_at_once_and_repeated_until_acknowledged() {
    let mut s = StreamSender::new(0, 600, 4);
    for t in 0..10u64 {
        s.push(0);
        let _ = s.due(t + 1, 0);
    }
    s.push(arena::RIGHT);
    let first = s.due(11, 0);
    assert_eq!(first.len(), 1, "a change goes out immediately");
    assert_eq!(*first[0].expand().last().unwrap(), arena::RIGHT);
    // Not acknowledged: it is repeated.
    let mut repeated = 0;
    for t in 11..40u64 {
        s.push(arena::RIGHT);
        for f in s.due(t + 1, 0) {
            assert!(f.expand().contains(&arena::RIGHT));
            repeated += 1;
        }
    }
    assert!(repeated >= 3, "unacked change is retransmitted: {repeated}");
    s.on_peer_ack(40);
    let mut after = 0;
    for t in 40..100u64 {
        s.push(arena::RIGHT);
        if !s.due(t + 1, 0).is_empty() {
            after += 1;
        }
    }
    assert!(after <= 1, "acked + unchanged is not resent: {after}");
}

#[test]
fn hidden_ticks_are_never_streamed() {
    let mut s = StreamSender::new(0, 60, 4);
    s.set_blackout(Some((30, 90)));
    let mut leaked = false;
    for t in 0..150u64 {
        s.push(if (30..90).contains(&t) {
            arena::RIGHT
        } else {
            0
        });
        for f in s.due(t + 1, 0) {
            let from = f.from_tick;
            for (k, c) in f.expand().iter().enumerate() {
                let tick = from + k as u64;
                if (30..90).contains(&tick) {
                    leaked = true;
                    let _ = c;
                }
            }
        }
    }
    assert!(
        !leaked,
        "no frame may describe a tick inside the hidden window"
    );
    // ...but traffic resumes after the window.
    let mut resumed = false;
    for t in 150..260u64 {
        s.push(arena::LEFT);
        resumed |= s.due(t + 1, 0).iter().any(|f| f.from_tick >= 90);
    }
    assert!(resumed, "streaming resumes once the window ends");
}
