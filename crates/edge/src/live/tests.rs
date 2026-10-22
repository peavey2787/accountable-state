#![allow(clippy::needless_range_loop)]
use super::timeline::Prediction;
use super::*;
use crate::testkit::{self as grid, GridRules, GridState};
use crate::StateMachine;
use gv_core::Session;
use gv_replay::step_tick;
use gv_sig::SigningKey;

fn session(n: u8) -> Session {
    let ids: Vec<_> = (1..=n)
        .map(|i| SigningKey::from_seed([i; 32]).id())
        .collect();
    Session::unanimous([3; 32], &ids).unwrap()
}

fn c(controls: u16) -> Vec<u8> {
    controls.to_le_bytes().to_vec()
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
fn script(seed: u64, ticks: usize) -> Vec<Vec<u8>> {
    let mut rng = Rng(seed | 1);
    let pool = [
        0,
        grid::LEFT,
        grid::RIGHT,
        grid::UP,
        grid::DOWN,
        grid::ACT,
        grid::HOLD,
        grid::UP | grid::ACT,
        grid::LEFT | grid::RIGHT, // contradictory: illegal
        128,                      // unsupported: illegal
    ];
    let mut out = Vec::with_capacity(ticks);
    while out.len() < ticks {
        let control = pool[rng.below(pool.len() as u64) as usize];
        for _ in 0..1 + rng.below(14) {
            out.push(c(control));
        }
    }
    out.truncate(ticks);
    out
}

/// Independent reference: replay full histories with the same rules and the shared tick stepper.
fn reference(session: &Session, ticks: usize, input: &dyn Fn(usize, usize) -> Vec<u8>) -> Vec<u8> {
    let rules = GridRules;
    let mut state = rules.genesis(session);
    for t in 0..ticks {
        let payloads: Vec<Vec<u8>> = (0..session.roster.len()).map(|s| input(s, t)).collect();
        let per_slot: Vec<Vec<&[u8]>> = payloads.iter().map(|p| vec![p.as_slice()]).collect();
        state = step_tick(
            &rules,
            session,
            state,
            t as u64,
            &per_slot,
            true,
            &mut Vec::new(),
        )
        .unwrap();
    }
    state
}

fn make(session: &Session, local: usize, max_predict: u64) -> Timeline<GridRules> {
    let genesis = GridRules.genesis(session);
    Timeline::new(
        GridRules,
        session.clone(),
        local,
        (0, genesis),
        c(0),
        Prediction::HoldLast,
        max_predict,
    )
    .unwrap()
}

#[test]
fn lossy_delayed_streams_converge_to_the_independent_replay() {
    const N: usize = 3;
    let session = session(N as u8);
    for seed in 1..=8u64 {
        let ticks = 500;
        let inputs: Vec<_> = (0..N)
            .map(|p| script(seed * 7 + p as u64 * 31, ticks))
            .collect();
        let mut line: Vec<_> = (0..N).map(|p| make(&session, p, 100_000)).collect();
        // sender[p][q]: what p streams to q.
        let mut sender: Vec<Vec<StreamSender>> = (0..N)
            .map(|_| (0..N).map(|_| StreamSender::new(0, 60, 4)).collect())
            .collect();
        let mut rng = Rng(seed * 99 + 3);
        // (deliver_at_tick, from, to, frame bytes)
        let mut wire: Vec<(usize, usize, usize, Vec<u8>)> = Vec::new();
        for t in 0..ticks + 80 {
            for p in 0..N {
                let now = if t < ticks {
                    inputs[p][t].clone()
                } else {
                    c(0)
                };
                line[p].advance(&now).unwrap_or(0);
                for q in (0..N).filter(|q| *q != p) {
                    sender[p][q].push(now.clone());
                }
            }
            for p in 0..N {
                for q in (0..N).filter(|q| *q != p) {
                    let ack = line[p].confirmed(q);
                    for frame in sender[p][q].due(t as u64 + 1, ack) {
                        if rng.below(100) >= 25 {
                            // 25% loss; the rest arrives 0-12 ticks late and may reorder.
                            wire.push((t + rng.below(13) as usize, p, q, frame.encode()));
                        }
                    }
                }
            }
            let (now, later): (Vec<_>, Vec<_>) = wire.drain(..).partition(|(at, _, _, _)| *at <= t);
            wire = later;
            for (_, from, to, bytes) in now {
                let frame = StreamFrame::decode(&bytes).unwrap();
                line[to]
                    .set_remote(from, frame.from_tick, &frame.expand())
                    .unwrap();
                sender[to][from].on_peer_ack(frame.ack_through);
                sender[to][from].note_received();
            }
        }
        // Lossless flush: every remaining frame, then a final full exchange.
        for (_, from, to, bytes) in wire.drain(..) {
            let frame = StreamFrame::decode(&bytes).unwrap();
            line[to]
                .set_remote(from, frame.from_tick, &frame.expand())
                .unwrap();
        }
        for p in 0..N {
            let frame = StreamFrame::from_inputs(0, &inputs[p], 0);
            for q in (0..N).filter(|q| *q != p) {
                line[q]
                    .set_remote(p, frame.from_tick, &frame.expand())
                    .unwrap();
            }
        }
        let want = reference(&session, ticks, &|s, t| inputs[s][t].clone());
        for p in 0..N {
            let rebuilt = reference(&session, ticks, &|s, t| {
                line[p]
                    .inputs_of(s, t as u64, t as u64 + 1)
                    .unwrap()
                    .remove(0)
            });
            assert_eq!(rebuilt, want, "seed {seed} participant {p}");
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
    let session = session(2);
    let inputs = [script(3, ticks), script(4, ticks)];
    let mut a = make(&session, 0, 10_000);
    for t in 0..ticks {
        a.advance(&inputs[0][t]).unwrap();
    }
    // The other participant's input arrives all at once, long after it was predicted.
    let depth = a.set_remote(1, 0, &inputs[1]).unwrap();
    assert!(depth > 0, "a late correction must roll back");
    assert_eq!(
        a.state(),
        reference(&session, ticks, &|s, t| inputs[s][t].clone()).as_slice()
    );
    assert_eq!(a.confirmed(1), ticks as u64);
    // Re-delivering identical data is free.
    assert_eq!(a.set_remote(1, 0, &inputs[1]).unwrap(), 0);
}

#[test]
fn prediction_is_bounded_and_resumes_when_the_remote_returns() {
    let session = session(2);
    let mut a = make(&session, 0, 30);
    let mut ran = 0;
    loop {
        match a.advance(&c(0)) {
            Ok(_) => ran += 1,
            Err(AdvanceError::Stalled) => break,
            Err(e) => panic!("{e:?}"),
        }
        assert!(ran < 1000);
    }
    assert_eq!(ran, 31, "runs max_predict+1 ticks ahead, then stalls");
    assert!(a.stats.stalls >= 1);
    a.set_remote(1, 0, &vec![c(0); 31]).unwrap();
    assert!(a.advance(&c(0)).is_ok(), "confirmed input lifts the stall");
}

#[test]
fn a_stalled_remote_stalls_a_three_party_timeline_until_it_returns() {
    let session = session(3);
    let mut a = make(&session, 0, 10);
    a.set_remote(1, 0, &vec![c(0); 200]).unwrap();
    let mut ran = 0;
    while a.advance(&c(0)).is_ok() {
        ran += 1;
        assert!(ran < 1000);
    }
    assert_eq!(
        ran, 11,
        "one silent participant bounds everyone's prediction"
    );
    a.set_remote(2, 0, &vec![c(0); 50]).unwrap();
    assert!(a.advance(&c(0)).is_ok());
}

#[test]
fn rebase_adopts_certified_state_and_reports_divergence() {
    let ticks = 120;
    let session = session(2);
    let inputs = [script(9, ticks), script(10, ticks)];
    let at = |t: usize| reference(&session, t, &|s, k| inputs[s][k].clone());
    let mut a = make(&session, 0, 10_000);
    for t in 0..ticks {
        a.advance(&inputs[0][t]).unwrap();
    }
    a.set_remote(1, 0, &inputs[1]).unwrap();
    assert!(
        a.rebase(64, &at(64)).unwrap(),
        "agrees with the certified state"
    );
    assert_eq!(a.verified().0, 64);
    assert_eq!(a.tick(), ticks as u64);
    assert_eq!(a.state(), at(ticks).as_slice());
    // A certified state that contradicts the provisional one wins, and the timeline is
    // replayed from it.
    let mut wrong = GridState::decode(&at(80)).unwrap();
    wrong.walkers[0].1.acts += 1;
    let wrong = wrong.encode();
    assert!(!a.rebase(80, &wrong).unwrap());
    assert_eq!(a.verified(), (80, wrong.as_slice()));
}

#[test]
fn sealed_participant_is_predicted_neutral_not_held() {
    let session = session(2);
    let mut a = make(&session, 0, 10);
    a.set_remote(1, 0, &vec![c(grid::RIGHT); 5]).unwrap();
    for _ in 0..5 {
        a.advance(&c(0)).unwrap();
    }
    a.set_sealed_window(1, Some((5, 305)));
    for _ in 0..200 {
        a.advance(&c(0)).unwrap(); // would stall after 10 ticks without the window
    }
    let held = a.inputs_of(1, 5, 205).unwrap();
    assert!(held.iter().all(|x| *x == c(0)), "sealed remote is neutral");
}

#[test]
fn stream_frames_round_trip_and_reject_garbage() {
    let controls: Vec<Vec<u8>> = [0u16, 0, 2, 2, 2, 18, 18, 0, 0, 16].map(c).to_vec();
    let frame = StreamFrame::from_inputs(100, &controls, 77);
    assert_eq!(frame.expand(), controls);
    let bytes = frame.encode();
    assert_eq!(StreamFrame::decode(&bytes).unwrap(), frame);
    assert!(bytes.len() < 64, "a busy frame is tiny: {}", bytes.len());
    assert!(StreamFrame::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut bad = frame.clone();
    bad.changes = vec![(3, c(5)), (2, c(6))];
    assert!(bad.validate().is_err(), "offsets must increase");
    bad.changes = vec![(3, frame.initial.clone())];
    assert!(bad.validate().is_err(), "a change must change something");
    bad.changes = vec![(3, vec![1])];
    assert!(
        bad.validate().is_err(),
        "every change is as wide as the initial"
    );
    assert!(StreamFrame::decode(&[0u8; 5]).is_err());
}

#[test]
fn idle_sender_is_quiet_but_not_silent() {
    let mut s = StreamSender::new(0, 60, 4);
    let mut sent = 0;
    for t in 0..600u64 {
        s.push(c(0));
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
        s.push(c(0));
        let _ = s.due(t + 1, 0);
    }
    s.push(c(grid::RIGHT));
    let first = s.due(11, 0);
    assert_eq!(first.len(), 1, "a change goes out immediately");
    assert_eq!(*first[0].expand().last().unwrap(), c(grid::RIGHT));
    // Not acknowledged: it is repeated.
    let mut repeated = 0;
    for t in 11..40u64 {
        s.push(c(grid::RIGHT));
        for f in s.due(t + 1, 0) {
            assert!(f.expand().contains(&c(grid::RIGHT)));
            repeated += 1;
        }
    }
    assert!(repeated >= 3, "unacked change is retransmitted: {repeated}");
    s.on_peer_ack(40);
    let mut after = 0;
    for t in 40..100u64 {
        s.push(c(grid::RIGHT));
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
            c(grid::RIGHT)
        } else {
            c(0)
        });
        for f in s.due(t + 1, 0) {
            let from = f.from_tick;
            leaked |= (0..f.expand().len()).any(|k| (30..90).contains(&(from + k as u64)));
        }
    }
    assert!(
        !leaked,
        "no frame may describe a tick inside the hidden window"
    );
    // ...but traffic resumes after the window.
    let mut resumed = false;
    for t in 150..260u64 {
        s.push(c(grid::LEFT));
        resumed |= s.due(t + 1, 0).iter().any(|f| f.from_tick >= 90);
    }
    assert!(resumed, "streaming resumes once the window ends");
}
