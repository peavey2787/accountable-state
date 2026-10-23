//! Reconnection on the in-process network: a peer that was away proves itself and catches up
//! from certified epochs; replayed, forged and duplicate claims are refused.
use super::msg::{Dest, PipeMsg};
use super::netsim::{busy, config, net_with, Net, MATCH};
use super::pipeline::{PeerEvent, PipeEvent};
use super::resume::{ResumeMsg, SignedProof};
use crate::fixtures::Cast;
use gv_core::Certification;

fn trio() -> Net {
    let cast = Cast::with_policy(3, MATCH, Certification::Threshold { min: 2 });
    let mut cfg = config();
    cfg.close_after_ticks = Some(60);
    net_with(cast, vec![busy(1, 900), busy(2, 900), busy(3, 900)], cfg, 2)
}

fn reconnect(n: &mut Net, i: usize) {
    let now = n.now;
    let ids: Vec<_> = n.cast.keys.iter().map(gv_sig::SigningKey::id).collect();
    for j in (0..ids.len()).filter(|j| *j != i) {
        n.peers[i].pipe.peer_up(ids[j]);
        n.peers[j].pipe.peer_up(ids[i]);
    }
    let _ = now;
}

fn peer_events(n: &Net, i: usize) -> Vec<PeerEvent> {
    n.peers[i]
        .events
        .iter()
        .filter_map(|(_, e)| match e {
            PipeEvent::Peer(p) => Some(p.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn an_absent_peer_resumes_and_catches_up_from_certified_epochs() {
    let mut n = trio();
    n.offline[2] = true;
    n.run(300);
    let ahead = n.peers[0].pipe.verified_tick();
    assert!(ahead >= 100, "play went on without the absent peer");
    assert_eq!(n.peers[2].pipe.verified_tick(), 0);
    n.offline[2] = false;
    reconnect(&mut n, 2);
    n.run(120);
    assert!(
        n.peers[2].pipe.verified_tick() >= ahead,
        "peer 2 reached {} of {ahead}",
        n.peers[2].pipe.verified_tick()
    );
    assert!(peer_events(&n, 2)
        .iter()
        .any(|e| matches!(e, PeerEvent::CaughtUp { .. })));
    assert!(n.violations(0).is_empty() && n.violations(2).is_empty());
}

#[test]
fn an_unsolicited_or_replayed_proof_is_ignored() {
    let mut n = trio();
    n.run(40);
    let ids: Vec<_> = n.cast.keys.iter().map(gv_sig::SigningKey::id).collect();
    let stale = SignedProof::sign(MATCH, 9, [1; 16], 0, [3; 16], &n.cast.keys[1]);
    n.inject(0, 1, PipeMsg::Resume(ResumeMsg::Proof(stale)));
    assert!(
        !n.peers[0].pipe.is_proven(&ids[1]),
        "no challenge was issued"
    );
    n.peers[0].pipe.peer_up(ids[1]);
    let again = SignedProof::sign(MATCH, 9, [1; 16], 0, [3; 16], &n.cast.keys[1]);
    n.inject(0, 1, PipeMsg::Resume(ResumeMsg::Proof(again)));
    assert!(!n.peers[0].pipe.is_proven(&ids[1]), "wrong nonce");
}

#[test]
fn a_sync_request_is_served_only_to_a_proven_peer() {
    let mut n = trio();
    n.run(200);
    let before = n.peers[0].sent.len();
    n.inject(0, 1, PipeMsg::Resume(ResumeMsg::Sync { tip: 0 }));
    n.run(1);
    let served = n.peers[0].sent[before..].iter().any(|(_, o)| {
        matches!(&o.msg, PipeMsg::Resume(ResumeMsg::Epochs { .. })) && matches!(o.to, Dest::Peer(_))
    });
    assert!(!served, "unproven peers get no state");
}

#[test]
fn the_newer_incarnation_wins_and_the_older_is_told_it_was_superseded() {
    let mut n = trio();
    n.run(40);
    let ids: Vec<_> = n.cast.keys.iter().map(gv_sig::SigningKey::id).collect();
    for (inc, sid) in [(5u64, [9u8; 16]), (4, [1; 16])] {
        n.peers[0].pipe.peer_up(ids[1]);
        let nonce = challenge_nonce(&mut n, 0);
        let p = SignedProof::sign(MATCH, inc, sid, 0, nonce, &n.cast.keys[1]);
        n.inject(0, 1, PipeMsg::Resume(ResumeMsg::Proof(p)));
    }
    let resumed: Vec<_> = peer_events(&n, 0)
        .into_iter()
        .filter_map(|e| match e {
            PeerEvent::Resumed { incarnation, .. } => Some(incarnation),
            _ => None,
        })
        .collect();
    assert_eq!(resumed, vec![5], "the older claim never replaces the newer");
}

#[test]
fn simultaneous_equal_incarnations_resolve_the_same_way_on_both_sides() {
    let a = SignedProof::sign(MATCH, 3, [1; 16], 0, [0; 16], &Cast::new(1, MATCH).keys[0]);
    let b = SignedProof::sign(MATCH, 3, [2; 16], 0, [0; 16], &Cast::new(1, MATCH).keys[0]);
    assert!(a.outranks(&b) && !b.outranks(&a));
}

#[test]
fn a_grace_period_expiry_is_reported_but_never_a_violation() {
    let mut n = trio();
    let id = n.cast.keys[2].id();
    n.run(10);
    n.peers[0].pipe.peer_down(id, n.now);
    n.run(2000);
    assert!(peer_events(&n, 0)
        .iter()
        .any(|e| matches!(e, PeerEvent::GraceExpired { peer, .. } if *peer == id)));
    assert!(n.violations(0).is_empty());
}

/// The nonce of the challenge peer `i` just queued (the test plays the remote side).
fn challenge_nonce(n: &mut Net, i: usize) -> [u8; 16] {
    std::iter::from_fn(|| n.peers[i].pipe.poll_outbox())
        .filter_map(|o| match o.msg {
            PipeMsg::Resume(ResumeMsg::Challenge { nonce }) => Some(nonce),
            _ => None,
        })
        .last()
        .expect("a challenge was sent")
}
