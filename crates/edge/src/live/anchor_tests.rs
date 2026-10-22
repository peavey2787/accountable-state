//! Live anchor recovery: lost, rolled-back and forked local state is repaired from heads that
//! the other participants or a witness returned; forged, foreign and replayed anchors change
//! nothing.
use super::auditor::{AuditEvent, Auditor};
use super::msg::{Dest, PipeMsg};
use crate::audit::trust::{Recovery, Unresolved};
use crate::audit::{AuditLog, Authenticator};
use gv_core::Roster;
use gv_sig::SigningKey;

const M: [u8; 32] = [7; 32];
const R: [u8; 32] = [9; 32];

/// Three participants: `a` restarts, `b` and `c` are its peers.
fn keys() -> (SigningKey, SigningKey, SigningKey) {
    (
        SigningKey::from_seed([1; 32]),
        SigningKey::from_seed([2; 32]),
        SigningKey::from_seed([3; 32]),
    )
}
fn log_of(key: &SigningKey, n: u64, salt: u8) -> AuditLog {
    let mut l = AuditLog::new(M, key.id());
    for i in 0..n {
        l.append(1, vec![salt, i as u8]).unwrap();
    }
    l
}
fn au(me: &SigningKey, others: &[&SigningKey]) -> Auditor {
    let ids: Vec<_> = std::iter::once(me)
        .chain(others.iter().copied())
        .map(SigningKey::id)
        .collect();
    Auditor::new(me.clone(), &Roster::players(&ids).unwrap(), M, R).unwrap()
}
fn feed(a: &mut Auditor, from: &SigningKey, m: PipeMsg) {
    a.on_msg(from.id(), m, 0, &super::NoAnswers);
}
/// Both peers give the same answer.
fn feed_all(a: &mut Auditor, peers: [&SigningKey; 2], m: &PipeMsg) {
    for p in peers {
        feed(a, p, m.clone());
    }
}
fn drain(a: &mut Auditor) -> Vec<super::msg::Outgoing> {
    std::iter::from_fn(|| a.poll_msg()).collect()
}

#[test]
fn lost_log_is_rebuilt_from_a_head_the_peers_hold() {
    let (a, b, c) = keys();
    let anchor = log_of(&a, 30, 0).sign_authenticator(R, &a);
    let mut x = au(&a, &[&b, &c]);
    x.restore(None, &[], &[]);
    x.require_anchor_check();
    assert!(x.anchor_check_pending());
    let asked = drain(&mut x);
    assert!(asked
        .iter()
        .any(|o| matches!(o.msg, PipeMsg::AnchorReq) && matches!(o.to, Dest::All)));
    feed(&mut x, &b, PipeMsg::Anchor(Some(anchor.clone())));
    assert!(
        x.anchor_check_pending(),
        "every peer must answer before signing resumes"
    );
    feed(&mut x, &c, PipeMsg::Anchor(None));
    assert!(!x.anchor_check_pending());
    assert!(x.recovery().may_sign());
    assert_eq!(x.log().len(), 30);
    assert_eq!(x.log().head(), anchor.head);
    let mut ev = Vec::new();
    while let Some(e) = x.poll_event() {
        ev.push(e);
    }
    assert!(ev
        .iter()
        .any(|e| matches!(e, AuditEvent::Rebased { seq: 30 })));
}

#[test]
fn rolled_back_and_forked_logs_are_rebased_not_extended() {
    let (a, b, c) = keys();
    let real = log_of(&a, 30, 0);
    let anchor = real.sign_authenticator(R, &a);
    for log in [log_of(&a, 12, 0), log_of(&a, 40, 1)] {
        let mut x = au(&a, &[&b, &c]);
        x.restore(Some(log), &[], &[]);
        x.require_anchor_check();
        feed_all(&mut x, [&b, &c], &PipeMsg::Anchor(Some(anchor.clone())));
        assert!(x.recovery().may_sign(), "{:?}", x.recovery());
        assert_eq!(x.log().len(), 30);
        assert_eq!(x.log().head(), real.head());
    }
}

#[test]
fn no_head_anywhere_resolves_an_unanchored_log_only_when_every_peer_answered() {
    let (a, b, c) = keys();
    let mut x = au(&a, &[&b, &c]);
    x.restore(Some(log_of(&a, 5, 0)), &[], &[]);
    assert_eq!(*x.recovery(), Recovery::Unresolved(Unresolved::NoAnchor));
    x.require_anchor_check();
    assert!(x.anchor_check_pending() && !x.recovery().may_sign());
    feed(&mut x, &b, PipeMsg::Anchor(None));
    assert!(
        x.anchor_check_pending(),
        "one silent peer keeps signing suspended"
    );
    feed(&mut x, &b, PipeMsg::Anchor(None));
    assert!(
        x.anchor_check_pending(),
        "a repeat answer is not a second peer"
    );
    feed(&mut x, &c, PipeMsg::Anchor(None));
    assert!(!x.anchor_check_pending());
    assert!(x.recovery().may_sign());
}

#[test]
fn a_lowered_quorum_trades_safety_for_liveness_explicitly() {
    let (a, b, c) = keys();
    let mut x = au(&a, &[&b, &c]);
    x.set_anchor_quorum(1);
    x.restore(Some(log_of(&a, 5, 0)), &[], &[]);
    x.require_anchor_check();
    feed(&mut x, &b, PipeMsg::Anchor(None));
    assert!(!x.anchor_check_pending());
    assert!(x.recovery().may_sign());
}

#[test]
fn forged_foreign_and_replayed_anchors_change_nothing() {
    let (a, b, c) = keys();
    let mine = log_of(&a, 30, 0);
    let stranger = SigningKey::from_seed([5; 32]);
    let theirs = log_of(&b, 50, 0).sign_authenticator(R, &b); // not mine
    let other_match = {
        let mut l = AuditLog::new([8; 32], a.id());
        l.append(1, vec![1]).unwrap();
        l.sign_authenticator(R, &a)
    };
    let mut forged: Authenticator = mine.sign_authenticator(R, &stranger); // wrong key
    forged.owner = a.id();
    let mut x = au(&a, &[&b, &c]);
    let own = mine.sign_authenticator(R, &a);
    x.restore(Some(mine.clone()), &[own], &[]);
    x.require_anchor_check();
    for bad in [theirs, other_match, forged] {
        feed(&mut x, &b, PipeMsg::Anchor(Some(bad)));
        assert!(
            x.anchor_check_pending(),
            "invalid anchor must not end the check"
        );
        assert_eq!(x.log().len(), 30);
    }
    // A replayed OLDER head of mine is consistent with the log and changes nothing.
    let old = log_of(&a, 10, 0).sign_authenticator(R, &a);
    feed_all(&mut x, [&b, &c], &PipeMsg::Anchor(Some(old)));
    assert!(x.recovery().may_sign());
    assert_eq!(x.log().len(), 30);
    assert_eq!(x.log().head(), mine.head());
}

#[test]
fn a_non_participant_cannot_answer_an_anchor_check() {
    let (a, b, c) = keys();
    let outsider = SigningKey::from_seed([6; 32]);
    let mut x = au(&a, &[&b, &c]);
    x.restore(None, &[], &[]);
    x.require_anchor_check();
    feed(&mut x, &outsider, PipeMsg::Anchor(None));
    feed(&mut x, &b, PipeMsg::Anchor(None));
    assert!(x.anchor_check_pending(), "an outsider is not a peer");
}

#[test]
fn a_peer_answers_with_the_highest_head_it_holds() {
    let (a, b, c) = keys();
    let mut x = au(&a, &[&b, &c]);
    let h20 = log_of(&b, 20, 0).sign_authenticator(R, &b);
    x.supply_anchor(&h20);
    feed(&mut x, &b, PipeMsg::AnchorReq);
    let reply = drain(&mut x).pop().expect("a reply");
    assert!(matches!(reply.to, Dest::Peer(p) if p == b.id()));
    match reply.msg {
        PipeMsg::Anchor(Some(got)) => assert_eq!(got.seq, 20),
        o => panic!("unexpected {o:?}"),
    }
}

#[test]
fn rebase_is_durable_and_survives_another_restart() {
    use crate::audit::journal::FileTrustStore;
    let (a, b, c) = keys();
    let real = log_of(&a, 30, 0);
    let anchor = real.sign_authenticator(R, &a);
    let dir = std::env::temp_dir().join(format!("gv-anchor-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let base = dir.join("p");
    {
        let (store, loaded) = FileTrustStore::open(&base, M, a.id()).unwrap();
        let mut x = au(&a, &[&b, &c]);
        x.restore(loaded.log.ok(), &loaded.heads, &[]);
        x.attach_store(Box::new(store), 0, 0);
        x.require_anchor_check();
        feed_all(&mut x, [&b, &c], &PipeMsg::Anchor(Some(anchor.clone())));
        assert!(x.recovery().may_sign());
        assert!(x.make_durable());
    }
    let (_s, loaded) = FileTrustStore::open(&base, M, a.id()).unwrap();
    let log = loaded.log.ok().expect("rebased log is durable");
    assert_eq!(log.len(), 30);
    assert_eq!(log.head(), real.head());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_witness_head_defeats_peers_withholding_a_newer_head() {
    let (a, b, c) = keys();
    let w = SigningKey::from_seed([4; 32]);
    let real = log_of(&a, 30, 0);
    let held_by_witness = real.sign_authenticator(R, &a);
    let mut x = au(&a, &[&b, &c]);
    x.admit_witness(w.id());
    x.restore(Some(log_of(&a, 5, 0)), &[], &[]);
    x.require_anchor_check();
    feed_all(&mut x, [&b, &c], &PipeMsg::Anchor(None)); // the peers claim to hold nothing
    assert!(
        x.anchor_check_pending(),
        "with witnesses pinned, the peers alone cannot end the check"
    );
    assert!(!x.recovery().may_sign());
    x.on_witness_anchor(&held_by_witness);
    assert!(!x.anchor_check_pending());
    assert!(x.recovery().may_sign());
    assert_eq!(
        x.log().head(),
        real.head(),
        "rebased on the witness-held head"
    );
}

#[test]
fn silent_witnesses_delay_signing_only_for_the_bounded_wait() {
    let (a, b, c) = keys();
    let mut x = au(&a, &[&b, &c]);
    x.admit_witness(SigningKey::from_seed([4; 32]).id());
    x.restore(Some(log_of(&a, 5, 0)), &[], &[]);
    x.require_anchor_check();
    feed_all(&mut x, [&b, &c], &PipeMsg::Anchor(None));
    x.tick(super::auditor::ANCHOR_WITNESS_WAIT - 1);
    assert!(x.anchor_check_pending());
    x.tick(super::auditor::ANCHOR_WITNESS_WAIT);
    assert!(!x.anchor_check_pending());
    assert!(x.recovery().may_sign());
}

#[test]
fn a_witness_alone_never_ends_the_check_and_unpinned_witnesses_are_ignored() {
    let (a, b, c) = keys();
    let real = log_of(&a, 30, 0);
    let head = real.sign_authenticator(R, &a);
    let mut x = au(&a, &[&b, &c]);
    x.restore(None, &[], &[]);
    x.require_anchor_check();
    x.on_witness_anchor(&head); // no witness pinned: ignored
    assert_eq!(x.log().len(), 0);
    x.admit_witness(SigningKey::from_seed([4; 32]).id());
    x.on_witness_anchor(&head);
    assert!(x.anchor_check_pending(), "the peers' answers are mandatory");
    feed_all(&mut x, [&b, &c], &PipeMsg::Anchor(None));
    assert!(!x.anchor_check_pending());
    assert_eq!(x.log().head(), real.head());
}
