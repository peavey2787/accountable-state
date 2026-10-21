//! Live anchor recovery: lost, rolled-back and forked local state is repaired from heads that
//! the opponent or a witness returned; forged, foreign and replayed anchors change nothing.
use super::auditor::{AuditEvent, Auditor};
use super::msg::PipeMsg;
use crate::audit::trust::{Recovery, Unresolved};
use crate::audit::{AuditLog, Authenticator};
use gv_sig::SigningKey;

const M: [u8; 32] = [7; 32];
const R: [u8; 32] = [9; 32];

fn keys() -> (SigningKey, SigningKey) {
    (
        SigningKey::from_seed([1; 32]),
        SigningKey::from_seed([2; 32]),
    )
}
fn log_of(key: &SigningKey, n: u64, salt: u8) -> AuditLog {
    let mut l = AuditLog::new(M, key.id());
    for i in 0..n {
        l.append(1, vec![salt, i as u8]).unwrap();
    }
    l
}
fn au(me: &SigningKey, other: &SigningKey) -> Auditor {
    Auditor::new(me.clone(), [me.id(), other.id()], M, R).unwrap()
}
fn feed(a: &mut Auditor, m: PipeMsg) {
    a.on_msg(m, 0, &super::NoAnswers);
}
fn drain(a: &mut Auditor) -> Vec<PipeMsg> {
    std::iter::from_fn(|| a.poll_msg()).collect()
}

#[test]
fn lost_log_is_rebuilt_from_a_head_the_opponent_holds() {
    let (a, b) = keys();
    let anchor = log_of(&a, 30, 0).sign_authenticator(R, &a);
    let mut x = au(&a, &b);
    x.restore(None, &[], &[]);
    x.require_anchor_check();
    assert!(x.anchor_check_pending());
    assert!(drain(&mut x)
        .iter()
        .any(|m| matches!(m, PipeMsg::AnchorReq)));
    feed(&mut x, PipeMsg::Anchor(Some(anchor.clone())));
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
    let (a, b) = keys();
    let real = log_of(&a, 30, 0);
    let anchor = real.sign_authenticator(R, &a);
    for log in [log_of(&a, 12, 0), log_of(&a, 40, 1)] {
        let mut x = au(&a, &b);
        x.restore(Some(log), &[], &[]);
        x.require_anchor_check();
        feed(&mut x, PipeMsg::Anchor(Some(anchor.clone())));
        assert!(x.recovery().may_sign(), "{:?}", x.recovery());
        assert_eq!(x.log().len(), 30);
        assert_eq!(x.log().head(), real.head());
    }
}

#[test]
fn no_head_anywhere_resolves_an_unanchored_log_only_when_answered() {
    let (a, b) = keys();
    let mut x = au(&a, &b);
    x.restore(Some(log_of(&a, 5, 0)), &[], &[]);
    assert_eq!(*x.recovery(), Recovery::Unresolved(Unresolved::NoAnchor));
    x.require_anchor_check();
    assert!(x.anchor_check_pending() && !x.recovery().may_sign());
    feed(&mut x, PipeMsg::Anchor(None));
    assert!(!x.anchor_check_pending());
    assert!(x.recovery().may_sign());
}

#[test]
fn forged_foreign_and_replayed_anchors_change_nothing() {
    let (a, b) = keys();
    let mine = log_of(&a, 30, 0);
    let c = SigningKey::from_seed([3; 32]);
    let theirs = log_of(&b, 50, 0).sign_authenticator(R, &b); // not mine
    let other_match = {
        let mut l = AuditLog::new([8; 32], a.id());
        l.append(1, vec![1]).unwrap();
        l.sign_authenticator(R, &a)
    };
    let mut forged: Authenticator = mine.sign_authenticator(R, &c); // signed by the wrong key
    forged.owner = a.id();
    let mut x = au(&a, &b);
    let own = mine.sign_authenticator(R, &a);
    x.restore(Some(mine.clone()), &[own], &[]);
    x.require_anchor_check();
    for bad in [theirs, other_match, forged] {
        feed(&mut x, PipeMsg::Anchor(Some(bad)));
        assert!(
            x.anchor_check_pending(),
            "invalid anchor must not end the check"
        );
        assert_eq!(x.log().len(), 30);
    }
    // A replayed OLDER head of mine is consistent with the log and changes nothing.
    let old = log_of(&a, 10, 0).sign_authenticator(R, &a);
    feed(&mut x, PipeMsg::Anchor(Some(old)));
    assert!(x.recovery().may_sign());
    assert_eq!(x.log().len(), 30);
    assert_eq!(x.log().head(), mine.head());
}

#[test]
fn the_opponent_answers_with_the_highest_head_it_holds() {
    let (a, b) = keys();
    let mut x = au(&a, &b);
    let h20 = log_of(&b, 20, 0).sign_authenticator(R, &b);
    x.supply_anchor(&h20);
    feed(&mut x, PipeMsg::AnchorReq);
    match drain(&mut x).pop() {
        Some(PipeMsg::Anchor(Some(got))) => assert_eq!(got.seq, 20),
        o => panic!("unexpected {o:?}"),
    }
}

#[test]
fn rebase_is_durable_and_survives_another_restart() {
    use crate::audit::journal::FileTrustStore;
    let (a, b) = keys();
    let real = log_of(&a, 30, 0);
    let anchor = real.sign_authenticator(R, &a);
    let dir = std::env::temp_dir().join(format!("gv-anchor-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let base = dir.join("p");
    {
        let (store, loaded) = FileTrustStore::open(&base, M, a.id()).unwrap();
        let mut x = au(&a, &b);
        x.restore(loaded.log.ok(), &loaded.heads, &[]);
        x.attach_store(Box::new(store), 0, 0);
        x.require_anchor_check();
        feed(&mut x, PipeMsg::Anchor(Some(anchor.clone())));
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
fn a_witness_head_defeats_an_opponent_withholding_a_newer_head() {
    let (a, b) = keys();
    let w = SigningKey::from_seed([4; 32]);
    let real = log_of(&a, 30, 0);
    let held_by_witness = real.sign_authenticator(R, &a);
    let mut x = au(&a, &b);
    x.admit_witness(w.id());
    x.restore(Some(log_of(&a, 5, 0)), &[], &[]);
    x.require_anchor_check();
    feed(&mut x, PipeMsg::Anchor(None)); // the opponent claims it holds nothing
    assert!(
        x.anchor_check_pending(),
        "with witnesses pinned, the opponent alone cannot end the check"
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
    let (a, b) = keys();
    let mut x = au(&a, &b);
    x.admit_witness(SigningKey::from_seed([4; 32]).id());
    x.restore(Some(log_of(&a, 5, 0)), &[], &[]);
    x.require_anchor_check();
    feed(&mut x, PipeMsg::Anchor(None));
    x.tick(super::auditor::ANCHOR_WITNESS_WAIT - 1);
    assert!(x.anchor_check_pending());
    x.tick(super::auditor::ANCHOR_WITNESS_WAIT);
    assert!(!x.anchor_check_pending());
    assert!(x.recovery().may_sign());
}

#[test]
fn a_witness_alone_never_ends_the_check_and_unpinned_witnesses_are_ignored() {
    let (a, b) = keys();
    let real = log_of(&a, 30, 0);
    let head = real.sign_authenticator(R, &a);
    let mut x = au(&a, &b);
    x.restore(None, &[], &[]);
    x.require_anchor_check();
    x.on_witness_anchor(&head); // no witness pinned: ignored
    assert_eq!(x.log().len(), 0);
    x.admit_witness(SigningKey::from_seed([4; 32]).id());
    x.on_witness_anchor(&head);
    assert!(
        x.anchor_check_pending(),
        "the opponent's answer is mandatory"
    );
    feed(&mut x, PipeMsg::Anchor(None));
    assert!(!x.anchor_check_pending());
    assert_eq!(x.log().head(), real.head());
}
