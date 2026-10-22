//! Trusted crash recovery: anchored restore, rollback/fork refusal, and real-filesystem
//! corruption, truncation and interrupted-write injection.
use super::auditor::{AuditEvent, Auditor};
use super::msg::{Outgoing, PipeMsg};
use crate::audit::durable::{Durable, Loaded};
use crate::audit::trust::{
    check_log, read_state, write_state, Pins, Recovery, Refusal, StateRead, Unresolved,
};
use crate::audit::{AuditLog, Authenticator, ChallengeKind, Response, Status};
use gv_core::Roster;
use gv_sig::SigningKey;
use std::fs;
use std::path::PathBuf;

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
fn auditor(me: &SigningKey, other: &SigningKey) -> Auditor {
    let roster = Roster::players(&[me.id(), other.id()]).unwrap();
    let mut a = Auditor::new(me.clone(), &roster, M, R).unwrap();
    a.use_ephemeral_store_for_tests();
    a
}
fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("gv-recovery-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn rollback_to_a_shorter_self_consistent_log_is_refused() {
    let (a, _) = keys();
    let full = log_of(&a, 30, 0);
    let anchor = full.sign_authenticator(R, &a);
    let older = log_of(&a, 12, 0); // perfectly chained prefix, attacker supplied
    assert_eq!(
        check_log(a.id(), M, Some(&older), std::slice::from_ref(&anchor)),
        Recovery::Refused(Refusal::Rollback {
            pinned_seq: 30,
            log_len: 12
        })
    );
    assert!(matches!(
        check_log(a.id(), M, Some(&full), &[anchor]),
        Recovery::Resumed {
            len: 30,
            anchored_at: 30
        }
    ));
}

#[test]
fn forked_log_of_sufficient_length_is_refused() {
    let (a, _) = keys();
    let real = log_of(&a, 20, 0);
    let anchor = real.sign_authenticator(R, &a);
    let fork = log_of(&a, 25, 1); // longer, self-consistent, different history
    assert_eq!(
        check_log(a.id(), M, Some(&fork), &[anchor]),
        Recovery::Refused(Refusal::Fork { seq: 20 })
    );
}

#[test]
fn no_anchor_is_unresolved_and_suspends_signing_until_an_anchor_arrives() {
    let (a, b) = keys();
    let log = log_of(&a, 15, 0);
    let mut au = auditor(&a, &b);
    let report = au.restore(Some(log.clone()), &[], &[]);
    assert_eq!(report.recovery, Recovery::Unresolved(Unresolved::NoAnchor));
    assert!(matches!(
        au.poll_event(),
        Some(AuditEvent::RecoveryNotTrusted(_))
    ));
    // Unadopted: the held log is not live, and no head is signed.
    assert_eq!(au.log().len(), 0);
    au.on_epoch(1);
    assert!(au.poll_msg().is_none(), "must not sign while unresolved");
    // A peer hands back a head I signed earlier: recovery completes.
    let held = log.sign_authenticator(R, &a);
    au.supply_anchor(&held);
    assert!(matches!(au.recovery(), Recovery::Resumed { .. }));
    assert_eq!(au.log().head(), log.head());
    au.on_epoch(2);
    assert!(matches!(
        au.poll_msg(),
        Some(Outgoing {
            msg: PipeMsg::Auth(_),
            ..
        })
    ));
    // A contradicting anchor from a peer after the fact does not silently win.
    let mut au2 = auditor(&a, &b);
    au2.restore(Some(log_of(&a, 15, 1)), &[], &[]);
    au2.supply_anchor(&held);
    assert!(matches!(
        au2.recovery(),
        Recovery::Refused(Refusal::Fork { .. })
    ));
}

#[test]
fn lost_log_with_anchors_is_not_proof_of_cheating_and_does_not_sign() {
    let (a, b) = keys();
    let anchor = log_of(&a, 9, 0).sign_authenticator(R, &a);
    let mut au = auditor(&a, &b);
    let report = au.restore(None, &[anchor], &[]);
    assert_eq!(report.recovery, Recovery::Unresolved(Unresolved::LogLost));
    au.on_epoch(1);
    assert!(au.poll_msg().is_none());
    assert_eq!(
        au.ledger().proven_total(),
        0,
        "lost evidence is not a verdict"
    );
    // Truly fresh start (nothing ever signed) is fine.
    let mut fresh = auditor(&a, &b);
    assert_eq!(fresh.restore(None, &[], &[]).recovery, Recovery::Fresh);
    fresh.on_epoch(1);
    assert!(matches!(
        fresh.poll_msg(),
        Some(Outgoing {
            msg: PipeMsg::Auth(_),
            ..
        })
    ));
}

#[test]
fn anchor_older_than_a_pruned_log_base_is_unresolved() {
    let (a, _) = keys();
    let mut log = log_of(&a, 40, 0);
    let early = log_of(&a, 10, 0).sign_authenticator(R, &a);
    assert!(log.prune_to_keep(5) > 0);
    assert_eq!(
        check_log(a.id(), M, Some(&log), &[early]),
        Recovery::Unresolved(Unresolved::AnchorPruned)
    );
}

#[test]
fn forged_or_foreign_anchors_are_ignored_not_trusted() {
    let (a, b) = keys();
    // An anchor signed by the wrong key claiming my seq cannot make a rollback look fine,
    // and a tampered one fails verification and is dropped.
    let log = log_of(&a, 10, 0);
    let mut bad: Authenticator = log.sign_authenticator(R, &a);
    bad.head[0] ^= 1;
    assert_eq!(
        check_log(a.id(), M, Some(&log), &[bad]),
        Recovery::Unresolved(Unresolved::NoAnchor)
    );
    let theirs = log_of(&b, 50, 0).sign_authenticator(R, &b);
    assert_eq!(
        check_log(a.id(), M, Some(&log), &[theirs]),
        Recovery::Unresolved(Unresolved::NoAnchor)
    );
}

#[test]
fn truncation_at_every_length_and_bit_rot_are_never_trusted() {
    let d = scratch("trunc");
    let p = d.join("state");
    let payload: Vec<u8> = (0..200u8).collect();
    write_state(&p, &payload).unwrap();
    let whole = fs::read(&p).unwrap();
    assert_eq!(read_state(&p), StateRead::Ok(payload.clone()));
    for len in 0..whole.len() {
        fs::write(&p, &whole[..len]).unwrap();
        assert_ne!(read_state(&p), StateRead::Ok(payload.clone()), "len {len}");
    }
    for i in 0..whole.len() {
        let mut t = whole.clone();
        t[i] ^= 0x80;
        fs::write(&p, &t).unwrap();
        assert_eq!(read_state(&p), StateRead::Corrupt, "flip {i}");
    }
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn interrupted_write_leaves_the_previous_state_intact() {
    let (a, _) = keys();
    let d = scratch("interrupt");
    let store = Durable::new(d.join("m"));
    let good = log_of(&a, 10, 0);
    store.save_log(&good).unwrap();
    // A crash after creating the temp file but before the rename leaves garbage next to it.
    let mut pending = store.log_path().into_os_string();
    pending.push(".pending");
    fs::write(&pending, b"half-written").unwrap();
    assert_eq!(store.load_log().ok().unwrap().head(), good.head());
    // Next successful save replaces everything atomically.
    let longer = log_of(&a, 20, 0);
    store.save_log(&longer).unwrap();
    assert_eq!(store.load_log().ok().unwrap().len(), 20);
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn corrupt_snapshot_or_pins_never_fabricate_trust() {
    let (a, b) = keys();
    let d = scratch("corrupt");
    let store = Durable::new(d.join("m"));
    let log = log_of(&a, 10, 0);
    let mut pins = Pins::new();
    pins.add(&log.sign_authenticator(R, &a)).unwrap();
    store.save_log(&log).unwrap();
    store.save_pins(&pins).unwrap();
    // Corrupt pins: log present but unanchored => unresolved, not adopted.
    let mut raw = fs::read(store.pins_path()).unwrap();
    let n = raw.len() / 2;
    raw[n] ^= 1;
    fs::write(store.pins_path(), raw).unwrap();
    assert!(matches!(store.load_pins(), Loaded::Corrupt));
    let mut au = auditor(&a, &b);
    let rep = au.restore(
        store.load_log().ok(),
        store.load_pins().ok().unwrap_or_default().items(),
        &[],
    );
    assert_eq!(rep.recovery, Recovery::Unresolved(Unresolved::NoAnchor));
    // Corrupt snapshot with intact pins => LogLost.
    store.save_pins(&pins).unwrap();
    fs::write(store.log_path(), b"garbage").unwrap();
    assert!(matches!(store.load_log(), Loaded::Corrupt));
    let mut au = auditor(&a, &b);
    let rep = au.restore(
        store.load_log().ok(),
        store.load_pins().ok().unwrap_or_default().items(),
        &[],
    );
    assert_eq!(rep.recovery, Recovery::Unresolved(Unresolved::LogLost));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn attacker_rewrites_snapshot_with_valid_framing_and_substituted_entry() {
    // The attacker can recompute the file checksum and the hash chain. Only the signed
    // anchor stops the substitution.
    let (a, b) = keys();
    let d = scratch("substitute");
    let store = Durable::new(d.join("m"));
    let real = log_of(&a, 25, 0);
    let mut pins = Pins::new();
    pins.add(&real.sign_authenticator(R, &a)).unwrap();
    store.save_pins(&pins).unwrap();
    let forged = log_of(&a, 30, 7);
    store.save_log(&forged).unwrap(); // valid framing, valid chain
    let mut au = auditor(&a, &b);
    let rep = au.restore(
        store.load_log().ok(),
        store.load_pins().ok().unwrap().items(),
        &[],
    );
    assert_eq!(rep.recovery, Recovery::Refused(Refusal::Fork { seq: 25 }));
    assert_eq!(au.log().len(), 0);
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn pins_survive_restart_and_pinned_opponent_heads_detect_a_later_fork() {
    let (a, b) = keys();
    let theirs = log_of(&b, 12, 0);
    let their_auth = theirs.sign_authenticator(R, &b);
    let mut au = auditor(&a, &b);
    au.restore(None, std::slice::from_ref(&their_auth), &[]);
    // After restart the opponent presents a different head at the pinned position.
    let forked = log_of(&b, 12, 3).sign_authenticator(R, &b);
    au.on_msg(b.id(), PipeMsg::Auth(forked), 5, &super::auditor::NoAnswers);
    assert_eq!(
        au.ledger().proven_total(),
        1,
        "contradiction with a pinned head is proof"
    );
    // Re-presenting the pinned head itself proves nothing.
    let mut au = auditor(&a, &b);
    au.restore(None, std::slice::from_ref(&their_auth), &[]);
    au.on_msg(
        b.id(),
        PipeMsg::Auth(their_auth),
        5,
        &super::auditor::NoAnswers,
    );
    assert_eq!(au.ledger().proven_total(), 0);
}

#[test]
fn open_challenge_survives_restart_and_timeout_is_never_proof() {
    let (a, b) = keys();
    let d = scratch("challenge");
    let store = Durable::new(d.join("m"));
    let mut au = auditor(&a, &b);
    au.restore(None, &[], &[]);
    let id = au
        .challenge(b.id(), ChallengeKind::Ack { seq: 0 }, 100)
        .unwrap();
    store.save_challenges(&au.open_challenges()).unwrap();
    // Restart.
    let mut au2 = auditor(&a, &b);
    au2.restore(None, &[], &[]);
    let cs = store.load_challenges().ok().unwrap();
    assert_eq!(au2.resume_challenges(&cs, 5000), 1);
    assert!(matches!(
        au2.poll_msg(),
        Some(Outgoing {
            msg: PipeMsg::Challenge(_),
            ..
        })
    ));
    // Silence only ever suspects, then marks unavailable; never fraud.
    for t in (5000..9000).step_by(10) {
        au2.tick(t);
    }
    let mut proven = 0;
    while let Some(ev) = au2.poll_event() {
        if let AuditEvent::Challenge { status, .. } = ev {
            assert!(!status.is_proof());
            if status == Status::Unavailable || status == Status::SuspectedNonCooperation {
                proven += 1;
            }
        }
    }
    assert!(proven > 0);
    assert_eq!(au2.ledger().proven_total(), 0);
    // A valid late answer still clears it.
    let mut au3 = auditor(&a, &b);
    au3.restore(None, &[], &[]);
    au3.resume_challenges(&cs, 0);
    let ch = cs.iter().find(|c| c.id() == id).unwrap();
    let ack = log_of(&b, 3, 0).sign_authenticator(R, &b).encode();
    let resp = Response::sign(ch, ack, &b);
    au3.on_msg(
        b.id(),
        PipeMsg::Response(resp),
        1,
        &super::auditor::NoAnswers,
    );
    assert!(matches!(
        au3.poll_event(),
        Some(AuditEvent::Challenge {
            status: Status::Cleared,
            ..
        })
    ));
    // Forged challenge file: tampered content is rejected wholesale.
    let mut raw = fs::read(store.challenges_path()).unwrap();
    let n = raw.len() - 40;
    raw[n] ^= 1;
    fs::write(store.challenges_path(), raw).unwrap();
    assert!(matches!(store.load_challenges(), Loaded::Corrupt));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn pruning_never_drops_entries_an_open_challenge_depends_on() {
    let (a, _) = keys();
    let mut log = log_of(&a, 100, 0);
    log.pin(30);
    log.prune_to_keep(10);
    assert!(log.base_seq() <= 29, "pin at 30 keeps entries from 30 on");
    assert!(log.segment(30, 60).is_ok());
    log.unpin(30);
    assert!(log.prune_to_keep(10) > 0);
    assert!(log.segment(30, 60).is_err());
}
