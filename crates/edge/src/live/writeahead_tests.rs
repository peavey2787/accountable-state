//! Strict write-ahead durability: nothing signed leaves the process before it is durable, a
//! failing store fails closed, and after a kill at EVERY persistence-to-send boundary a
//! restarted participant never contradicts a head it already sent (`NoSelfEquivocation`).
use super::auditor::{AuditEvent, Auditor};
use super::msg::PipeMsg;
use super::pipeline::{PipeEvent, Pipeline, PipelineConfig};
use crate::arena::ArenaRules;
use crate::audit::failpoint::{self, Action};
use crate::audit::journal::{FileTrustStore, TrustStore};
use crate::audit::{AuditLog, Authenticator};
use crate::MatchReplica;
use gv_core::PlayerId;
use gv_sig::SigningKey;
use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const M: [u8; 32] = [7; 32];
const R: [u8; 32] = [9; 32];

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
fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("gv-wal-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}
fn copy_dir(from: &Path, to: &Path) {
    let _ = fs::remove_dir_all(to);
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap().flatten() {
        let _ = fs::copy(e.path(), to.join(e.file_name()));
    }
}

// ---------------------------------------------------------------------------------------------
// Real pipeline: the egress gate itself.

struct Duo {
    pipes: [Pipeline<ArenaRules>; 2],
    wire: [VecDeque<Vec<u8>>; 2],
    sent0: Vec<PipeMsg>,
    events0: Vec<PipeEvent>,
    dir: PathBuf,
    now: u64,
}

impl Duo {
    fn new(name: &str) -> Self {
        let dir = scratch(name);
        let roster = roster();
        let rules = ArenaRules::new(roster);
        let mk = |i: usize| {
            Pipeline::new(
                keys()[i].clone(),
                roster,
                M,
                rules.clone(),
                MatchReplica::new(M, roster, rules.clone()).unwrap(),
                PipelineConfig::default(),
            )
            .unwrap()
        };
        let mut pipes = [mk(0), mk(1)];
        let (mut store, loaded) = FileTrustStore::open(dir.join("p0"), M, keys()[0].id()).unwrap();
        store.set_compact_at(40_000);
        assert!(loaded.heads.is_empty());
        pipes[0].auditor_mut().attach_store(Box::new(store), 0, 0);
        pipes[1].auditor_mut().use_ephemeral_store_for_tests();
        Self {
            pipes,
            wire: [VecDeque::new(), VecDeque::new()],
            sent0: Vec::new(),
            events0: Vec::new(),
            dir,
            now: 0,
        }
    }
    fn run(&mut self, ticks: u64) {
        for _ in 0..ticks {
            self.now += 1;
            let now = self.now;
            for i in 0..2 {
                let own = move |from: u64, to: u64| -> Option<Vec<u16>> {
                    (to <= now).then(|| {
                        (from..to)
                            .map(|k| if k % 30 < 4 { crate::arena::UP } else { 0u16 })
                            .collect()
                    })
                };
                self.pipes[i].tick(now, &own);
                self.flush(i);
                while let Some(bytes) = self.wire[i].pop_front() {
                    let msg = PipeMsg::decode(&bytes).unwrap();
                    self.pipes[i].on_message(msg, now, &own);
                    self.flush(i);
                }
            }
        }
    }
    fn flush(&mut self, i: usize) {
        while let Some(m) = self.pipes[i].poll_outbox() {
            if i == 0 {
                // The write-ahead property, checked at the instant of egress.
                self.assert_durable(&m);
                self.sent0.push(m.clone());
            }
            self.wire[1 - i].push_back(m.encode().unwrap());
        }
        while let Some(e) = self.pipes[i].poll_event() {
            if i == 0 {
                self.events0.push(e);
            }
        }
    }
    /// What a crash right now would leave behind must already cover `m`.
    fn assert_durable(&self, m: &PipeMsg) {
        let snap = self.dir.join("snap");
        copy_dir(&self.dir, &snap);
        let (_, loaded) = FileTrustStore::open(snap.join("p0"), M, keys()[0].id()).unwrap();
        let log = loaded.log.ok().expect("durable log present at egress");
        let own = &self.pipes[0].auditor();
        assert!(
            log.len() >= own.log().len(),
            "journal covers {} of {} entries when a message left",
            log.len(),
            own.log().len()
        );
        assert_eq!(log.head(), own.log().head());
        if let PipeMsg::Auth(a) = m {
            assert!(
                loaded.heads.iter().any(|h| h == a),
                "authenticator seq {} left the process before it was durable",
                a.seq
            );
        }
    }
}

#[test]
fn nothing_signed_leaves_before_it_is_durable() {
    let mut d = Duo::new("gate");
    d.run(400);
    let auths = d
        .sent0
        .iter()
        .filter(|m| matches!(m, PipeMsg::Auth(_)))
        .count();
    assert!(auths >= 10, "expected steady authenticators, saw {auths}");
    assert!(d.pipes[0].auditor().commits() > 0);
    assert!(!d.pipes[0].auditor().persistence_failed());
}

#[test]
fn a_failing_store_fails_closed_and_recovers_without_loss() {
    for point in [
        "commit.before_write",
        "commit.torn_write",
        "commit.before_sync",
        "commit.after_sync",
    ] {
        let mut d = Duo::new(&format!("fail-{point}"));
        d.run(100);
        let before = d.sent0.len();
        failpoint::arm(point, 1, Action::Error);
        d.run(60);
        // Under failure nothing new may leave unless it is durable (checked in flush); the
        // failure is reported and signing is suspended.
        let failed_reported = d
            .events0
            .iter()
            .any(|e| matches!(e, PipeEvent::Audit(AuditEvent::PersistenceFailed(_))));
        failpoint::disarm();
        assert!(failed_reported, "{point}: failure must be reported");
        d.run(300);
        assert!(
            !d.pipes[0].auditor().persistence_failed(),
            "{point}: store recovers when the fault clears"
        );
        assert!(d.sent0.len() > before, "{point}: traffic resumes");
        // Heads sent over the whole run form one consistent chain.
        let mut seen: Vec<Authenticator> = Vec::new();
        for m in &d.sent0 {
            if let PipeMsg::Auth(a) = m {
                for b in &seen {
                    if b.seq == a.seq {
                        assert_eq!(b.head, a.head, "{point}: two heads at seq {}", a.seq);
                    }
                }
                seen.push(a.clone());
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Real process kills at every persistence-to-send boundary.

/// Child body: a participant that appends log entries, signs a head per epoch and "sends" it by
/// durably appending to a wire file (standing in for what the opponent remembers). Runs only
/// when spawned by the parent test below.
#[test]
fn crash_child() {
    let Ok(dir) = std::env::var("GV_WAL_CHILD_DIR") else {
        return;
    };
    let dir = PathBuf::from(dir);
    let epochs: u64 = std::env::var("GV_WAL_EPOCHS").unwrap().parse().unwrap();
    let unsafe_order = std::env::var("GV_WAL_UNSAFE_ORDER").is_ok();
    let nonce: u8 = std::env::var("GV_WAL_NONCE").unwrap().parse().unwrap();
    let me = keys()[0].clone();
    let other = keys()[1].clone();
    let mut au = Auditor::new(me.clone(), [me.id(), other.id()], M, R).unwrap();
    let (mut store, loaded) = FileTrustStore::open(dir.join("node"), M, me.id()).unwrap();
    store.set_compact_at(6_000);
    let top = loaded.heads.iter().map(|h| h.seq).max().unwrap_or(0);
    let report = au.restore(loaded.log.ok(), &loaded.heads, &[]);
    // Nothing in the journal anchors the log: ask "the opponent" (the wire file) whether it
    // holds any head of mine. If it holds none, nothing was ever released and resuming is safe.
    if matches!(
        report.recovery,
        crate::audit::trust::Recovery::Unresolved(crate::audit::trust::Unresolved::NoAnchor)
    ) {
        let held = sent_heads(&dir);
        if held.is_empty() {
            assert!(au.confirm_no_prior_heads());
        } else {
            for a in &held {
                au.supply_anchor(a);
            }
        }
    }
    if !au.recovery().may_sign() {
        eprintln!("RECOVERY-NOT-TRUSTED {:?}", au.recovery());
        std::process::exit(3);
    }
    let len = au.log().len();
    au.attach_store(Box::new(store), len, top);
    let mut wire = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("wire"))
        .unwrap();
    let mut now = len * 20;
    for i in 0..epochs {
        now += 20;
        au.test_append(1, vec![nonce, (i % 251) as u8, (len % 251) as u8]);
        au.test_append(2, vec![nonce, i as u8]);
        au.on_epoch(now);
        while let Some(m) = au.poll_msg() {
            let PipeMsg::Auth(a) = m else { continue };
            if !unsafe_order && !au.make_durable() {
                std::process::exit(4); // fail closed
            }
            failpoint::hit("send.before_wire").ok();
            wire.write_all(&a.encode()).unwrap();
            wire.sync_data().unwrap();
            failpoint::hit("send.after_wire").ok();
            if unsafe_order {
                let _ = au.make_durable();
            }
        }
    }
}

fn spawn_child(dir: &Path, epochs: u64, nonce: u8, fp: Option<&str>, unsafe_order: bool) -> bool {
    let mut c = std::process::Command::new(std::env::current_exe().unwrap());
    c.args([
        "--exact",
        "live::writeahead_tests::crash_child",
        "--nocapture",
        "--test-threads=1",
    ])
    .env("GV_WAL_CHILD_DIR", dir)
    .env("GV_WAL_EPOCHS", epochs.to_string())
    .env("GV_WAL_NONCE", nonce.to_string())
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null());
    if let Some(fp) = fp {
        c.env("GV_FAILPOINT", fp);
    }
    if unsafe_order {
        c.env("GV_WAL_UNSAFE_ORDER", "1");
    }
    c.status().unwrap().success()
}

fn sent_heads(dir: &Path) -> Vec<Authenticator> {
    let mut b = Vec::new();
    if let Ok(mut f) = fs::File::open(dir.join("wire")) {
        f.read_to_end(&mut b).unwrap();
    }
    b.chunks(Authenticator::WIRE_SIZE)
        .filter(|c| c.len() == Authenticator::WIRE_SIZE)
        .map(|c| Authenticator::decode(c).unwrap())
        .collect()
}

/// `NoSelfEquivocation`: every head ever sent lies on the final log's chain.
fn self_equivocations(dir: &Path) -> usize {
    let (_, loaded) = FileTrustStore::open(dir.join("node"), M, keys()[0].id()).unwrap();
    let log: Option<AuditLog> = loaded.log.ok();
    let sent = sent_heads(dir);
    let mut bad = 0;
    for a in &sent {
        match log.as_ref().and_then(|l| l.head_at(a.seq)) {
            Some(h) if h == a.head => {}
            // Pruned or longer-than-log heads cannot be compared; a head the final log lacks
            // altogether (rollback) or contradicts is a violation.
            None if log.as_ref().is_some_and(|l| a.seq < l.base_seq()) => {}
            _ => bad += 1,
        }
    }
    for (i, a) in sent.iter().enumerate() {
        for b in &sent[i + 1..] {
            if a.seq == b.seq && a.head != b.head {
                bad += 1;
            }
        }
    }
    bad
}

const POINTS: [&str; 8] = [
    "commit.before_write",
    "commit.torn_write",
    "commit.before_sync",
    "commit.after_sync",
    "send.before_wire",
    "send.after_wire",
    "compact.after_snapshot",
    "compact.before_rename",
];

#[test]
fn killing_the_process_at_every_boundary_never_causes_self_equivocation() {
    let mut matrix = 0;
    for point in POINTS {
        for nth in [1u64, 2, 5, 17, 40] {
            let dir = scratch(&format!("kill-{point}-{nth}"));
            let fp = format!("{point}:{nth}:abort");
            let first = spawn_child(&dir, 120, 1, Some(&fp), false);
            // Restart after the kill, repeatedly, with a different nonce: new entries differ,
            // so a lost or rolled-back state would show up as a conflicting head.
            let mut ok = true;
            for round in 0..3u8 {
                ok &= spawn_child(&dir, 40, 10 + round, None, false);
            }
            assert!(
                ok,
                "{point}:{nth}: restarted participant must resume signing"
            );
            assert_eq!(
                self_equivocations(&dir),
                0,
                "{point}:{nth}: a restarted participant contradicted a head it already sent \
                 (first run {})",
                if first { "finished" } else { "was killed" }
            );
            matrix += 1;
        }
    }
    assert_eq!(matrix, 40);
}

#[test]
fn random_sigkill_during_a_run_never_causes_self_equivocation() {
    for round in 0..8u64 {
        let dir = scratch(&format!("sigkill-{round}"));
        for gen in 0..4u8 {
            let mut c = std::process::Command::new(std::env::current_exe().unwrap());
            c.args([
                "--exact",
                "live::writeahead_tests::crash_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("GV_WAL_CHILD_DIR", &dir)
            .env("GV_WAL_EPOCHS", "400")
            .env(
                "GV_WAL_NONCE",
                (round as u8).wrapping_mul(7).wrapping_add(gen).to_string(),
            )
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
            let mut child = c.spawn().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(
                60 + 35 * round + 20 * u64::from(gen),
            ));
            let _ = child.kill();
            let _ = child.wait();
        }
        assert!(
            spawn_child(&dir, 20, 99, None, false),
            "round {round}: resumes"
        );
        assert_eq!(self_equivocations(&dir), 0, "round {round}");
    }
}

/// Control: with the OLD order (send first, persist after) the same kill matrix DOES produce a
/// self-equivocation, so the checks above are able to fail.
#[test]
fn control_sending_before_persisting_is_detected_as_self_equivocation() {
    let mut detected = 0;
    for nth in [1u64, 2, 3, 5, 9] {
        let dir = scratch(&format!("control-{nth}"));
        let fp = format!("send.after_wire:{nth}:abort");
        spawn_child(&dir, 120, 1, Some(&fp), true);
        spawn_child(&dir, 40, 50, None, false);
        if self_equivocations(&dir) > 0 {
            detected += 1;
        }
    }
    assert!(detected > 0, "the unsafe order must be caught");
}

/// Hand-over: a store implementation is just a trait object, so a host can supply its own.
#[allow(dead_code)]
fn _assert_object_safe(_: &dyn TrustStore) {}

#[test]
fn without_a_durable_store_nothing_signed_is_released() {
    let (me, other) = (keys()[0].clone(), keys()[1].clone());
    let mut au = Auditor::new(me.clone(), [me.id(), other.id()], M, R).unwrap();
    au.test_append(1, vec![1]);
    assert!(!au.make_durable(), "a missing store must fail closed");
    assert!(au.persistence_failed());
    assert!(matches!(
        au.poll_event(),
        Some(AuditEvent::PersistenceFailed(_))
    ));
    assert!(!au.make_durable());
    assert!(au.poll_event().is_none(), "the failure is reported once");
}
