//! Witnessed mode end to end on one auditor: recovery by quorum read (never by timeout), the
//! release gate, and certified-only conviction.
use super::auditor::{AuditEvent, Auditor};
use super::msg::PipeMsg;
use crate::audit::{AuditLog, Authenticator, Evidence};
use crate::quorum::{Acceptor, Cell, QuorumMsg, WitnessSet};
use gv_core::Roster;
use gv_sig::SigningKey;

const M: [u8; 32] = [7; 32];
const R: [u8; 32] = [9; 32];

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed([seed; 32])
}

struct Witnesses {
    acceptors: Vec<Acceptor>,
    cells: Vec<Cell>,
    set: WitnessSet,
}

impl Witnesses {
    fn new(n: u8) -> Self {
        let keys: Vec<_> = (0..n).map(|i| key(100 + i)).collect();
        let ids: Vec<_> = keys.iter().map(SigningKey::id).collect();
        Self {
            acceptors: keys.into_iter().map(Acceptor::new).collect(),
            cells: vec![Cell::default(); n as usize],
            set: WitnessSet::new(&ids).unwrap(),
        }
    }

    /// Deliver everything the auditor queued to the witnesses in `up`; feed the replies back.
    fn pump(&mut self, a: &mut Auditor, up: &[usize]) {
        while let Some((_, msg)) = a.poll_quorum() {
            for &i in up {
                let mut persist = |_: &_, _: &_, _: &[u8]| true;
                let replies = match &msg {
                    QuorumMsg::HeldReq { seq, .. } => self.acceptors[i].held(&self.cells[i], *seq),
                    _ => self.acceptors[i]
                        .handle(&mut self.cells[i], &msg, &mut persist)
                        .into_iter()
                        .collect(),
                };
                for r in replies {
                    a.on_quorum(self.acceptors[i].id(), r);
                }
            }
        }
    }
}

fn auditor(set: &WitnessSet) -> Auditor {
    let (me, b, c) = (key(1), key(2), key(3));
    let ids = [me.id(), b.id(), c.id()];
    let mut a = Auditor::new(me, &Roster::players(&ids).unwrap(), M, R).unwrap();
    a.use_ephemeral_store_for_tests();
    assert!(a.enable_witness_quorum(set.clone()));
    a
}

fn grow(log: &mut AuditLog, n: u8) {
    for i in 0..n {
        log.append(1, vec![i]).unwrap();
    }
}

fn released(a: &mut Auditor) -> Vec<Authenticator> {
    std::iter::from_fn(|| a.poll_msg())
        .filter_map(|o| match o.msg {
            PipeMsg::Auth(x) => Some(x),
            _ => None,
        })
        .collect()
}

fn events(a: &mut Auditor) -> Vec<AuditEvent> {
    std::iter::from_fn(|| a.poll_event()).collect()
}

#[test]
fn fresh_start_recovers_by_quorum_then_commits_and_releases() {
    let mut w = Witnesses::new(4);
    let mut a = auditor(&w.set);
    a.restore(None, &[], &[]);
    a.require_anchor_check();
    assert!(a.recovery_blocked());
    w.pump(&mut a, &[0, 1, 2]);
    assert!(!a.recovery_blocked());
    assert!(events(&mut a)
        .iter()
        .any(|e| matches!(e, AuditEvent::QuorumRecovered { seq: None })));
    a.test_append(1, vec![1]);
    a.on_epoch(10);
    w.pump(&mut a, &[0, 1, 2]);
    let out = released(&mut a);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].seq, 1);
}

#[test]
fn recovery_blocks_below_a_quorum_and_never_times_out() {
    let mut w = Witnesses::new(4);
    let mut a = auditor(&w.set);
    a.restore(None, &[], &[]);
    a.require_anchor_check();
    w.pump(&mut a, &[0, 1]);
    for t in (0..100_000).step_by(500) {
        a.tick(t);
        w.pump(&mut a, &[0, 1]);
    }
    assert!(a.recovery_blocked());
    assert!(a.anchor_check_pending());
    assert!(released(&mut a).is_empty());
    a.tick(200_000); // retransmission reaches the witness that was down
    w.pump(&mut a, &[2]);
    assert!(!a.recovery_blocked());
}

#[test]
fn a_rolled_back_log_is_rebased_on_the_committed_head_without_conviction() {
    let mut w = Witnesses::new(4);
    let mut first = auditor(&w.set);
    first.restore(None, &[], &[]);
    first.require_anchor_check();
    w.pump(&mut first, &[0, 1, 2, 3]);
    for _ in 0..20 {
        first.test_append(1, vec![5]);
    }
    first.on_epoch(10);
    w.pump(&mut first, &[0, 1, 2, 3]);
    let head = released(&mut first).pop().expect("released head");
    assert_eq!(head.seq, 20);

    // The process restarts with a stale (shorter) log.
    let mut again = auditor(&w.set);
    let mut stale = AuditLog::new(M, key(1).id());
    grow(&mut stale, 5);
    again.restore(None, &[], &[]);
    again.require_anchor_check();
    w.pump(&mut again, &[1, 2, 3]);
    assert!(!again.recovery_blocked());
    assert_eq!(again.log().len(), 20);
    assert_eq!(again.log().head(), head.head);
    assert!(again.recovery().may_sign());
    assert!(again.ledger().proven_total() == 0);
}

#[test]
fn equivocation_needs_certificates_before_it_convicts() {
    let mut w = Witnesses::new(4);
    let mut a = auditor(&w.set);
    a.restore(None, &[], &[]);
    a.require_anchor_check();
    w.pump(&mut a, &[0, 1, 2, 3]);
    let peer = key(2);
    let mut l1 = AuditLog::new(M, peer.id());
    let mut l2 = AuditLog::new(M, peer.id());
    l1.append(1, vec![1]).unwrap();
    l2.append(1, vec![2]).unwrap();
    let x = l1.sign_authenticator(R, &peer);
    let y = l2.sign_authenticator(R, &peer);
    a.on_msg(peer.id(), PipeMsg::Auth(x), 0, &super::NoAnswers);
    a.on_msg(peer.id(), PipeMsg::Auth(y), 0, &super::NoAnswers);
    assert!(
        a.ledger().proven_total() == 0,
        "two signed heads are not enough: the witnesses never committed them"
    );
    let plain = Evidence::ConflictingAuthenticators(
        l1.sign_authenticator(R, &peer),
        l2.sign_authenticator(R, &peer),
    );
    assert!(plain.verify_under(Some(&w.set)).is_err());
}
