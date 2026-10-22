use super::*;
use crate::audit::Authenticator;
use gv_core::MatchId;
use gv_sig::SigningKey;
use std::collections::BTreeMap;

const M: MatchId = [7; 32];
const RULES: [u8; 32] = [9; 32];

type Disk = BTreeMap<(MatchId, [u8; 32]), Vec<u8>>;

struct Cluster {
    keys: Vec<SigningKey>,
    acceptors: Vec<Acceptor>,
    cells: Vec<Cell>,
    disks: Vec<Disk>,
    set: WitnessSet,
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed([seed; 32])
}

impl Cluster {
    fn new(n: u8) -> Self {
        let keys: Vec<_> = (0..n).map(|i| key(100 + i)).collect();
        let set = WitnessSet::new(&keys.iter().map(|k| k.id()).collect::<Vec<_>>()).unwrap();
        Self {
            acceptors: keys.iter().map(|k| Acceptor::new(k.clone())).collect(),
            cells: vec![Cell::default(); n as usize],
            disks: vec![BTreeMap::new(); n as usize],
            keys,
            set,
        }
    }
    /// Deliver the registrar's pending output to the witnesses in `up` and feed back replies.
    fn pump(&mut self, reg: &mut Registrar, up: &[usize]) {
        while let Some((_, msg)) = reg.poll_out() {
            for &i in up {
                let disk = &mut self.disks[i];
                let mut persist = |m: &MatchId, o: &[u8; 32], b: &[u8]| {
                    disk.insert((*m, *o), b.to_vec());
                    true
                };
                let reply = self.acceptors[i].handle(&mut self.cells[i], &msg, &mut persist);
                match reply {
                    Some(QuorumMsg::Promise(p)) => reg.on_promise(p),
                    Some(QuorumMsg::Receipt(r)) => reg.on_receipt(r),
                    Some(QuorumMsg::Nack(n)) => reg.on_nack(n),
                    _ => {}
                }
            }
        }
    }
    fn restart(&mut self, i: usize) {
        let bytes = self.disks[i].values().next().cloned();
        self.cells[i] = bytes.map_or_else(Cell::default, |b| Cell::decode(&b).unwrap());
    }
}

fn ballot(counter: u64, nonce: u64) -> Ballot {
    Ballot { counter, nonce }
}

fn owner_registrar(c: &Cluster, b: Ballot) -> Registrar {
    Registrar::new(key(1), M, c.set.clone(), b)
}

fn auth(seq: u64, head: u8) -> Authenticator {
    Authenticator::sign(M, RULES, seq, [head; 32], &key(1))
}

fn drain(reg: &mut Registrar) -> Vec<Event> {
    std::iter::from_fn(|| reg.poll_event()).collect()
}

fn active(c: &mut Cluster, b: Ballot, up: &[usize]) -> Registrar {
    let mut r = owner_registrar(c, b);
    c.pump(&mut r, up);
    assert!(matches!(drain(&mut r).as_slice(), [Event::Recovered(_)]));
    assert!(r.activate());
    r
}

#[test]
fn committed_head_is_certified_by_a_quorum() {
    let mut c = Cluster::new(4);
    let mut r = active(&mut c, ballot(1, 1), &[0, 1, 2, 3]);
    r.propose(auth(3, 1), 60).unwrap();
    c.pump(&mut r, &[0, 1, 2]);
    let events = drain(&mut r);
    let [Event::Certified(cert)] = events.as_slice() else {
        panic!("expected a certificate")
    };
    assert!(cert.verify(&c.set).is_ok());
    let mut thin = (**cert).clone();
    thin.receipts.truncate(2);
    assert_eq!(thin.verify(&c.set), Err(QuorumError::Insufficient));
}

#[test]
fn recovery_adopts_the_committed_head_after_a_crash() {
    let mut c = Cluster::new(4);
    let mut r = active(&mut c, ballot(1, 1), &[0, 1, 2, 3]);
    r.propose(auth(5, 2), 100).unwrap();
    c.pump(&mut r, &[0, 1, 2]);
    drop(r);
    for i in 0..4 {
        c.restart(i);
    }
    let mut again = owner_registrar(&c, ballot(2, 2));
    c.pump(&mut again, &[1, 2, 3]);
    let events = drain(&mut again);
    let [Event::Recovered(Some(claim))] = events.as_slice() else {
        panic!("expected adopted claim")
    };
    assert_eq!((claim.auth.seq, claim.through_tick), (5, 100));
}

#[test]
fn recovery_blocks_below_a_quorum_and_never_resumes_on_silence() {
    let mut c = Cluster::new(4);
    let mut r = owner_registrar(&c, ballot(1, 1));
    c.pump(&mut r, &[0, 1]);
    for _ in 0..1000 {
        r.retransmit();
        c.pump(&mut r, &[0, 1]);
    }
    assert_eq!(r.phase(), Phase::Recovering);
    assert!(drain(&mut r).is_empty());
    assert!(!r.activate());
    r.retransmit();
    c.pump(&mut r, &[2]);
    assert!(matches!(drain(&mut r).as_slice(), [Event::Recovered(None)]));
}

#[test]
fn old_incarnation_is_fenced_and_cannot_commit() {
    let mut c = Cluster::new(4);
    let mut old = active(&mut c, ballot(1, 1), &[0, 1, 2, 3]);
    let mut new = active(&mut c, ballot(2, 2), &[0, 1, 2, 3]);
    old.propose(auth(1, 3), 20).unwrap();
    c.pump(&mut old, &[0, 1, 2, 3]);
    assert_eq!(old.phase(), Phase::Fenced);
    assert!(matches!(drain(&mut old).as_slice(), [Event::Fenced(b)] if *b == ballot(2, 2)));
    assert!(new.propose(auth(1, 4), 20).is_some());
}

#[test]
fn one_lying_witness_cannot_fence_an_honest_owner() {
    let mut c = Cluster::new(4);
    let mut r = active(&mut c, ballot(1, 1), &[0, 1, 2, 3]);
    let liar = Nack::sign(M, key(1).id(), ballot(1, 1), ballot(9, 9), &c.keys[3]);
    r.on_nack(liar);
    assert_eq!(r.phase(), Phase::Active);
}

#[test]
fn a_byzantine_witness_cannot_hide_a_committed_head() {
    let mut c = Cluster::new(4);
    let mut r = active(&mut c, ballot(1, 1), &[0, 1, 2, 3]);
    r.propose(auth(8, 5), 160).unwrap();
    c.pump(&mut r, &[0, 1, 2]);
    drop(r);
    // Witness 0 lies (reports nothing); the quorum {0, 2, 3} still includes honest holder 2.
    c.cells[0] = Cell::default();
    let mut again = owner_registrar(&c, ballot(2, 2));
    c.pump(&mut again, &[0, 2, 3]);
    let events = drain(&mut again);
    let [Event::Recovered(Some(claim))] = events.as_slice() else {
        panic!("expected adopted claim")
    };
    assert_eq!(claim.auth.seq, 8);
}

#[test]
fn nack_makes_a_recovering_owner_retry_above() {
    let mut c = Cluster::new(4);
    let _other = active(&mut c, ballot(5, 9), &[0, 1, 2, 3]);
    let mut r = owner_registrar(&c, ballot(1, 1));
    c.pump(&mut r, &[0, 1, 2, 3]);
    assert_eq!(r.ballot().counter, 6);
    c.pump(&mut r, &[0, 1, 2, 3]);
    assert!(matches!(drain(&mut r).as_slice(), [Event::Recovered(None)]));
}

#[test]
fn equal_ballot_equivocation_gets_no_receipt() {
    let mut c = Cluster::new(4);
    let mut r = active(&mut c, ballot(1, 1), &[0, 1, 2, 3]);
    r.propose(auth(4, 1), 40).unwrap();
    c.pump(&mut r, &[0, 1, 2, 3]);
    drain(&mut r);
    let forged = Claim::sign(ballot(1, 1), auth(4, 2), 40, &key(1));
    let mut no_persist = |_: &MatchId, _: &[u8; 32], _: &[u8]| true;
    for i in 0..4 {
        let reply = c.acceptors[i].handle(
            &mut c.cells[i],
            &QuorumMsg::Store(forged.clone()),
            &mut no_persist,
        );
        assert!(reply.is_none());
    }
}

#[test]
fn a_witness_that_cannot_persist_answers_nothing() {
    let mut c = Cluster::new(4);
    let rec = Recover::sign(M, ballot(1, 1), &key(1));
    let mut full = |_: &MatchId, _: &[u8; 32], _: &[u8]| false;
    let reply = c.acceptors[0].handle(&mut c.cells[0], &QuorumMsg::Recover(rec), &mut full);
    assert!(reply.is_none());
    assert_eq!(c.cells[0], Cell::default());
}

#[test]
fn cell_and_messages_round_trip_and_reject_corruption() {
    let mut c = Cluster::new(4);
    let mut r = active(&mut c, ballot(1, 1), &[0, 1, 2, 3]);
    r.propose(auth(2, 6), 30).unwrap();
    c.pump(&mut r, &[0, 1, 2, 3]);
    let bytes = c.cells[0].encode();
    assert_eq!(Cell::decode(&bytes), Some(c.cells[0].clone()));
    assert_eq!(Cell::decode(&bytes[..bytes.len() - 1]), None);
    let msg = c.acceptors[0].held(&c.cells[0], 2).remove(0);
    assert_eq!(QuorumMsg::decode(&msg.encode()), Ok(msg.clone()));
    let mut bad = msg.encode();
    bad.truncate(bad.len() - 3);
    assert!(QuorumMsg::decode(&bad).is_err());
    assert!(c.acceptors[0].held(&c.cells[0], 3).is_empty());
}
