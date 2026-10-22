//! Witness propagation over an in-memory network with injected loss, duplication, reordering,
//! delay and partitions. Cryptography is the real ML-DSA path; only the wire is simulated.
use crate::audit::{AuditLog, Authenticator, ChallengeKind, Evidence, Status};
use crate::testkit::GridRules;
use crate::witness::{Event, Msg, Remote, WitnessNode};
use gv_core::{ParticipantId, Session};
use gv_sig::SigningKey;
use std::collections::{BTreeSet, VecDeque};

const M: [u8; 32] = [5; 32];

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

struct Sim {
    nodes: Vec<WitnessNode<GridRules>>,
    inflight: VecDeque<(u64, usize, usize, Vec<u8>)>, // deliver_at, from, to, bytes
    now: u64,
    rng: Rng,
    loss: u64,
    dup: u64,
    jitter: u64,
    cut: BTreeSet<usize>, // nodes partitioned from everyone
    events: Vec<Vec<Event>>,
}

struct Cast {
    keys: Vec<SigningKey>, // 0,1 players; 2.. witnesses
}
fn cast(witnesses: usize) -> Cast {
    Cast {
        keys: (0..2 + witnesses)
            .map(|i| SigningKey::from_seed([10 + i as u8; 32]))
            .collect(),
    }
}

impl Cast {
    fn session(&self) -> Session {
        Session::unanimous(M, &[self.keys[0].id(), self.keys[1].id()]).unwrap()
    }
}

fn sim(c: &Cast, loss: u64, dup: u64, jitter: u64) -> Sim {
    let wids: Vec<ParticipantId> = c.keys[2..].iter().map(SigningKey::id).collect();
    let rules = GridRules;
    let mut nodes: Vec<_> = c
        .keys
        .iter()
        .map(|k| WitnessNode::new(k.clone(), c.session(), &wids, rules))
        .collect();
    // Bipartite links: every witness to both players.
    for w in 2..c.keys.len() {
        for p in 0..2 {
            nodes[w].open_link(p as u32, Remote::Player(c.keys[p].id()), 0);
            nodes[p].open_link(w as u32, Remote::AnyWitness, 0);
        }
    }
    let n = nodes.len();
    Sim {
        nodes,
        inflight: VecDeque::new(),
        now: 0,
        rng: Rng(7),
        loss,
        dup,
        jitter,
        cut: BTreeSet::new(),
        events: vec![Vec::new(); n],
    }
}

impl Sim {
    fn step(&mut self) {
        self.now += 100;
        for i in 0..self.nodes.len() {
            self.nodes[i].tick(self.now);
            while let Some((to, bytes)) = self.nodes[i].poll_out() {
                let to = to as usize;
                if self.cut.contains(&i) || self.cut.contains(&to) || self.rng.chance(self.loss) {
                    continue;
                }
                let copies = if self.rng.chance(self.dup) { 2 } else { 1 };
                for _ in 0..copies {
                    let at = self.now + 50 + self.rng.next() % (self.jitter + 1);
                    self.inflight.push_back((at, i, to, bytes.clone()));
                }
            }
        }
        let now = self.now;
        let mut due = Vec::new();
        let mut keep = VecDeque::new();
        while let Some(m) = self.inflight.pop_front() {
            if m.0 <= now {
                due.push(m)
            } else {
                keep.push_back(m)
            }
        }
        self.inflight = keep;
        due.sort_by_key(|m| m.0 ^ (self.rng.next() & 0xff)); // reorder within a step
        for (_, from, to, bytes) in due {
            if self.cut.contains(&to) {
                continue;
            }
            self.nodes[to].on_message(from as u32, &bytes, now);
        }
        for i in 0..self.nodes.len() {
            while let Some(e) = self.nodes[i].poll_event() {
                self.events[i].push(e);
            }
        }
    }
    fn run(&mut self, steps: usize) {
        for _ in 0..steps {
            self.step();
        }
    }
    fn verified(&self, i: usize) -> usize {
        self.events[i]
            .iter()
            .filter(|e| matches!(e, Event::Verified { .. }))
            .count()
    }
}

fn equivocation(c: &Cast, who: usize) -> Evidence {
    let k = &c.keys[who];
    let a = AuditLog::new(M, k.id());
    let mut x = a.clone();
    x.append(1, vec![1]).unwrap();
    let mut y = a;
    y.append(1, vec![2]).unwrap();
    use gv_replay::StateMachine;
    let r = GridRules.ruleset_hash();
    Evidence::ConflictingAuthenticators(x.sign_authenticator(r, k), y.sign_authenticator(r, k))
}

#[test]
fn admission_then_evidence_reaches_every_independent_witness_under_faults() {
    let c = cast(3);
    let mut s = sim(&c, 30, 20, 400);
    s.run(40);
    for w in 2..5 {
        for p in 0..2 {
            assert!(s.nodes[w].is_admitted(p), "witness {w} link {p}");
        }
    }
    let ev = equivocation(&c, 1);
    s.nodes[0].submit_evidence(&ev, None);
    s.run(400);
    for w in 2..5 {
        assert_eq!(s.verified(w), 1, "witness {w} must verify exactly once");
        assert_eq!(s.nodes[w].ledger().proven_total(), 1);
    }
    // The accused's own node never needs to agree: both players converged anyway.
    assert_eq!(s.nodes[1].item_ids(), s.nodes[0].item_ids());
}

#[test]
fn malicious_witness_cannot_forge_a_verdict() {
    let c = cast(4); // witness index 5 is malicious but pinned
    let mut s = sim(&c, 0, 0, 100);
    s.run(30);
    let honest = c.keys[0].id();
    // 1. Framing: signatures by the attacker over a conflicting pair "owned" by the honest player.
    let atk = &c.keys[5];
    let mut a = AuditLog::new(M, atk.id());
    a.append(1, vec![1]).unwrap();
    let mut b = AuditLog::new(M, atk.id());
    b.append(1, vec![2]).unwrap();
    let r = s.nodes[0]
        .latest_auth(&honest)
        .map_or([0u8; 32], |x| x.ruleset);
    let _ = r;
    use gv_replay::StateMachine;
    let ruleset = GridRules.ruleset_hash();
    let (mut fa, mut fb) = (
        a.sign_authenticator(ruleset, atk),
        b.sign_authenticator(ruleset, atk),
    );
    fa.owner = honest;
    fb.owner = honest; // relabel as the honest player: signatures no longer verify
    let forged = Evidence::ConflictingAuthenticators(fa, fb);
    // 2. Evidence signed by the attacker about the attacker: not a roster member, so no verdict
    //    about a participant; and a bit-flipped genuine item.
    let mut stranger_a = a.sign_authenticator(ruleset, atk);
    stranger_a.seq = 1;
    let genuine = equivocation(&c, 1);
    let mut bytes = Msg::Evidence(Box::new(genuine)).encode();
    let n = bytes.len() - 100;
    bytes[n] ^= 1;
    let injections: Vec<Vec<u8>> = vec![
        Msg::Evidence(Box::new(forged)).encode(),
        bytes,
        Msg::Auth(stranger_a).encode(),
    ];
    for w in [2usize, 3, 4] {
        for _ in 0..3 {
            for inj in &injections {
                // The malicious witness' link as seen by node w is not even a witness link, but
                // inject directly through the player links to exercise verification itself.
                s.nodes[w].on_message(0, inj, s.now);
            }
        }
    }
    s.run(100);
    for n in 0..6 {
        assert_eq!(
            s.nodes[n].ledger().proven_total(),
            0,
            "node {n} recorded a forged verdict"
        );
        assert_eq!(s.verified(n), 0);
    }
    assert!(s.nodes[2].stats().rejected > 0);
}

#[test]
fn unpinned_or_unadmitted_links_cannot_inject_anything() {
    let c = cast(1);
    let mut s = sim(&c, 0, 0, 10);
    // An extra, unpinned witness key tries to talk to player 0 on a fresh link.
    let rogue = SigningKey::from_seed([99; 32]);
    let mut r = WitnessNode::new(rogue.clone(), c.session(), &[rogue.id()], GridRules);
    r.open_link(0, Remote::Player(c.keys[0].id()), 0);
    s.nodes[0].open_link(9, Remote::AnyWitness, 0);
    let (_, hello) = r.poll_out().unwrap();
    s.nodes[0].on_message(9, &hello, 0);
    assert!(!s.nodes[0].is_admitted(9));
    // Unadmitted evidence is dropped before verification.
    let ev = equivocation(&c, 1);
    s.nodes[0].on_message(9, &Msg::Evidence(Box::new(ev)).encode(), 10);
    assert_eq!(s.nodes[0].ledger().proven_total(), 0);
    assert_eq!(s.nodes[0].stats().dropped_unadmitted, 1);
}

#[test]
fn partitioned_witness_converges_after_reconnect_via_anti_entropy() {
    let c = cast(3);
    let mut s = sim(&c, 10, 10, 200);
    s.run(30);
    s.cut.insert(4);
    let ev = equivocation(&c, 0);
    s.nodes[1].submit_evidence(&ev, None);
    s.run(150);
    assert_eq!(s.verified(2), 1);
    assert_eq!(s.verified(3), 1);
    assert_eq!(s.verified(4), 0, "partitioned witness has not seen it");
    s.cut.clear();
    for w in 2..5 {
        for p in 0..2 {
            s.nodes[w].open_link(p, Remote::Player(c.keys[p as usize].id()), s.now);
            s.nodes[p as usize].open_link(w as u32, Remote::AnyWitness, s.now);
        }
    }
    s.run(300);
    assert_eq!(s.verified(4), 1, "converged after healing");
}

#[test]
fn duplicate_evidence_is_counted_not_reverified_or_reforwarded() {
    let c = cast(2);
    let mut s = sim(&c, 0, 0, 10);
    s.run(30);
    let ev = equivocation(&c, 1);
    for _ in 0..5 {
        s.nodes[0].submit_evidence(&ev, None);
    }
    s.run(60);
    assert_eq!(s.verified(2), 1);
    assert_eq!(s.verified(0), 1);
    assert!(s.nodes[0].stats().duplicates >= 4);
}

#[test]
fn flooding_a_link_is_rate_limited_and_garbage_blocks_it() {
    let c = cast(1);
    let mut s = sim(&c, 0, 0, 10);
    s.run(20);
    let want = Msg::Want(vec![]).encode();
    for _ in 0..500 {
        s.nodes[2].on_message(0, &want, s.now);
    }
    assert!(
        s.nodes[2].stats().dropped_rate > 400,
        "valid flood is rate limited"
    );
    for _ in 0..20 {
        s.nodes[2].on_message(1, b"not a witness message", s.now + 5000);
    }
    s.run(2);
    assert!(s.events[2]
        .iter()
        .any(|e| matches!(e, Event::Blocked { .. })));
}

#[test]
fn witness_audits_a_player_log_and_silence_is_never_proof() {
    let c = cast(1);
    let mut s = sim(&c, 0, 0, 10);
    s.run(20);
    let p = c.keys[0].clone();
    use gv_replay::StateMachine;
    let ruleset = GridRules.ruleset_hash();
    let mut log = AuditLog::new(M, p.id());
    for i in 0..6u8 {
        log.append(1, vec![i]).unwrap();
    }
    let early: Authenticator = {
        let mut l = AuditLog::new(M, p.id());
        for i in 0..3u8 {
            l.append(1, vec![i]).unwrap();
        }
        l.sign_authenticator(ruleset, &p)
    };
    let late = log.sign_authenticator(ruleset, &p);
    s.nodes[2].submit_auth(&early, None);
    s.nodes[2].submit_auth(&late, None);
    let id = s.nodes[2]
        .audit_player(0, p.id(), s.now)
        .expect("challenge issued");
    // The player stays silent: SUSPECTED then UNAVAILABLE, never a fraud verdict.
    s.run(1200);
    let statuses: Vec<_> = s.events[2]
        .iter()
        .filter_map(|e| {
            if let Event::Challenge { status, .. } = e {
                Some(*status)
            } else {
                None
            }
        })
        .collect();
    assert!(statuses.contains(&Status::SuspectedNonCooperation));
    assert!(statuses.iter().all(|x| !x.is_proof()));
    assert_eq!(s.nodes[2].ledger().proven_total(), 0);
    let _ = (id, ChallengeKind::Ack { seq: 0 });
}

#[test]
fn chunked_transfer_reassembles_in_order_and_rejects_malformed_pieces() {
    use crate::witness::{CHUNK_BYTES, MAX_ITEM_BYTES};
    use sha2::{Digest as _, Sha256};
    let c = cast(1);
    let mut s = sim(&c, 0, 0, 10);
    s.run(20);
    // A large blob that is not a valid package: it must reassemble, hash-match and then be
    // rejected by package verification (never stored, never forwarded).
    let blob: Vec<u8> = (0..CHUNK_BYTES * 3 + 5).map(|i| (i % 251) as u8).collect();
    let transfer: [u8; 32] = Sha256::digest(&blob).into();
    let count = blob.chunks(CHUNK_BYTES).count() as u32;
    let before = s.nodes[2].stats();
    let now = s.now;
    // Pieces out of order or duplicated do not start or corrupt an assembly.
    let pieces: Vec<_> = blob.chunks(CHUNK_BYTES).enumerate().collect();
    for (i, p) in pieces.iter().skip(1) {
        let m = Msg::Chunk {
            transfer,
            index: *i as u32,
            count,
            data: p.to_vec(),
        };
        s.nodes[2].on_message(0, &m.encode(), now);
    }
    assert_eq!(
        s.nodes[2].stats().rejected,
        before.rejected,
        "orphan tail is ignored, not a strike"
    );
    for (i, p) in &pieces {
        let m = Msg::Chunk {
            transfer,
            index: *i as u32,
            count,
            data: p.to_vec(),
        };
        s.nodes[2].on_message(0, &m.encode(), now + 1);
        s.nodes[2].on_message(0, &m.encode(), now + 1); // duplicate delivery
    }
    assert!(
        s.nodes[2].stats().rejected > before.rejected,
        "a reassembled non-package is rejected"
    );
    assert!(s.nodes[2].item_ids().is_empty());
    // Whole-item hash mismatch is rejected.
    let r0 = s.nodes[2].stats().rejected;
    for (i, p) in &pieces {
        let m = Msg::Chunk {
            transfer: [9; 32],
            index: *i as u32,
            count,
            data: p.to_vec(),
        };
        s.nodes[2].on_message(0, &m.encode(), now + 2000);
    }
    assert!(s.nodes[2].stats().rejected > r0);
    // Impossible metadata is rejected before any allocation.
    let r1 = s.nodes[2].stats().rejected;
    let huge = MAX_ITEM_BYTES.div_ceil(CHUNK_BYTES) as u32 + 1;
    for m in [
        Msg::Chunk {
            transfer,
            index: 0,
            count: 0,
            data: vec![],
        },
        Msg::Chunk {
            transfer,
            index: 5,
            count: 2,
            data: vec![],
        },
        Msg::Chunk {
            transfer,
            index: 0,
            count: huge,
            data: vec![],
        },
        Msg::Chunk {
            transfer,
            index: 0,
            count: 2,
            data: vec![0; CHUNK_BYTES + 1],
        },
    ] {
        s.nodes[2].on_message(0, &m.encode(), now + 4000);
    }
    assert!(s.nodes[2].stats().rejected >= r1 + 4);
}
