//! Witness-quorum mode on real nodes: committed heads on four witnesses, crash recovery from a
//! quorum read, and the explicit blocked state.
use accountable_state::identity::SigningKey;
use accountable_state::session::{Certification, Ordering, Roster, Session};
use accountable_state::{
    AccountableState, AuditEvent, Config, Dest, DisclosurePolicy, DurableStorage, Event, Outgoing,
    Output, Peer, PeerEvent, PipelineConfig, WitnessMode, WitnessOut,
};
use gv_edge::live::PipeMsg;
use gv_edge::quorum::{FileCellStore, RegisterWitness};
use gv_edge::testkit::{GridRules, ACT, LEFT, RIGHT};
use std::path::{Path, PathBuf};
use std::time::Instant;

const MATCH: [u8; 32] = [9; 32];
const PLAYERS: usize = 3;
const WITNESSES: u8 = 4;

fn keys() -> Vec<SigningKey> {
    (0..PLAYERS as u8)
        .map(|i| SigningKey::from_seed([1 + i; 32]))
        .collect()
}
fn witness_keys() -> Vec<SigningKey> {
    (0..WITNESSES)
        .map(|i| SigningKey::from_seed([100 + i; 32]))
        .collect()
}
/// Two of three certify, so one absent player does not stop the others.
fn session() -> Session {
    let ids: Vec<_> = keys().iter().map(SigningKey::id).collect();
    Session::new(
        MATCH,
        Roster::players(&ids).unwrap(),
        Certification::Threshold { min: 2 },
        Ordering::Roster,
        Vec::new(),
    )
    .unwrap()
}
fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("as-witnessed-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn open(dir: &Path, i: usize) -> AccountableState<GridRules> {
    let key = keys()[i].clone();
    let mut pipeline = PipelineConfig::new(vec![0, 0]);
    pipeline.close_after_ticks = Some(60);
    let storage = DurableStorage::at(dir.join(hex(&key.id()[..4])));
    AccountableState::open(
        GridRules,
        Config {
            key,
            session: session(),
            pipeline,
            witnesses: witness_keys().iter().map(SigningKey::id).collect(),
            witness_mode: WitnessMode::Quorum,
            disclosure: DisclosurePolicy::PUBLIC,
            resume: None,
            storage,
        },
    )
    .unwrap()
}

struct Net {
    nodes: Vec<AccountableState<GridRules>>,
    witnesses: Vec<RegisterWitness<FileCellStore>>,
    /// Witnesses currently reachable.
    up: Vec<bool>,
    /// Players whose link is down: they neither send nor receive.
    away: Vec<bool>,
    events: Vec<Vec<Event>>,
}

impl Net {
    fn new(dir: &Path) -> Self {
        let witnesses = witness_keys()
            .into_iter()
            .enumerate()
            .map(|(i, k)| {
                let store = FileCellStore::open(dir.join(format!("w{i}"))).unwrap();
                RegisterWitness::new(k, store)
            })
            .collect();
        Self {
            nodes: (0..PLAYERS).map(|i| open(dir, i)).collect(),
            witnesses,
            up: vec![true; WITNESSES as usize],
            away: vec![false; PLAYERS],
            events: vec![Vec::new(); PLAYERS],
        }
    }

    fn shuttle(&mut self) {
        let ids: Vec<_> = keys().iter().map(SigningKey::id).collect();
        loop {
            let mut moved = false;
            for i in 0..self.nodes.len() {
                if self.away[i] {
                    continue;
                }
                while let Some(out) = self.nodes[i].poll(Instant::now()) {
                    moved = true;
                    match out {
                        Output::Send(Outgoing::Member { to, bytes }) => {
                            for j in (0..self.nodes.len()).filter(|&j| j != i && !self.away[j]) {
                                if matches!(to, Dest::All) || to == Dest::Peer(ids[j]) {
                                    let _ = self.nodes[j].receive(Peer::Member(ids[i]), &bytes);
                                }
                            }
                        }
                        Output::Send(Outgoing::Witness(WitnessOut::Quorum { to, msg })) => {
                            self.deliver_to_witnesses(i, to, &msg);
                        }
                        Output::Send(Outgoing::Witness(_)) => {}
                        Output::Event(e) => self.events[i].push(e),
                    }
                }
            }
            if !moved {
                return;
            }
        }
    }

    fn deliver_to_witnesses(
        &mut self,
        from: usize,
        to: Option<[u8; 32]>,
        msg: &gv_edge::quorum::QuorumMsg,
    ) {
        for w in 0..self.witnesses.len() {
            let id = self.witnesses[w].id();
            if !self.up[w] || to.is_some_and(|t| t != id) {
                continue;
            }
            for reply in self.witnesses[w].handle(MATCH, msg) {
                let bytes = PipeMsg::Quorum(reply).encode().unwrap();
                self.nodes[from].receive(Peer::Witness(id), &bytes).unwrap();
            }
        }
    }

    fn play(&mut self, ticks: u64) {
        for t in 0..ticks {
            let control = [LEFT, RIGHT, ACT, 0][(t % 4) as usize];
            for (node, _) in self.nodes.iter_mut().zip(&self.away).filter(|(_, a)| !**a) {
                node.submit(&[control as u8, (control >> 8) as u8]).unwrap();
            }
            self.shuttle();
        }
    }
    fn violations(&self) -> usize {
        self.events
            .iter()
            .flatten()
            .filter(|e| matches!(e, Event::Violation(_)))
            .count()
    }
    fn recovered(&self, i: usize) -> bool {
        self.events[i]
            .iter()
            .any(|e| matches!(e, Event::Audit(AuditEvent::QuorumRecovered { .. })))
    }
}

#[test]
fn a_group_runs_with_every_head_committed_on_a_witness_quorum() {
    let dir = scratch("honest");
    let mut net = Net::new(&dir);
    net.shuttle();
    assert!(net.nodes.iter().all(|n| !n.state().recovery_blocked));
    net.play(200);
    for n in &net.nodes {
        assert!(
            n.state().certified_tick >= 100,
            "{}",
            n.state().certified_tick
        );
    }
    assert_eq!(net.violations(), 0);
}

#[test]
fn recovery_is_blocked_with_too_few_witnesses_and_never_resumes_by_timeout() {
    let dir = scratch("blocked");
    let mut net = Net::new(&dir);
    net.up = vec![true, true, false, false]; // 2 of 4: below the quorum of 3
    net.shuttle();
    assert!(net.nodes.iter().all(|n| n.state().recovery_blocked));
    for _ in 0..50 {
        net.play(10);
    }
    assert!(net.nodes.iter().all(|n| n.state().recovery_blocked));
    assert!(net.nodes.iter().all(|n| n.state().certified_tick == 0));
    net.up[2] = true;
    net.play(10);
    assert!(net.nodes.iter().all(|n| !n.state().recovery_blocked));
}

#[test]
fn a_node_that_lost_its_state_recovers_from_the_witnesses_without_any_conviction() {
    let dir = scratch("lost");
    let mut net = Net::new(&dir);
    net.play(60);
    let before = net.events[0].len();
    // Process 0 dies and its disk is wiped; it restarts as a new incarnation.
    let wiped = dir.join(hex(&keys()[0].id()[..4]));
    for f in std::fs::read_dir(&dir).unwrap().flatten() {
        let name = f.file_name().to_string_lossy().to_string();
        if f.path().starts_with(&wiped) || name.starts_with(&hex(&keys()[0].id()[..4])) {
            let _ = std::fs::remove_file(f.path());
        }
    }
    net.nodes[0] = open(&dir, 0);
    net.shuttle();
    assert!(!net.nodes[0].state().recovery_blocked);
    assert!(net.events[0][before..].iter().any(|e| matches!(
        e,
        Event::Audit(AuditEvent::QuorumRecovered { seq: Some(_) })
    )));
    assert_eq!(
        net.violations(),
        0,
        "legitimate crash recovery convicts nobody"
    );
    assert!(net.recovered(0));
}

#[test]
fn a_returning_player_proves_itself_catches_up_and_rejoins_at_the_live_tick() {
    let dir = scratch("reconnect");
    let mut net = Net::new(&dir);
    net.shuttle();
    net.away[2] = true;
    net.play(300);
    let ahead = net.nodes[0].state().certified_tick;
    assert!(
        ahead >= 100,
        "play went on without the absent player: {ahead}"
    );
    assert_eq!(net.nodes[2].state().certified_tick, 0);

    net.away[2] = false;
    let ids: Vec<_> = keys().iter().map(SigningKey::id).collect();
    for j in 0..2 {
        net.nodes[2].peer_up(ids[j]);
        net.nodes[j].peer_up(ids[2]);
    }
    net.shuttle();
    let back = net.nodes[2].state();
    assert!(back.certified_tick >= ahead, "{}", back.certified_tick);
    assert!(back.next_submit >= ahead, "rejoined at the live tick");
    assert!(net.events[2]
        .iter()
        .any(|e| matches!(e, Event::Peer(PeerEvent::CaughtUp { .. }))));
    net.play(120);
    assert!(net.nodes[2].state().certified_tick > ahead, "and plays on");
    assert_eq!(net.violations(), 0, "an absence convicts nobody");
}

#[test]
fn every_open_of_the_same_storage_is_a_newer_incarnation() {
    let dir = scratch("incarnation");
    drop(open(&dir, 0));
    drop(open(&dir, 0));
    let file = dir.join(format!("{}.incarnation", hex(&keys()[0].id()[..4])));
    let bytes = std::fs::read(file).unwrap();
    assert_eq!(u64::from_le_bytes(bytes.try_into().unwrap()), 2);
}
