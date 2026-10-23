//! Witness-quorum mode on real nodes: committed heads on four witnesses, crash recovery from a
//! quorum read, and the explicit blocked state.
use accountable_state::identity::SigningKey;
use accountable_state::session::Session;
use accountable_state::{
    AccountableState, AuditEvent, Config, Dest, DisclosurePolicy, DurableStorage, Event, Outgoing,
    Output, Peer, PipelineConfig, WitnessMode, WitnessOut,
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
fn session() -> Session {
    let ids: Vec<_> = keys().iter().map(SigningKey::id).collect();
    Session::unanimous(MATCH, &ids).unwrap()
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
    let storage = DurableStorage::at(dir.join(hex(&key.id()[..4])));
    AccountableState::open(
        GridRules,
        Config {
            key,
            session: session(),
            pipeline: PipelineConfig::new(vec![0, 0]),
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
            events: vec![Vec::new(); PLAYERS],
        }
    }

    fn shuttle(&mut self) {
        let ids: Vec<_> = keys().iter().map(SigningKey::id).collect();
        loop {
            let mut moved = false;
            for i in 0..self.nodes.len() {
                while let Some(out) = self.nodes[i].poll(Instant::now()) {
                    moved = true;
                    match out {
                        Output::Send(Outgoing::Member { to, bytes }) => {
                            for j in (0..self.nodes.len()).filter(|&j| j != i) {
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
            for node in &mut self.nodes {
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
