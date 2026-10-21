use accountable_state::identity::SigningKey;
use accountable_state::{
    AccountableState, ActionOrdering, Config, DisclosurePolicy, DurableStorage, Event, ExportEvent,
    ExportQuery, OpenError, Outgoing, Output, Peer, PlayerId, ReceiveError, RuleError,
    StateMachine, SubmitError, TrustAnchor, VerificationResult, Verifier,
};
use gv_edge::live::PipeMsg;
use gv_edge::testkit::{GridRules, ACT, LEFT, RIGHT};
use std::path::PathBuf;
use std::time::Instant;

const MATCH: [u8; 32] = [9; 32];

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
    let d = std::env::temp_dir().join(format!("accountable-state-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn config(key: SigningKey, storage: DurableStorage) -> Config {
    Config {
        key,
        roster: roster(),
        match_id: MATCH,
        epoch_ticks: 20,
        witnesses: Vec::new(),
        disclosure: DisclosurePolicy::PUBLIC,
        resume: None,
        storage,
    }
}
fn open_pair<M: StateMachine + Clone>(
    machine: &M,
    dir: &std::path::Path,
) -> [AccountableState<M>; 2] {
    keys().map(|k| {
        let storage = DurableStorage::at(dir.join(hex(&k.id()[..4])));
        AccountableState::open(machine.clone(), config(k, storage)).unwrap()
    })
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Deliver everything both nodes want to send; returns the events seen per node.
fn shuttle<M: StateMachine + Clone>(
    nodes: &mut [AccountableState<M>; 2],
    events: &mut [Vec<Event>; 2],
) {
    loop {
        let mut moved = false;
        for i in 0..2 {
            while let Some(out) = nodes[i].poll(Instant::now()) {
                moved = true;
                match out {
                    Output::Send(Outgoing::Opponent(bytes)) => {
                        nodes[1 - i].receive(Peer::Opponent, &bytes).unwrap();
                    }
                    Output::Send(Outgoing::Witness(_)) => {}
                    Output::Event(e) => events[i].push(e),
                }
            }
        }
        if !moved {
            return;
        }
    }
}
fn play<M: StateMachine + Clone>(
    nodes: &mut [AccountableState<M>; 2],
    ticks: u64,
    fault_at: Option<u64>,
) -> [Vec<Event>; 2] {
    let mut events = [Vec::new(), Vec::new()];
    for t in 0..ticks {
        let control = [LEFT, RIGHT, ACT, 0][(t % 4) as usize];
        for (i, node) in nodes.iter_mut().enumerate() {
            if i == 0 && fault_at == Some(t) {
                inject(node);
            }
            node.submit(control).unwrap();
        }
        shuttle(nodes, &mut events);
    }
    events
}
#[cfg(feature = "fault-injection")]
fn inject<M: StateMachine + Clone>(node: &mut AccountableState<M>) {
    node.inject_false_checkpoint();
}
#[cfg(not(feature = "fault-injection"))]
fn inject<M: StateMachine + Clone>(_: &mut AccountableState<M>) {
    unreachable!("fault injection is disabled");
}

fn verifier() -> Verifier {
    Verifier::new(TrustAnchor {
        match_id: MATCH,
        ruleset: GridRules::new(roster()).ruleset_hash(),
        roster: roster(),
    })
}

#[test]
fn an_honest_pair_certifies_and_exports_a_verifiable_archive() {
    let dir = scratch("honest");
    let rules = GridRules::new(roster());
    let mut nodes = open_pair(&rules, &dir);
    let events = play(&mut nodes, 200, None);
    for (node, seen) in nodes.iter().zip(&events) {
        let view = node.state();
        assert!(view.certified_tick >= 100, "{}", view.certified_tick);
        assert!(!view.anchor_check_pending);
        assert!(view.checkpoint.is_some());
        assert!(!seen.iter().any(|e| matches!(e, Event::Violation(_))));
    }
    assert_eq!(nodes[0].state().state, nodes[1].state().state);
    for n in &mut nodes {
        n.flush();
    }
    let pkg = nodes[0].export(ExportQuery::MatchArchive).unwrap();
    assert!(matches!(
        verifier().verify_package(pkg.bytes(), &rules),
        VerificationResult::Valid(_)
    ));
    let feed = nodes[0].subscribe(0, 100);
    assert!(!feed.is_empty());
    assert!(feed.windows(2).all(|w| w[0].id < w[1].id));
    let after = nodes[0].subscribe(feed[0].id, 100);
    assert_eq!(after.len(), feed.len() - 1);
}

#[cfg(feature = "fault-injection")]
#[test]
fn a_false_checkpoint_becomes_an_exportable_proven_violation() {
    let dir = scratch("fraud");
    let rules = GridRules::new(roster());
    let mut nodes = open_pair(&rules, &dir);
    let cheater = keys()[0].id();
    let events = play(&mut nodes, 120, Some(30));
    assert!(events[1]
        .iter()
        .any(|e| matches!(e, Event::Violation(v) if v.accused == cheater)));
    let commitment = nodes[1]
        .subscribe(0, 1000)
        .into_iter()
        .find_map(|e| match e.event {
            ExportEvent::Evidence {
                accused,
                commitment,
            } if accused == cheater => Some(commitment),
            _ => None,
        })
        .expect("evidence published on the feed");
    let pkg = nodes[1].export(ExportQuery::Fraud(commitment.id)).unwrap();
    match verifier().verify_package(pkg.bytes(), &rules) {
        VerificationResult::ProvenViolation(p) => assert_eq!(p.accused, vec![cheater]),
        other => panic!("{other:?}"),
    }
}

#[test]
fn open_fails_closed_when_storage_is_unavailable() {
    let missing = scratch("nostore").join("absent").join("node");
    let err = AccountableState::open(
        GridRules::new(roster()),
        config(keys()[0].clone(), DurableStorage::at(missing)),
    )
    .err()
    .unwrap();
    assert!(matches!(err, OpenError::Storage { .. }), "{err:?}");
}

#[test]
fn a_key_outside_the_roster_is_refused() {
    let dir = scratch("roster");
    let stranger = SigningKey::from_seed([3; 32]);
    let err = AccountableState::open(
        GridRules::new(roster()),
        config(stranger, DurableStorage::at(dir.join("x"))),
    )
    .err()
    .unwrap();
    assert_eq!(err, OpenError::NotInRoster);
}

#[test]
fn a_witness_may_only_deliver_challenges_and_retained_heads() {
    let dir = scratch("witness");
    let mut nodes = open_pair(&GridRules::new(roster()), &dir);
    let req = PipeMsg::AnchorReq.encode().unwrap();
    assert_eq!(
        nodes[0].receive(Peer::Witness, &req),
        Err(ReceiveError::NotAllowedFromWitness)
    );
    assert_eq!(
        nodes[0].receive(Peer::Opponent, &[0xff, 1, 2]),
        Err(ReceiveError::Malformed)
    );
}

/// A ledger where `ACT` is a transfer whose outcome depends on a global order.
#[derive(Clone)]
struct Ledger(GridRules);
impl StateMachine for Ledger {
    fn ruleset_hash(&self) -> accountable_state::Digest {
        self.0.ruleset_hash()
    }
    fn genesis(&self, roster: &[PlayerId; 2]) -> Vec<u8> {
        self.0.genesis(roster)
    }
    fn apply(&self, state: &[u8], input: &[u8]) -> Result<Vec<u8>, RuleError> {
        self.0.apply(state, input)
    }
    fn ordering(&self, control: u16) -> ActionOrdering {
        if control & ACT != 0 {
            ActionOrdering::RequiresExternalOrdering
        } else {
            ActionOrdering::MergeSafe
        }
    }
}

#[test]
fn externally_ordered_actions_are_never_accepted_locally() {
    let dir = scratch("ordering");
    let mut nodes = open_pair(&Ledger(GridRules::new(roster())), &dir);
    assert_eq!(
        nodes[0].submit(ACT),
        Err(SubmitError::RequiresExternalOrdering)
    );
    assert_eq!(nodes[0].submit(LEFT), Ok(0));
    assert_eq!(nodes[0].state().next_submit, 1);
}
