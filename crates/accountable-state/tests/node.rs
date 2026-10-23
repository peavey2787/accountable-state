use accountable_state::identity::SigningKey;
use accountable_state::session::Session;
use accountable_state::{
    AccountableState, ActionOrdering, Config, Dest, DisclosurePolicy, DurableStorage, Event,
    ExportQuery, OpenError, Outgoing, Output, Peer, PipelineConfig, ReceiveError, RuleError,
    StateMachine, SubmitError, TrustAnchor, VerificationResult, Verifier,
};
use gv_edge::live::PipeMsg;
use gv_edge::testkit::{GridRules, ACT, LEFT, RIGHT};
use std::path::PathBuf;
use std::time::Instant;

const MATCH: [u8; 32] = [9; 32];
const PLAYERS: usize = 3;

fn keys() -> Vec<SigningKey> {
    (0..PLAYERS as u8)
        .map(|i| SigningKey::from_seed([1 + i; 32]))
        .collect()
}
fn session() -> Session {
    let ids: Vec<_> = keys().iter().map(SigningKey::id).collect();
    Session::unanimous(MATCH, &ids).unwrap()
}
fn controls(c: u16) -> [u8; 2] {
    c.to_le_bytes()
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
        session: session(),
        pipeline: PipelineConfig::new(controls(0).to_vec()),
        witnesses: Vec::new(),
        witness_mode: accountable_state::WitnessMode::PeersOnly,
        disclosure: DisclosurePolicy::PUBLIC,
        resume: None,
        storage,
    }
}
fn open_all<M: StateMachine + Clone>(
    machine: &M,
    dir: &std::path::Path,
) -> Vec<AccountableState<M>> {
    keys()
        .into_iter()
        .map(|k| {
            let storage = DurableStorage::at(dir.join(hex(&k.id()[..4])));
            AccountableState::open(machine.clone(), config(k, storage)).unwrap()
        })
        .collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Deliver everything the nodes want to send; collects the events each one saw.
fn shuttle<M: StateMachine + Clone>(nodes: &mut [AccountableState<M>], events: &mut [Vec<Event>]) {
    let ids: Vec<_> = keys().iter().map(SigningKey::id).collect();
    loop {
        let mut moved = false;
        for i in 0..nodes.len() {
            while let Some(out) = nodes[i].poll(Instant::now()) {
                moved = true;
                match out {
                    Output::Send(Outgoing::Member { to, bytes }) => {
                        for j in (0..nodes.len()).filter(|&j| j != i) {
                            if matches!(to, Dest::All) || to == Dest::Peer(ids[j]) {
                                nodes[j].receive(Peer::Member(ids[i]), &bytes).unwrap();
                            }
                        }
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
    nodes: &mut [AccountableState<M>],
    ticks: u64,
    fault_at: Option<u64>,
) -> Vec<Vec<Event>> {
    let mut events = vec![Vec::new(); nodes.len()];
    for t in 0..ticks {
        let control = [LEFT, RIGHT, ACT, 0][(t % 4) as usize];
        for (i, node) in nodes.iter_mut().enumerate() {
            if i == 0 && fault_at == Some(t) {
                inject(node);
            }
            node.submit(&controls(control)).unwrap();
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
        ruleset: GridRules.ruleset_hash(),
        session: session().digest(),
    })
}

#[test]
fn an_honest_group_certifies_and_exports_a_verifiable_archive() {
    let dir = scratch("honest");
    let mut nodes = open_all(&GridRules, &dir);
    let events = play(&mut nodes, 200, None);
    for (node, seen) in nodes.iter().zip(&events) {
        let view = node.state();
        assert!(view.certified_tick >= 100, "{}", view.certified_tick);
        assert!(!view.anchor_check_pending);
        assert!(view.checkpoint.is_some());
        assert!(!seen.iter().any(|e| matches!(e, Event::Violation(_))));
    }
    assert!(nodes
        .windows(2)
        .all(|w| w[0].state().state == w[1].state().state));
    for n in &mut nodes {
        n.flush();
    }
    let pkg = nodes[0].export(ExportQuery::MatchArchive).unwrap();
    assert!(matches!(
        verifier().verify_package(pkg.bytes(), &GridRules),
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
    let mut nodes = open_all(&GridRules, &dir);
    let cheater = keys()[0].id();
    let events = play(&mut nodes, 120, Some(30));
    for seen in &events[1..] {
        assert!(seen
            .iter()
            .any(|e| matches!(e, Event::Violation(v) if v.accused == cheater)));
    }
    let commitment = nodes[1]
        .subscribe(0, 1000)
        .into_iter()
        .find_map(|e| match e.event {
            accountable_state::ExportEvent::Evidence {
                accused,
                commitment,
            } if accused == cheater => Some(commitment),
            _ => None,
        })
        .expect("evidence published on the feed");
    let pkg = nodes[1].export(ExportQuery::Fraud(commitment.id)).unwrap();
    match verifier().verify_package(pkg.bytes(), &GridRules) {
        VerificationResult::ProvenViolation(p) => assert_eq!(p.accused, vec![cheater]),
        other => panic!("{other:?}"),
    }
}

#[test]
fn open_fails_closed_when_storage_is_unavailable() {
    let missing = scratch("nostore").join("absent").join("node");
    let err = AccountableState::open(
        GridRules,
        config(keys()[0].clone(), DurableStorage::at(missing)),
    )
    .err()
    .unwrap();
    assert!(matches!(err, OpenError::Storage { .. }), "{err:?}");
}

#[test]
fn a_key_outside_the_roster_is_refused() {
    let dir = scratch("roster");
    let stranger = SigningKey::from_seed([77; 32]);
    let err = AccountableState::open(
        GridRules,
        config(stranger, DurableStorage::at(dir.join("x"))),
    )
    .err()
    .unwrap();
    assert_eq!(err, OpenError::NotInRoster);
}

#[test]
fn a_witness_may_only_deliver_challenges_and_retained_heads() {
    let dir = scratch("witness");
    let mut nodes = open_all(&GridRules, &dir);
    let witness = SigningKey::from_seed([88; 32]).id();
    let req = PipeMsg::AnchorReq.encode().unwrap();
    assert_eq!(
        nodes[0].receive(Peer::Witness(witness), &req),
        Err(ReceiveError::NotAllowedFromWitness)
    );
    assert_eq!(
        nodes[0].receive(Peer::Member(keys()[1].id()), &[0xff, 1, 2]),
        Err(ReceiveError::Malformed)
    );
}

/// A ledger where `ACT` is a transfer whose outcome depends on a global order.
#[derive(Clone)]
struct Ledger;
impl StateMachine for Ledger {
    fn ruleset_hash(&self) -> accountable_state::Digest {
        GridRules.ruleset_hash()
    }
    fn genesis(&self, session: &Session) -> Vec<u8> {
        GridRules.genesis(session)
    }
    fn apply(&self, state: &[u8], input: &[u8]) -> Result<Vec<u8>, RuleError> {
        GridRules.apply(state, input)
    }
    fn ordering(&self, payload: &[u8]) -> ActionOrdering {
        let control = u16::from_le_bytes([payload[0], payload[1]]);
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
    let mut nodes = open_all(&Ledger, &dir);
    assert_eq!(
        nodes[0].submit(&controls(ACT)),
        Err(SubmitError::RequiresExternalOrdering)
    );
    assert_eq!(nodes[0].submit(&controls(LEFT)), Ok(0));
    assert_eq!(nodes[0].state().next_submit, 1);
}

#[test]
fn an_action_of_the_wrong_width_is_refused() {
    let dir = scratch("width");
    let mut nodes = open_all(&GridRules, &dir);
    assert_eq!(
        nodes[0].submit(&[1]),
        Err(SubmitError::WrongWidth { expected: 2 })
    );
}
