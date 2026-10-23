use accountable_state::identity::SigningKey;
use accountable_state::session::Session;
use accountable_state::{
    AccountableState, Config, DisclosurePolicy, DurableStorage, IngressLimits, Peer,
    PipelineConfig, ReceiveError, WitnessMode,
};
use gv_edge::live::PipeMsg;
use gv_edge::testkit::GridRules;
use std::time::{Duration, Instant};

const MATCH: [u8; 32] = [4; 32];

fn keys() -> Vec<SigningKey> {
    (0..3u8)
        .map(|i| SigningKey::from_seed([1 + i; 32]))
        .collect()
}

fn node(name: &str) -> AccountableState<GridRules> {
    let ids: Vec<_> = keys().iter().map(SigningKey::id).collect();
    let dir = std::env::temp_dir().join(format!("as-flood-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    AccountableState::open(
        GridRules,
        Config {
            key: keys()[0].clone(),
            session: Session::unanimous(MATCH, &ids).unwrap(),
            pipeline: PipelineConfig::new(0u16.to_le_bytes().to_vec()),
            witnesses: Vec::new(),
            witness_mode: WitnessMode::PeersOnly,
            disclosure: DisclosurePolicy::PUBLIC,
            resume: None,
            storage: DurableStorage::at(dir.join("n")),
        },
    )
    .unwrap()
}

fn limits() -> IngressLimits {
    IngressLimits {
        max_message: 1024,
        window: Duration::from_secs(1),
        messages_per_window: 100,
        bytes_per_window: 1 << 20,
        resume_per_window: 3,
    }
}

fn peer(i: usize) -> Peer {
    Peer::Member(keys()[i].id())
}

#[test]
fn a_flooding_peer_is_throttled_without_affecting_another_and_recovers_next_window() {
    let mut n = node("rate");
    n.set_ingress_limits(limits());
    let ping = PipeMsg::AnchorReq.encode().unwrap();
    let results: Vec<_> = (0..1000).map(|_| n.receive(peer(1), &ping)).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 100);
    assert!(results[100..]
        .iter()
        .all(|r| *r == Err(ReceiveError::Throttled)));
    assert_eq!(
        n.receive(peer(2), &ping),
        Ok(()),
        "another peer has its own budget"
    );
    let later = Instant::now() + Duration::from_secs(2);
    while n.poll(later).is_some() {}
    assert_eq!(
        n.receive(peer(1), &ping),
        Ok(()),
        "a new window restores the budget"
    );
}

#[test]
fn oversize_messages_are_refused_before_decoding() {
    let mut n = node("size");
    n.set_ingress_limits(limits());
    assert_eq!(
        n.receive(peer(1), &vec![1u8; 2000]),
        Err(ReceiveError::TooLarge)
    );
}

#[test]
fn evidence_is_never_throttled() {
    let mut n = node("evidence");
    n.set_ingress_limits(limits());
    let ping = PipeMsg::AnchorReq.encode().unwrap();
    for _ in 0..200 {
        let _ = n.receive(peer(1), &ping);
    }
    assert_eq!(n.receive(peer(1), &ping), Err(ReceiveError::Throttled));
    // A message tagged as evidence is examined (and here found malformed), not dropped by the budget.
    assert_eq!(
        n.receive(peer(1), &[11, 0, 0]),
        Err(ReceiveError::Malformed)
    );
}

#[test]
fn resume_traffic_has_a_smaller_budget_than_ordinary_traffic() {
    let mut n = node("resume");
    n.set_ingress_limits(limits());
    let results: Vec<_> = (0..10).map(|_| n.receive(peer(1), &[15, 0])).collect();
    assert!(results[3..]
        .iter()
        .all(|r| *r == Err(ReceiveError::Throttled)));
    assert_eq!(
        n.receive(peer(1), &PipeMsg::AnchorReq.encode().unwrap()),
        Err(ReceiveError::Throttled)
    );
}
