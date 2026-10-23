//! Three player processes and four witnesses over real TCP: one player process is killed without
//! warning and started again, and must rejoin through the witness quorum and a catch-up without
//! anyone being accused. The test binary runs itself as the player (`AS_ROLE` selects the role).
use accountable_state::identity::SigningKey;
use accountable_state::session::{Certification, Ordering, Roster, Session};
use accountable_state::{
    AccountableState, Config, Dest, DisclosurePolicy, DurableStorage, Event, Outgoing, Output,
    Peer, PeerEvent, PipelineConfig, WitnessMode, WitnessOut,
};
use gv_edge::live::PipeMsg;
use gv_edge::quorum::{FileCellStore, RegisterWitness};
use gv_edge::testkit::{GridRules, ACT, LEFT, RIGHT};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MATCH: [u8; 32] = [9; 32];
const PLAYERS: usize = 3;
const WITNESSES: u8 = 4;
const ALL: u8 = 0xFF;
const PATIENCE: Duration = Duration::from_secs(90);

const HELLO: u8 = 0;
const MEMBER: u8 = 1;
const WITNESS: u8 = 2;
const PEER_UP: u8 = 3;
const PEER_DOWN: u8 = 4;

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
    Session::new(
        MATCH,
        Roster::players(&ids).unwrap(),
        Certification::Threshold { min: 2 },
        Ordering::Roster,
        Vec::new(),
    )
    .unwrap()
}

fn write_frame(stream: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    let mut frame = (body.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(body);
    stream.write_all(&frame)
}

fn read_frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
    stream.read_exact(&mut body)?;
    Ok(body)
}

// ---- the player process ------------------------------------------------------------------

fn open_node(dir: &Path, i: usize) -> AccountableState<GridRules> {
    let key = keys()[i].clone();
    let mut pipeline = PipelineConfig::new(vec![0, 0]);
    pipeline.close_after_ticks = Some(60);
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
            storage: DurableStorage::at(dir.join(format!("player{i}"))),
        },
    )
    .unwrap()
}

/// Frames from the hub, read on their own thread so the node loop never blocks on the socket.
fn inbox(stream: &TcpStream) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    let mut reader = stream.try_clone().unwrap();
    std::thread::spawn(move || {
        while let Ok(frame) = read_frame(&mut reader) {
            if tx.send(frame).is_err() {
                break;
            }
        }
    });
    rx
}

fn send_output(stream: &mut TcpStream, out: Outgoing, ids: &[[u8; 32]]) {
    let body = match out {
        Outgoing::Member { to, bytes } => {
            let dest = match to {
                Dest::All => ALL,
                Dest::Peer(id) => ids.iter().position(|p| *p == id).map_or(ALL, |i| i as u8),
            };
            [&[MEMBER, dest][..], &bytes].concat()
        }
        Outgoing::Witness(WitnessOut::Quorum { to, msg }) => {
            let wire = PipeMsg::Quorum(*msg).encode().unwrap();
            let target = to.unwrap_or([0; 32]);
            [&[WITNESS, u8::from(to.is_some())][..], &target, &wire].concat()
        }
        Outgoing::Witness(_) => return,
    };
    write_frame(stream, &body).unwrap();
}

fn deliver(node: &mut AccountableState<GridRules>, frame: &[u8], ids: &[[u8; 32]]) {
    match frame[0] {
        MEMBER => {
            let _ = node.receive(Peer::Member(ids[usize::from(frame[1])]), &frame[2..]);
        }
        WITNESS => {
            let id: [u8; 32] = frame[1..33].try_into().unwrap();
            let _ = node.receive(Peer::Witness(id), &frame[33..]);
        }
        PEER_UP => node.peer_up(ids[usize::from(frame[1])]),
        PEER_DOWN => node.peer_down(ids[usize::from(frame[1])]),
        _ => {}
    }
}

#[derive(Default)]
struct Tally {
    violations: usize,
    caught_up: bool,
}

impl Tally {
    fn note(&mut self, e: &Event) {
        match e {
            Event::Violation(_) => self.violations += 1,
            Event::Peer(PeerEvent::CaughtUp { .. }) => self.caught_up = true,
            _ => {}
        }
    }
}

/// One game tick at 60 Hz.
const TICK: Duration = Duration::from_millis(16);

fn run_player(role: usize, addr: &str, dir: &Path) {
    let ids: Vec<_> = keys().iter().map(SigningKey::id).collect();
    let mut stream = TcpStream::connect(addr).unwrap();
    write_frame(&mut stream, &[HELLO, role as u8]).unwrap();
    let frames = inbox(&stream);
    let mut node = open_node(dir, role);
    let mut tally = Tally::default();
    let (mut last_submit, mut last_status) = (Instant::now(), Instant::now());
    let mut peers_up = 0;
    loop {
        while let Ok(frame) = frames.try_recv() {
            peers_up += usize::from(frame[0] == PEER_UP);
            deliver(&mut node, &frame, &ids);
        }
        // Play starts once everyone is connected, as in a lobby; a rejoiner starts at once.
        let linked = peers_up >= PLAYERS - 1;
        while let Some(out) = node.poll(Instant::now()) {
            match out {
                Output::Send(o) => send_output(&mut stream, o, &ids),
                Output::Event(e) => tally.note(&e),
            }
        }
        if linked && last_submit.elapsed() >= TICK {
            last_submit = Instant::now();
            let control = [LEFT, RIGHT, ACT, 0][(node.state().next_submit % 4) as usize];
            let _ = node.submit(&[control as u8, (control >> 8) as u8]);
        }
        if last_status.elapsed() >= Duration::from_millis(100) {
            last_status = Instant::now();
            let s = node.state();
            println!(
                "STATUS {role} {} {} {}",
                s.certified_tick,
                tally.violations,
                u8::from(tally.caught_up)
            );
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// The child half: does nothing in a normal test run.
#[test]
fn player_process() {
    let (Ok(role), Ok(addr), Ok(dir)) = (
        std::env::var("AS_ROLE"),
        std::env::var("AS_ADDR"),
        std::env::var("AS_DIR"),
    ) else {
        return;
    };
    run_player(role.parse().unwrap(), &addr, Path::new(&dir));
}

// ---- the hub: witnesses and message relay, in the test process ---------------------------------

enum Hub {
    Joined(usize, TcpStream),
    Frame(usize, Vec<u8>),
    Left(usize),
}

fn accept_players(listener: TcpListener, tx: mpsc::Sender<Hub>) {
    for stream in listener.incoming().flatten() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut stream = stream;
            let Ok(hello) = read_frame(&mut stream) else {
                return;
            };
            let role = usize::from(hello[1]);
            let mut reader = stream.try_clone().unwrap();
            let _ = tx.send(Hub::Joined(role, stream));
            while let Ok(frame) = read_frame(&mut reader) {
                let _ = tx.send(Hub::Frame(role, frame));
            }
            let _ = tx.send(Hub::Left(role));
        });
    }
}

/// How the relay treats gameplay frames between players: a lossy, jittery, duplicating network.
/// Reordering follows from jitter. Control and witness frames are never impaired.
#[derive(Clone, Copy, Default)]
struct Impairment {
    drop_percent: u64,
    duplicate_percent: u64,
    delay_ms: u64,
    jitter_ms: u64,
}

/// A small deterministic generator, so an impaired run is repeatable.
struct Dice(u64);

impl Dice {
    fn roll(&mut self, below: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % below.max(1)
    }
}

struct Relay {
    links: Vec<Option<TcpStream>>,
    witnesses: Vec<RegisterWitness<FileCellStore>>,
    ids: Vec<[u8; 32]>,
    impairment: Impairment,
    dice: Dice,
    in_flight: Vec<(Instant, usize, Vec<u8>)>,
}

impl Relay {
    fn tell(&mut self, to: usize, body: &[u8]) {
        if let Some(link) = self.links[to].as_mut() {
            if write_frame(link, body).is_err() {
                self.links[to] = None;
            }
        }
    }

    fn joined(&mut self, role: usize, stream: TcpStream) {
        self.links[role] = Some(stream);
        let present: Vec<usize> = (0..PLAYERS)
            .filter(|o| *o != role && self.links[*o].is_some())
            .collect();
        for other in present {
            self.tell(role, &[PEER_UP, other as u8]);
            self.tell(other, &[PEER_UP, role as u8]);
        }
    }

    fn left(&mut self, role: usize) {
        self.links[role] = None;
        for other in (0..PLAYERS).filter(|o| *o != role) {
            self.tell(other, &[PEER_DOWN, role as u8]);
        }
    }

    fn member(&mut self, from: usize, frame: &[u8]) {
        let body = [&[MEMBER, from as u8][..], &frame[2..]].concat();
        match frame[1] {
            ALL => (0..PLAYERS)
                .filter(|o| *o != from)
                .for_each(|o| self.impaired(o, &body)),
            to => self.impaired(usize::from(to), &body),
        }
    }

    /// Hand a gameplay frame to the network model: it may be lost, delayed, or delivered twice.
    fn impaired(&mut self, to: usize, body: &[u8]) {
        let i = self.impairment;
        if self.dice.roll(100) < i.drop_percent {
            return;
        }
        let copies = 1 + usize::from(self.dice.roll(100) < i.duplicate_percent);
        for _ in 0..copies {
            let wait = Duration::from_millis(i.delay_ms + self.dice.roll(i.jitter_ms + 1));
            self.in_flight
                .push((Instant::now() + wait, to, body.to_vec()));
        }
        self.deliver_due();
    }

    fn deliver_due(&mut self) {
        let now = Instant::now();
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.in_flight)
            .into_iter()
            .partition(|(at, _, _)| *at <= now);
        self.in_flight = later;
        for (_, to, body) in due {
            self.tell(to, &body);
        }
    }

    fn witness(&mut self, from: usize, frame: &[u8]) {
        let target: [u8; 32] = frame[2..34].try_into().unwrap();
        let msg = match PipeMsg::decode(&frame[34..]) {
            Ok(PipeMsg::Quorum(m)) => m,
            _ => return,
        };
        let mut replies = Vec::new();
        for w in &mut self.witnesses {
            if frame[1] == 1 && target != w.id() {
                continue;
            }
            for reply in w.handle(MATCH, &msg) {
                let wire = PipeMsg::Quorum(reply).encode().unwrap();
                replies.push([&[WITNESS][..], &w.id(), &wire].concat());
            }
        }
        replies.iter().for_each(|r| self.tell(from, r));
    }

    fn handle(&mut self, event: Hub) {
        match event {
            Hub::Joined(role, stream) => self.joined(role, stream),
            Hub::Left(role) => self.left(role),
            Hub::Frame(from, frame) => match frame[0] {
                MEMBER => self.member(from, &frame),
                WITNESS => self.witness(from, &frame),
                _ => {}
            },
        }
    }
}

fn start_hub(dir: &Path, impairment: Impairment) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || accept_players(listener, tx));
    let witnesses = witness_keys()
        .into_iter()
        .enumerate()
        .map(|(i, k)| {
            RegisterWitness::new(k, FileCellStore::open(dir.join(format!("w{i}"))).unwrap())
        })
        .collect();
    let mut relay = Relay {
        links: (0..PLAYERS).map(|_| None).collect(),
        witnesses,
        ids: keys().iter().map(SigningKey::id).collect(),
        impairment,
        dice: Dice(0x9E37_79B9_7F4A_7C15),
        in_flight: Vec::new(),
    };
    std::thread::spawn(move || {
        debug_assert_eq!(relay.ids.len(), PLAYERS);
        loop {
            match rx.recv_timeout(Duration::from_millis(2)) {
                Ok(event) => relay.handle(event),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
            relay.deliver_due();
        }
    });
    addr
}

// ---- the test ---------------------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct Status {
    certified: u64,
    violations: usize,
    caught_up: bool,
}

type Statuses = Arc<Mutex<[Status; PLAYERS]>>;

struct Fleet {
    children: Vec<Option<Child>>,
    status: Statuses,
    addr: String,
    dir: PathBuf,
}

impl Fleet {
    fn start(&mut self, role: usize) {
        *self.status.lock().unwrap().get_mut(role).unwrap() = Status::default();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "player_process",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("AS_ROLE", role.to_string())
            .env("AS_ADDR", &self.addr)
            .env("AS_DIR", &self.dir)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let out = child.stdout.take().unwrap();
        let status = Arc::clone(&self.status);
        std::thread::spawn(move || watch(out, &status));
        self.children[role] = Some(child);
    }

    fn kill(&mut self, role: usize) {
        let mut child = self.children[role].take().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
    }

    fn status(&self, role: usize) -> Status {
        self.status.lock().unwrap()[role]
    }

    fn wait_until(&self, what: &str, done: impl Fn(&Fleet) -> bool) {
        let started = Instant::now();
        while !done(self) {
            assert!(
                started.elapsed() < PATIENCE,
                "timed out waiting for {what}: certified {:?}",
                self.status
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|s| s.certified)
                    .collect::<Vec<_>>()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Fleet {
    fn drop(&mut self) {
        for child in self.children.iter_mut().flatten() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn watch(out: impl Read, status: &Statuses) {
    use std::io::{BufRead, BufReader};
    for line in BufReader::new(out).lines().map_while(Result::ok) {
        let f: Vec<&str> = line.split(' ').collect();
        if f.len() != 5 || f[0] != "STATUS" {
            continue;
        }
        let (Ok(role), Ok(certified), Ok(violations)) =
            (f[1].parse::<usize>(), f[2].parse(), f[3].parse())
        else {
            continue;
        };
        status.lock().unwrap()[role] = Status {
            certified,
            violations,
            caught_up: f[4] == "1",
        };
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("as-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fleet(dir: &Path, impairment: Impairment) -> Fleet {
    Fleet {
        children: (0..PLAYERS).map(|_| None).collect(),
        status: Arc::default(),
        addr: start_hub(dir, impairment),
        dir: dir.to_path_buf(),
    }
}

fn assert_nobody_was_accused(fleet: &Fleet) {
    for r in 0..PLAYERS {
        assert_eq!(fleet.status(r).violations, 0, "player {r} saw a violation");
    }
}

#[test]
fn a_killed_and_restarted_player_process_rejoins_over_tcp_without_being_accused() {
    let dir = scratch("tcp");
    let mut fleet = fleet(&dir, Impairment::default());
    (0..PLAYERS).for_each(|r| fleet.start(r));
    fleet.wait_until("the group to play", |f| {
        (0..PLAYERS).all(|r| f.status(r).certified >= 60)
    });

    fleet.kill(2);
    let at_kill = fleet.status(0).certified;
    fleet.wait_until("the others to play on without the dead process", |f| {
        f.status(0).certified >= at_kill + 100 && f.status(1).certified >= at_kill + 100
    });
    let ahead = fleet.status(0).certified;

    fleet.start(2);
    fleet.wait_until("the restarted process to catch up", |f| {
        f.status(2).caught_up && f.status(2).certified >= ahead
    });
    let live = fleet.status(0).certified;
    fleet.wait_until("everyone to play on together", |f| {
        (0..PLAYERS).all(|r| f.status(r).certified > live + 60)
    });
    assert_nobody_was_accused(&fleet);
    drop(fleet);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Windows-friendly network impairment: real processes and sockets, with loss, duplication, latency,
/// jitter and reordering applied by the relay, so no `tc`/`netem` (and no WSL) is needed.
#[test]
fn players_keep_certifying_over_a_lossy_jittery_duplicating_network_without_accusations() {
    let dir = scratch("impaired");
    let mut fleet = fleet(
        &dir,
        Impairment {
            drop_percent: 5,
            duplicate_percent: 5,
            delay_ms: 30,
            jitter_ms: 60,
        },
    );
    (0..PLAYERS).for_each(|r| fleet.start(r));
    fleet.wait_until("the group to certify through the impairment", |f| {
        (0..PLAYERS).all(|r| f.status(r).certified >= 300)
    });
    assert_nobody_was_accused(&fleet);
    drop(fleet);
    let _ = std::fs::remove_dir_all(&dir);
}
