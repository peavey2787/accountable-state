//! In-process N-peer network for the pipeline tests: per-link delay, per-peer clock skew, a drop
//! predicate, offline peers, and a scripted held input per participant. Peer `i` is roster slot `i`.
use super::msg::{Dest, Outgoing, PipeMsg};
use super::{PipeEvent, Pipeline, PipelineConfig, Violation};
use crate::fixtures::{controls, Cast};
use crate::testkit::{self as grid, GridRules};
use gv_core::MatchId;
use gv_replay::{step_tick, StateMachine};
use std::collections::VecDeque;

pub(crate) const MATCH: MatchId = [7; 32];

pub(crate) struct Peer {
    pub pipe: Pipeline<GridRules>,
    pub script: Vec<u16>,
    pub events: Vec<(u64, PipeEvent)>,
    pub sent: Vec<(u64, Outgoing)>,
}
/// `(sender, local tick, message)`: true drops the message on the wire.
pub(crate) type DropRule = Box<dyn Fn(usize, u64, &Outgoing) -> bool>;

pub(crate) struct Net {
    pub cast: Cast,
    pub peers: Vec<Peer>,
    /// `wire[i]` = `(deliver_at, sender, bytes)` travelling to peer `i`.
    wire: Vec<VecDeque<(u64, usize, Vec<u8>)>>,
    delay: u64,
    pub now: u64,
    /// Peer `i` runs on local tick `now - skew[i]`: its clock lags.
    pub skew: Vec<u64>,
    /// An offline peer neither runs nor receives.
    pub offline: Vec<bool>,
    pub drop: DropRule,
}

pub(crate) fn config() -> PipelineConfig {
    PipelineConfig::new(controls(0))
}

pub(crate) fn net(scripts: Vec<Vec<u16>>, cfg: PipelineConfig, delay: u64) -> Net {
    let cast = Cast::new(u8::try_from(scripts.len()).expect("peers"), MATCH);
    net_with(cast, scripts, cfg, delay)
}

pub(crate) fn net_with(cast: Cast, scripts: Vec<Vec<u16>>, cfg: PipelineConfig, delay: u64) -> Net {
    let n = scripts.len();
    let peers = scripts
        .into_iter()
        .enumerate()
        .map(|(i, script)| {
            let mut pipe =
                Pipeline::new(cast.keys[i].clone(), cast.replica(), cfg.clone()).expect("pipeline");
            pipe.auditor_mut().use_ephemeral_store_for_tests();
            Peer {
                pipe,
                script,
                events: Vec::new(),
                sent: Vec::new(),
            }
        })
        .collect();
    Net {
        cast,
        peers,
        wire: (0..n).map(|_| VecDeque::new()).collect(),
        delay,
        now: 0,
        skew: vec![0; n],
        offline: vec![false; n],
        drop: Box::new(|_, _, _| false),
    }
}

pub(crate) fn own_inputs(
    script: &[u16],
    now: u64,
) -> impl Fn(u64, u64) -> Option<Vec<Vec<u8>>> + '_ {
    move |from, to| {
        (to <= now).then(|| {
            (from..to)
                .map(|k| controls(script.get(k as usize).copied().unwrap_or(0)))
                .collect()
        })
    }
}

impl Net {
    pub fn run(&mut self, ticks: u64) {
        for _ in 0..ticks {
            self.now += 1;
            for i in 0..self.peers.len() {
                if !self.offline[i] {
                    self.step_peer(i);
                }
            }
        }
    }
    fn step_peer(&mut self, i: usize) {
        let now = self.now.saturating_sub(self.skew[i]);
        let script = self.peers[i].script.clone();
        let own = own_inputs(&script, now);
        self.peers[i].pipe.tick(now, &own);
        self.flush(i, now);
        while self.wire[i].front().is_some_and(|(at, ..)| *at <= self.now) {
            let (_, from, bytes) = self.wire[i].pop_front().expect("front");
            let msg = PipeMsg::decode(&bytes).expect("wire message decodes");
            let sender = self.cast.keys[from].id();
            self.peers[i].pipe.on_message(sender, msg, now, &own);
            self.flush(i, now);
        }
    }
    fn flush(&mut self, i: usize, now: u64) {
        while let Some(out) = self.peers[i].pipe.poll_outbox() {
            if !(self.drop)(i, now, &out) {
                self.route(i, &out);
            }
            self.peers[i].sent.push((now, out));
        }
        while let Some(e) = self.peers[i].pipe.poll_event() {
            self.peers[i].events.push((now, e));
        }
    }
    fn route(&mut self, from: usize, out: &Outgoing) {
        let bytes = out.msg.encode().expect("encodes");
        let at = self.now + self.delay;
        for to in 0..self.peers.len() {
            let wanted = match out.to {
                Dest::All => to != from,
                Dest::Peer(id) => self.cast.keys[to].id() == id,
            };
            if wanted && !self.offline[to] {
                self.wire[to].push_back((at, from, bytes.clone()));
            }
        }
    }
    /// Deliver a hand-made message to peer `to` as if `from` had sent it.
    pub fn inject(&mut self, to: usize, from: usize, msg: PipeMsg) {
        let now = self.now;
        let script = self.peers[to].script.clone();
        let own = own_inputs(&script, now);
        let sender = self.cast.keys[from].id();
        self.peers[to].pipe.on_message(sender, msg, now, &own);
        self.flush(to, now);
    }
    /// Put raw bytes on the wire to peer `to`, as if `from` had sent them.
    pub fn inject_wire(&mut self, to: usize, from: usize, bytes: Vec<u8>) {
        self.wire[to].push_back((self.now, from, bytes));
    }
    pub fn violations(&self, i: usize) -> Vec<&Violation> {
        self.peers[i]
            .events
            .iter()
            .filter_map(|(_, e)| match e {
                PipeEvent::Violation(v) => Some(v),
                _ => None,
            })
            .collect()
    }
    pub fn finalized(&self, i: usize) -> Vec<(u64, u64, bool)> {
        self.peers[i]
            .events
            .iter()
            .filter_map(|(_, e)| match e {
                PipeEvent::Finalized {
                    start,
                    end,
                    disputed,
                    ..
                } => Some((*start, *end, *disputed)),
                _ => None,
            })
            .collect()
    }
    /// Every listed peer certified the same epochs and holds the same verified state.
    pub fn agree(&self, among: &[usize]) -> bool {
        let first = among[0];
        among.iter().all(|&i| {
            self.finalized(i) == self.finalized(first)
                && self.peers[i].pipe.verified_state() == self.peers[first].pipe.verified_state()
        })
    }
}

/// The independent replay of the scripts for `ticks` ticks, through the shared replay engine.
pub(crate) fn reference(cast: &Cast, scripts: &[Vec<u16>], ticks: u64) -> Vec<u8> {
    let rules = GridRules;
    let mut state = rules.genesis(&cast.session);
    for t in 0..ticks {
        let payloads: Vec<Vec<u8>> = scripts
            .iter()
            .map(|s| controls(s.get(t as usize).copied().unwrap_or(0)))
            .collect();
        let inputs: Vec<Vec<&[u8]>> = payloads.iter().map(|p| vec![p.as_slice()]).collect();
        state = step_tick(
            &rules,
            &cast.session,
            state,
            t,
            &inputs,
            true,
            &mut Vec::new(),
        )
        .expect("replay");
    }
    state
}

pub(crate) fn held(c: u16, from: usize, to: usize, len: usize) -> Vec<u16> {
    let mut v = vec![0; len];
    for x in &mut v[from..to] {
        *x = c;
    }
    v
}

pub(crate) fn busy(seed: u64, ticks: usize) -> Vec<u16> {
    let mut s = seed | 1;
    let pool = [
        0,
        grid::LEFT,
        grid::RIGHT,
        grid::UP,
        grid::DOWN,
        grid::ACT,
        grid::HOLD,
        0,
        0,
    ];
    let mut out = Vec::new();
    while out.len() < ticks {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let c = pool[(s % pool.len() as u64) as usize];
        for _ in 0..1 + (s >> 20) % 12 {
            out.push(c);
        }
    }
    out.truncate(ticks);
    out
}
