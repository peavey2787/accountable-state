//! Per-peer ingress budget. A peer that floods cannot make this node spend unbounded memory or
//! verification time on it, and the refusal is reported to the caller (who can drop the link), never
//! swallowed. Evidence of misbehavior is exempt from the rate budget: it is size-bounded by its
//! decoder and is exactly what a hostile peer would want us to drop.
use crate::io::{Peer, ReceiveError};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Message tag of relayed misbehavior proofs (`PipeMsg::Evidence`).
const EVIDENCE_TAG: u8 = 11;
/// Message tag of reconnection traffic (`PipeMsg::Resume`): a peer can ask for megabytes of
/// history per message, so it has its own, much smaller, budget.
const RESUME_TAG: u8 = 15;
/// More distinct peers than any roster plus its witnesses; everyone beyond shares one bucket.
const MAX_TRACKED: usize = 256;

/// What a peer may send per window. Bytes bound bandwidth and memory, whole messages bound the
/// signature work they trigger, and malformed bytes (rejected cheaply, before any signature check)
/// have their own, much larger allowance so garbage cannot crowd out the same peer's real traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IngressLimits {
    /// Largest accepted message, checked before it is decoded.
    pub max_message: usize,
    pub window: Duration,
    pub bytes_per_window: usize,
    pub messages_per_window: u32,
    pub malformed_per_window: u32,
    pub resume_per_window: u32,
}

impl Default for IngressLimits {
    fn default() -> Self {
        Self {
            max_message: 32 << 20,
            window: Duration::from_secs(1),
            bytes_per_window: 64 << 20,
            messages_per_window: 4096,
            malformed_per_window: 65_536,
            resume_per_window: 32,
        }
    }
}

#[derive(Clone, Copy)]
struct Window {
    start: Instant,
    bytes: usize,
    messages: u32,
    malformed: u32,
    resume: u32,
}

impl Window {
    fn new(start: Instant) -> Self {
        Self {
            start,
            bytes: 0,
            messages: 0,
            malformed: 0,
            resume: 0,
        }
    }
}

pub(crate) struct Ingress {
    limits: IngressLimits,
    clock: Instant,
    peers: HashMap<(bool, [u8; 32]), Window>,
}

impl Ingress {
    pub(crate) fn new(limits: IngressLimits) -> Self {
        Self {
            limits,
            clock: Instant::now(),
            peers: HashMap::new(),
        }
    }

    pub(crate) fn set_limits(&mut self, limits: IngressLimits) {
        self.limits = limits;
    }

    /// The node's notion of now: advanced by the host through `poll`, never read from the system,
    /// so behavior is reproducible.
    pub(crate) fn advance(&mut self, now: Instant) {
        self.clock = self.clock.max(now);
        let window = self.limits.window;
        let clock = self.clock;
        self.peers
            .retain(|_, w| clock.saturating_duration_since(w.start) < window);
    }

    /// Before decoding: size and bandwidth. Evidence is exempt from the bandwidth budget.
    pub(crate) fn admit(&mut self, from: Peer, bytes: &[u8]) -> Result<(), ReceiveError> {
        if bytes.len() > self.limits.max_message {
            return Err(ReceiveError::TooLarge);
        }
        if bytes.first() == Some(&EVIDENCE_TAG) {
            return Ok(());
        }
        let limit = self.limits.bytes_per_window;
        let w = self.window(from);
        w.bytes = w.bytes.saturating_add(bytes.len());
        refuse_if(w.bytes > limit)
    }

    /// After a successful decode: the message will cost signature work.
    pub(crate) fn charge(&mut self, from: Peer, tag: u8) -> Result<(), ReceiveError> {
        if tag == EVIDENCE_TAG {
            return Ok(());
        }
        let (messages, resume) = (
            self.limits.messages_per_window,
            self.limits.resume_per_window,
        );
        let w = self.window(from);
        w.messages = w.messages.saturating_add(1);
        w.resume = w.resume.saturating_add(u32::from(tag == RESUME_TAG));
        refuse_if(w.messages > messages || w.resume > resume)
    }

    /// A message that failed to decode. Reported as malformed until the peer sends so many that
    /// it is plainly a flood.
    pub(crate) fn malformed(&mut self, from: Peer) -> ReceiveError {
        let limit = self.limits.malformed_per_window;
        let w = self.window(from);
        w.malformed = w.malformed.saturating_add(1);
        if w.malformed > limit {
            ReceiveError::Throttled
        } else {
            ReceiveError::Malformed
        }
    }

    fn window(&mut self, from: Peer) -> &mut Window {
        let (witness, id) = match from {
            Peer::Member(id) => (false, id),
            Peer::Witness(id) => (true, id),
        };
        let key = if self.peers.len() >= MAX_TRACKED && !self.peers.contains_key(&(witness, id)) {
            (witness, [0; 32])
        } else {
            (witness, id)
        };
        let clock = self.clock;
        let limit = self.limits.window;
        let w = self.peers.entry(key).or_insert_with(|| Window::new(clock));
        if clock.saturating_duration_since(w.start) >= limit {
            *w = Window::new(clock);
        }
        w
    }
}

fn refuse_if(over: bool) -> Result<(), ReceiveError> {
    if over {
        Err(ReceiveError::Throttled)
    } else {
        Ok(())
    }
}
