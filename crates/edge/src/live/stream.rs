//! Continuous, loss-tolerant input streaming between participants.
//!
//! A frame carries the sender's held input state for a span of ticks as a run-length list of
//! *changes*, plus a cumulative acknowledgement of what the sender has received from the
//! receiver. Frames are idempotent and redundant: every frame repeats all changes the peer has
//! not yet acknowledged, so a lost or reordered datagram costs nothing. Frames are unsigned
//! hints that let a peer predict and roll back in real time; the non-repudiable record is the
//! signed epoch batch that the checkpoint pipeline exchanges later. The input state is an
//! application-defined byte string of constant width (at most [`MAX_HELD_WIDTH`]).
use gv_codec::MAX_HELD_WIDTH;
use std::collections::VecDeque;

const MAGIC: u8 = 0x54;
const VERSION: u8 = 2;
const HEADER: usize = 2 + 8 + 8 + 8 + 1 + 2;
pub const MAX_SPAN: u64 = 4096;
const MAX_CHANGES: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamFrame {
    /// Inputs cover ticks `from_tick..through_tick`.
    pub from_tick: u64,
    pub through_tick: u64,
    pub initial: Vec<u8>,
    /// `(offset from from_tick, new input)`, strictly increasing offsets, each as wide as
    /// `initial`.
    pub changes: Vec<(u32, Vec<u8>)>,
    /// Sender has authoritative input of the receiver for every tick below this.
    pub ack_through: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    Malformed,
    TooLarge,
}

impl StreamFrame {
    pub fn validate(&self) -> Result<(), StreamError> {
        let span = self
            .through_tick
            .checked_sub(self.from_tick)
            .ok_or(StreamError::Malformed)?;
        if span == 0
            || span > MAX_SPAN
            || self.changes.len() > MAX_CHANGES
            || self.initial.len() > MAX_HELD_WIDTH
        {
            return Err(StreamError::TooLarge);
        }
        let mut previous = (0u32, &self.initial);
        for (offset, state) in &self.changes {
            if *offset <= previous.0
                || u64::from(*offset) >= span
                || *state == *previous.1
                || state.len() != self.initial.len()
            {
                return Err(StreamError::Malformed);
            }
            previous = (*offset, state);
        }
        Ok(())
    }
    pub fn encode(&self) -> Vec<u8> {
        let width = self.initial.len();
        let mut out =
            Vec::with_capacity(HEADER + width * (1 + self.changes.len()) + self.changes.len() * 4);
        out.push(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.from_tick.to_le_bytes());
        out.extend_from_slice(&self.through_tick.to_le_bytes());
        out.extend_from_slice(&self.ack_through.to_le_bytes());
        out.push(width as u8);
        out.extend_from_slice(&(self.changes.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.initial);
        for (offset, state) in &self.changes {
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(state);
        }
        out
    }
    pub fn decode(b: &[u8]) -> Result<Self, StreamError> {
        if b.len() < HEADER || b[0] != MAGIC || b[1] != VERSION {
            return Err(StreamError::Malformed);
        }
        let u64_at = |p: usize| u64::from_le_bytes(b[p..p + 8].try_into().unwrap_or([0; 8]));
        let width = usize::from(b[26]);
        let count = usize::from(u16::from_le_bytes([b[27], b[28]]));
        if width > MAX_HELD_WIDTH
            || count > MAX_CHANGES
            || b.len() != HEADER + width + count * (4 + width)
        {
            return Err(StreamError::Malformed);
        }
        let body = &b[HEADER..];
        let (initial, rest) = body.split_at(width);
        let changes = rest
            .chunks_exact(4 + width)
            .map(|c| {
                (
                    u32::from_le_bytes([c[0], c[1], c[2], c[3]]),
                    c[4..].to_vec(),
                )
            })
            .collect();
        let frame = Self {
            from_tick: u64_at(2),
            through_tick: u64_at(10),
            ack_through: u64_at(18),
            initial: initial.to_vec(),
            changes,
        };
        frame.validate()?;
        Ok(frame)
    }
    /// The per-tick inputs this frame describes.
    pub fn expand(&self) -> Vec<Vec<u8>> {
        let span = (self.through_tick - self.from_tick) as usize;
        let mut out = Vec::with_capacity(span);
        let mut current = &self.initial;
        let mut next = self.changes.iter().peekable();
        for k in 0..span {
            while let Some((offset, state)) = next.peek() {
                if *offset as usize != k {
                    break;
                }
                current = state;
                next.next();
            }
            out.push(current.clone());
        }
        out
    }
    pub fn from_inputs(from_tick: u64, inputs: &[Vec<u8>], ack_through: u64) -> Self {
        let initial = inputs.first().cloned().unwrap_or_default();
        let mut changes = Vec::new();
        let mut previous = &initial;
        for (k, c) in inputs.iter().enumerate().skip(1) {
            if c != previous {
                changes.push((k as u32, c.clone()));
                previous = c;
            }
        }
        Self {
            from_tick,
            through_tick: from_tick + inputs.len() as u64,
            initial,
            changes,
            ack_through,
        }
    }
}

/// Decides when a frame is worth sending to one peer. Idle participants send (almost) nothing.
pub struct StreamSender {
    log: VecDeque<Vec<u8>>,
    /// Tick of `log[0]`.
    log_from: u64,
    peer_ack: u64,
    last_sent_tick: Option<u64>,
    /// Highest tick whose input has been included in some sent frame.
    sent_through: u64,
    needs_ack: bool,
    keepalive: u64,
    resend: u64,
    blackout: Option<(u64, u64)>,
}

impl StreamSender {
    pub fn new(start_tick: u64, keepalive_ticks: u64, resend_ticks: u64) -> Self {
        Self {
            log: VecDeque::new(),
            log_from: start_tick,
            peer_ack: start_tick,
            last_sent_tick: None,
            sent_through: start_tick,
            needs_ack: false,
            keepalive: keepalive_ticks,
            resend: resend_ticks,
            blackout: None,
        }
    }
    /// Suppress streaming for `[from, to)`: those ticks are sealed and are only ever disclosed
    /// through the commit-reveal path.
    pub fn set_blackout(&mut self, window: Option<(u64, u64)>) {
        self.blackout = window;
    }
    fn next_tick(&self) -> u64 {
        self.log_from + self.log.len() as u64
    }
    pub fn push(&mut self, input: Vec<u8>) {
        self.log.push_back(input);
    }
    pub fn on_peer_ack(&mut self, ack_through: u64) {
        self.peer_ack = self.peer_ack.max(ack_through);
        // Keep one tick before the ack so the first input of a frame is known.
        while self.log_from + 1 < self.peer_ack.min(self.next_tick()) && self.log.len() > 1 {
            self.log.pop_front();
            self.log_from += 1;
        }
    }
    /// Something arrived from the peer that deserves an acknowledgement.
    pub fn note_received(&mut self) {
        self.needs_ack = true;
    }
    fn input_at(&self, tick: u64) -> Option<&Vec<u8>> {
        tick.checked_sub(self.log_from)
            .and_then(|i| self.log.get(i as usize))
    }
    /// The unacknowledged spans, split around the blackout.
    fn spans(&self, next: u64) -> Vec<(u64, u64)> {
        let mut lo = self
            .peer_ack
            .max(self.log_from)
            .max(next.saturating_sub(MAX_SPAN));
        if lo >= next {
            // Nothing unacknowledged: describe only the newest tick.
            lo = next - 1;
        }
        let mut spans = Vec::new();
        match self.blackout {
            Some((a, b)) => {
                if lo < a {
                    spans.push((lo, next.min(a)));
                }
                if next > b {
                    spans.push((lo.max(b), next));
                }
            }
            None => spans.push((lo, next)),
        }
        spans.retain(|(s, e)| s < e);
        spans
    }
    /// Whether any sent-worthy change exists: `(important, unacked_change)`; `None` when a
    /// needed input is no longer in the log.
    fn changes(&self, spans: &[(u64, u64)], next: u64) -> Option<(bool, bool)> {
        let mut important = self
            .blackout
            .is_some_and(|(_, b)| next > b && self.sent_through <= b);
        let mut unacked_change = false;
        for (start, end) in spans {
            let mut prev = start.checked_sub(1).and_then(|t| self.input_at(t));
            for t in *start..*end {
                let c = self.input_at(t)?;
                let changed = prev.is_some_and(|p| p != c);
                important |= changed && t >= self.sent_through;
                unacked_change |= changed && t >= self.peer_ack;
                prev = Some(c);
            }
        }
        Some((important, unacked_change))
    }
    /// Frames worth sending now (usually none). A frame never describes a tick inside the
    /// blackout, so a span that straddles it is split in two.
    pub fn due(&mut self, now_tick: u64, ack_through: u64) -> Vec<StreamFrame> {
        let next = self.next_tick();
        if next <= self.log_from {
            return Vec::new();
        }
        let spans = self.spans(next);
        if spans.is_empty() {
            return Vec::new();
        }
        let Some((important, unacked_change)) = self.changes(&spans, next) else {
            return Vec::new();
        };
        let since = now_tick.saturating_sub(self.last_sent_tick.unwrap_or(0));
        let send = important
            || self.needs_ack
            || (unacked_change && since >= self.resend)
            || self.last_sent_tick.is_none_or(|_| since >= self.keepalive);
        if !send {
            return Vec::new();
        }
        let frames: Vec<StreamFrame> = spans
            .iter()
            .filter_map(|(start, end)| {
                let inputs: Option<Vec<Vec<u8>>> =
                    (*start..*end).map(|t| self.input_at(t).cloned()).collect();
                inputs.map(|c| StreamFrame::from_inputs(*start, &c, ack_through))
            })
            .collect();
        if !frames.is_empty() {
            self.last_sent_tick = Some(now_tick);
            self.sent_through = self
                .sent_through
                .max(spans.iter().map(|(_, e)| *e).max().unwrap_or(0));
            self.needs_ack = false;
        }
        frames
    }
}
