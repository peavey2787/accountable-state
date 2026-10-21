//! Windowed reliable, ordered delivery over a lossy datagram channel.
//!
//! Sequence-numbered frames, cumulative acknowledgements, go-back-N receive and
//! timer retransmission with an RTT-adaptive timeout. It is deliberately
//! independent of the network stack so loss and reordering can be tested.
//! The sender never blocks: gameplay queues a message and carries on.
#![forbid(unsafe_code)]
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

/// Floor for the retransmission timer. Under a burst the end-to-end service
/// time per message (Hydra + gossip) is a few milliseconds, so a timer shorter
/// than this retransmits frames that are merely queued, and the duplicates make
/// the queue longer.
const MIN_RTO: Duration = Duration::from_millis(150);
const INITIAL_RTO: Duration = Duration::from_millis(300);
const MAX_RTO: Duration = Duration::from_secs(1);
const DEFAULT_WINDOW: usize = 32;

struct Pending {
    seq: u64,
    payload: Vec<u8>,
    sent_at: Option<Instant>,
    first_sent: Option<Instant>,
    transmissions: u32,
}

pub struct Reliable {
    next_seq: u64,
    pending: VecDeque<Pending>,
    window: usize,
    rto: Duration,
    srtt: Option<Duration>,
    expected: u64,
    /// Out-of-order frames held until the gap before them fills.
    reorder: BTreeMap<u64, Vec<u8>>,
    ack_owed: bool,
    last_ack_seen: u64,
    dup_acks: u32,
    /// Oldest unacknowledged data is older than this => the peer is gone.
    pub retransmissions: u64,
}

impl Default for Reliable {
    fn default() -> Self {
        Self::new()
    }
}

impl Reliable {
    pub fn new() -> Self {
        Self {
            next_seq: 0,
            pending: VecDeque::new(),
            window: DEFAULT_WINDOW,
            rto: INITIAL_RTO,
            srtt: None,
            expected: 0,
            reorder: BTreeMap::new(),
            ack_owed: false,
            last_ack_seen: 0,
            dup_acks: 0,
            retransmissions: 0,
        }
    }
    /// Queue a message; it is transmitted by `poll_transmit`.
    pub fn queue(&mut self, payload: Vec<u8>) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.pending.push_back(Pending {
            seq,
            payload,
            sent_at: None,
            first_sent: None,
            transmissions: 0,
        });
        seq
    }
    pub fn in_flight(&self) -> usize {
        self.pending.len()
    }
    pub fn rto(&self) -> Duration {
        self.rto
    }
    /// How long the oldest unacknowledged message has been outstanding.
    pub fn oldest_outstanding(&self, now: Instant) -> Option<Duration> {
        self.pending
            .front()
            .and_then(|p| p.first_sent)
            .map(|t| now.saturating_duration_since(t))
    }
    /// Frames to put on the wire now: new ones, plus the oldest unacknowledged
    /// frame once its timer (with exponential backoff) expires. Only the head
    /// of the line is retransmitted: the receiver buffers early frames, so a
    /// single hole is all that can block delivery, and resending the whole
    /// window would just flood a link that is merely slow.
    /// `backoff` stretches the timer when the peer has gone silent.
    pub fn poll_transmit(&mut self, now: Instant, backoff: bool) -> Vec<(u64, Vec<u8>)> {
        let base = if backoff { MAX_RTO * 2 } else { self.rto };
        let mut out = Vec::new();
        for (i, p) in self.pending.iter_mut().take(self.window).enumerate() {
            let due = match p.sent_at {
                None => true,
                Some(at) => {
                    let doublings = p.transmissions.saturating_sub(1).min(2);
                    let timer = (base * (1u32 << doublings)).min(MAX_RTO * 2);
                    i == 0 && now.saturating_duration_since(at) >= timer
                }
            };
            if due {
                if p.transmissions > 0 {
                    self.retransmissions += 1;
                }
                p.sent_at = Some(now);
                p.first_sent.get_or_insert(now);
                p.transmissions += 1;
                out.push((p.seq, p.payload.clone()));
            }
        }
        out
    }
    /// Cumulative acknowledgement: every sequence below `next_expected` arrived.
    /// Two identical acks in a row mean the receiver keeps getting frames past a
    /// hole: resend the head at once instead of waiting for the timer.
    pub fn on_ack(&mut self, next_expected: u64, now: Instant) {
        if next_expected == self.last_ack_seen && !self.pending.is_empty() {
            self.dup_acks += 1;
            if self.dup_acks >= 2 {
                self.dup_acks = 0;
                if let Some(head) = self.pending.front_mut() {
                    if head.seq == next_expected {
                        head.sent_at = None;
                    }
                }
            }
        } else {
            self.dup_acks = 0;
        }
        self.last_ack_seen = self.last_ack_seen.max(next_expected);
        while self.pending.front().is_some_and(|p| p.seq < next_expected) {
            if let Some(p) = self.pending.pop_front() {
                // Karn: only unambiguous (never retransmitted) samples update RTT.
                if p.transmissions == 1 {
                    if let Some(at) = p.first_sent {
                        let sample = now.saturating_duration_since(at);
                        let srtt = self.srtt.map_or(sample, |s| (s * 7 + sample) / 8);
                        self.srtt = Some(srtt);
                        self.rto = (srtt * 2).clamp(MIN_RTO, MAX_RTO);
                    }
                }
            }
        }
    }
    /// A data frame arrived. Returns every payload that is now deliverable in
    /// order. Early frames are buffered (bounded); duplicates are dropped.
    /// Either way the peer is re-acknowledged.
    pub fn on_data(&mut self, seq: u64, payload: Vec<u8>) -> Vec<Vec<u8>> {
        self.ack_owed = true;
        if seq < self.expected || seq >= self.expected + (self.window as u64) * 2 {
            return Vec::new();
        }
        self.reorder.entry(seq).or_insert(payload);
        let mut ready = Vec::new();
        while let Some(p) = self.reorder.remove(&self.expected) {
            ready.push(p);
            self.expected += 1;
        }
        ready
    }
    pub fn take_ack(&mut self) -> Option<u64> {
        std::mem::take(&mut self.ack_owed).then_some(self.expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            // splitmix64: well mixed even when the call pattern is periodic.
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
    }

    #[test]
    fn delivers_everything_exactly_once_in_order_over_a_lossy_reordering_link() {
        for seed in 1..=20u64 {
            let mut rng = Lcg(seed);
            let (mut a, mut b) = (Reliable::new(), Reliable::new());
            let t0 = Instant::now();
            let mut delivered = Vec::new();
            // (deliver_at_ms, to_b, kind, seq, payload) ; kind 0 = data, 1 = ack
            let mut wire: Vec<(u64, bool, u8, u64, Vec<u8>)> = Vec::new();
            let total = 300u32;
            let mut queued = 0u32;
            for ms in 0..60_000u64 {
                let now = t0 + Duration::from_millis(ms);
                if ms % 7 == 0 && queued < total {
                    a.queue(queued.to_le_bytes().to_vec());
                    queued += 1;
                }
                for (seq, payload) in a.poll_transmit(now, false) {
                    if rng.next() % 100 >= 20 {
                        wire.push((ms + rng.next() % 40, true, 0, seq, payload));
                    }
                }
                if let Some(ack) = b.take_ack() {
                    if rng.next() % 100 >= 20 {
                        wire.push((ms + rng.next() % 40, false, 1, ack, Vec::new()));
                    }
                }
                let (due, rest): (Vec<_>, Vec<_>) = wire.drain(..).partition(|w| w.0 <= ms);
                wire = rest;
                for (_, to_b, kind, seq, payload) in due {
                    match (to_b, kind) {
                        (true, 0) => {
                            for p in b.on_data(seq, payload) {
                                delivered.push(u32::from_le_bytes(p.try_into().unwrap()));
                            }
                        }
                        (false, 1) => a.on_ack(seq, now),
                        _ => {}
                    }
                }
                if delivered.len() == total as usize && a.in_flight() == 0 {
                    break;
                }
            }
            assert_eq!(delivered, (0..total).collect::<Vec<_>>(), "seed {seed}");
            assert!(a.retransmissions > 0, "loss forces retransmission");
        }
    }

    #[test]
    fn timeout_adapts_to_the_round_trip_and_backoff_slows_retransmits() {
        let mut a = Reliable::new();
        let t0 = Instant::now();
        a.queue(vec![1]);
        assert_eq!(a.poll_transmit(t0, false).len(), 1);
        a.on_ack(1, t0 + Duration::from_millis(30));
        assert_eq!(
            a.rto(),
            Duration::from_millis(150),
            "timer never drops below the floor"
        );
        a.queue(vec![2]);
        let t1 = t0 + Duration::from_millis(100);
        assert_eq!(a.poll_transmit(t1, false).len(), 1);
        assert!(
            a.poll_transmit(t1 + Duration::from_millis(100), false)
                .is_empty(),
            "not yet due"
        );
        assert_eq!(
            a.poll_transmit(t1 + Duration::from_millis(200), false)
                .len(),
            1,
            "retransmitted"
        );
        // Exponential backoff: the second timeout takes twice as long.
        assert!(a
            .poll_transmit(t1 + Duration::from_millis(200 + 200), false)
            .is_empty());
        assert_eq!(
            a.poll_transmit(t1 + Duration::from_millis(200 + 320), false)
                .len(),
            1
        );
        // A silent peer is probed far less often.
        let mut b = Reliable::new();
        b.queue(vec![9]);
        assert_eq!(b.poll_transmit(t1, true).len(), 1);
        assert!(b
            .poll_transmit(t1 + Duration::from_millis(1500), true)
            .is_empty());
        assert_eq!(
            b.poll_transmit(t1 + Duration::from_millis(2100), true)
                .len(),
            1
        );
    }

    #[test]
    fn duplicates_are_dropped_and_gaps_are_filled_in_order() {
        let mut r = Reliable::new();
        assert_eq!(r.on_data(0, vec![1]), vec![vec![1]]);
        assert!(r.on_data(0, vec![1]).is_empty(), "duplicate");
        assert!(r.on_data(2, vec![9]).is_empty(), "early: buffered");
        assert_eq!(r.take_ack(), Some(1));
        assert_eq!(r.take_ack(), None);
        // The gap fills: both come out, in order.
        assert_eq!(r.on_data(1, vec![5]), vec![vec![5], vec![9]]);
        assert_eq!(r.take_ack(), Some(3));
        assert!(
            r.on_data(500, vec![0]).is_empty(),
            "far-future frames are refused"
        );
    }

    #[test]
    fn a_slow_burst_does_not_trigger_a_retransmission_storm() {
        // 20 frames sent at once; the receiver is just slow (10 ms each), not lossy.
        let mut a = Reliable::new();
        let mut b = Reliable::new();
        let t0 = Instant::now();
        for i in 0..20u8 {
            a.queue(vec![i]);
        }
        let mut wire: Vec<(u64, u64, Vec<u8>)> = a
            .poll_transmit(t0, false)
            .into_iter()
            .enumerate()
            .map(|(i, (seq, p))| (10 * (i as u64 + 1), seq, p))
            .collect();
        let mut delivered = 0;
        for ms in 1..1000u64 {
            let now = t0 + Duration::from_millis(ms);
            for (_, seq, p) in wire
                .iter()
                .filter(|w| w.0 == ms)
                .cloned()
                .collect::<Vec<_>>()
            {
                delivered += b.on_data(seq, p).len();
            }
            if let Some(ack) = b.take_ack() {
                a.on_ack(ack, now);
            }
            for (seq, p) in a.poll_transmit(now, false) {
                wire.push((ms + 10, seq, p));
            }
            if delivered == 20 {
                break;
            }
        }
        assert_eq!(delivered, 20);
        assert!(
            a.retransmissions <= 2,
            "no storm: {} retransmissions",
            a.retransmissions
        );
    }

    #[test]
    fn window_limits_what_is_in_flight() {
        let mut a = Reliable::new();
        for i in 0..100u8 {
            a.queue(vec![i]);
        }
        assert_eq!(a.poll_transmit(Instant::now(), false).len(), DEFAULT_WINDOW);
    }
}
