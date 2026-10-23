//! Counters and a latency histogram. Gauges (live jobs, journal size) come from
//! [`crate::queue::Stats`].
use crate::job::JobState;

const BUCKETS: usize = 40;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metrics {
    pub submitted: u64,
    pub duplicates: u64,
    pub resubmitted: u64,
    pub rejected_full: u64,
    pub rejected_invalid: u64,
    pub leased: u64,
    pub retries: u64,
    pub lapsed_leases: u64,
    pub gc_removed: u64,
    pub compactions: u64,
    /// Journal bytes dropped at open because they were torn or corrupt.
    pub truncated_bytes: u64,
    pub storage_errors: u64,
    finished: [u64; 8],
    /// Submit-to-finish time, one bucket per power of two ticks.
    latency: [u64; BUCKETS],
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            submitted: 0,
            duplicates: 0,
            resubmitted: 0,
            rejected_full: 0,
            rejected_invalid: 0,
            leased: 0,
            retries: 0,
            lapsed_leases: 0,
            gc_removed: 0,
            compactions: 0,
            truncated_bytes: 0,
            storage_errors: 0,
            finished: [0; 8],
            latency: [0; BUCKETS],
        }
    }
}

impl Metrics {
    pub fn finished(&self, state: JobState) -> u64 {
        self.finished[usize::from(state.code())]
    }

    pub(crate) fn record_finish(&mut self, state: JobState, latency: u64) {
        self.finished[usize::from(state.code())] += 1;
        let bucket = (u64::BITS - latency.leading_zeros()) as usize;
        self.latency[bucket.min(BUCKETS - 1)] += 1;
    }

    /// Upper bound (a power of two) of the `q`-quantile submit-to-finish latency.
    pub fn latency_quantile(&self, q: f64) -> u64 {
        let total: u64 = self.latency.iter().sum();
        let target = (total as f64 * q).ceil() as u64;
        let mut seen = 0;
        for (i, n) in self.latency.iter().enumerate() {
            seen += n;
            if seen >= target.max(1) {
                return if i == 0 { 0 } else { 1u64 << i.min(62) };
            }
        }
        0
    }
}
