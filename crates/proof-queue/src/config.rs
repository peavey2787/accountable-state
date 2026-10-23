//! Queue limits and policies. Times are ticks of whatever clock the service runs on
//! (milliseconds for [`crate::service::SystemClock`]).
#[derive(Clone, Debug)]
pub struct Config {
    /// Jobs not yet finished, across all matches.
    pub max_live: usize,
    /// Unfinished jobs of one match, so one flooded match cannot starve the rest.
    pub max_live_per_match: usize,
    /// Jobs kept in memory and on disk, finished ones included (until collected).
    pub max_retained: usize,
    pub max_payload: usize,
    /// Capacity held back for `High` priority: `Normal` is refused this far below `max_live`,
    /// `Low` twice as far.
    pub high_reserve: usize,
    /// How long a worker may hold a job before it is handed to another.
    pub lease_ticks: u64,
    /// Attempts (leases) before a job that keeps failing is given up on.
    pub max_attempts: u32,
    pub retry_base: u64,
    pub retry_cap: u64,
    /// How long a finished job stays queryable before collection. Jobs that proved a violation
    /// stay until the application forgets them.
    pub retention: u64,
    /// Notifications kept for subscribers.
    pub max_events: usize,
    /// The journal is compacted once it is at least this large and has doubled since the last
    /// compaction.
    pub compact_min_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_live: 100_000,
            max_live_per_match: 10_000,
            max_retained: 200_000,
            max_payload: 1 << 20,
            high_reserve: 1_000,
            lease_ticks: 60_000,
            max_attempts: 5,
            retry_base: 1_000,
            retry_cap: 60_000,
            retention: 3_600_000,
            max_events: 100_000,
            compact_min_bytes: 8 << 20,
        }
    }
}
