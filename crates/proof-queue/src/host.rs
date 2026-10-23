//! The proof queue as a browser host drives it: no threads, no file system. The page supplies the
//! clock and stores the journal itself (IndexedDB), draining [`HostQueue::take_writes`] after
//! every call that may have changed the queue and acknowledging callers only once stored.
use crate::verify::{
    pack, unpack, Commitments, Equivocation, RecoveryCertificates, Registry, SignedInputs,
};
use crate::{
    Config, Family, JobId, JobSpec, ManualClock, MatchStatus, OutboxJournal, Priority, Queue,
    Service, ServiceConfig, Write,
};
use gv_core::MatchId;
use gv_edge::quorum::WitnessSet;
use std::fmt::Write as _;
use std::sync::Arc;

const APPEND: u8 = 0;
const REWRITE: u8 = 1;

/// A clock the page sets on every call.
struct PageClock(Arc<ManualClock>);

impl crate::Clock for PageClock {
    fn now(&self) -> u64 {
        crate::Clock::now(&*self.0)
    }
}

pub struct HostQueue {
    service: Service,
    clock: Arc<ManualClock>,
    outbox: OutboxJournal,
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn match_id(b: &[u8]) -> Result<MatchId, String> {
    b.try_into().map_err(|_| "match id must be 32 bytes".into())
}

fn job_id(b: &[u8]) -> Option<JobId> {
    b.try_into().ok()
}

fn registry(witnesses: &[[u8; 32]]) -> Registry {
    let set = WitnessSet::new(witnesses);
    let base = Registry::new()
        .with(SignedInputs)
        .with(Commitments)
        .with(Equivocation {
            witnesses: set.clone(),
        });
    match set {
        Some(witnesses) => base.with(RecoveryCertificates { witnesses }),
        None => base,
    }
}

impl HostQueue {
    /// `stored` are the blobs [`HostQueue::take_writes`] produced earlier, oldest first;
    /// `witnesses` the pinned witness set (empty: none). `outbox_limit` bounds the writes waiting
    /// to be stored.
    pub fn open(
        stored: &[Vec<u8>],
        witnesses: &[[u8; 32]],
        now: u64,
        outbox_limit: u64,
    ) -> Result<Self, String> {
        let opened = OutboxJournal::open(replay(stored)?, outbox_limit);
        let outbox = opened.journal.clone();
        let queue = Queue::open(opened, Config::default(), now).map_err(|e| e.to_string())?;
        let clock = Arc::new(ManualClock::new(now));
        let service = Service::new(
            queue,
            registry(witnesses),
            Box::new(PageClock(Arc::clone(&clock))),
            ServiceConfig::default(),
        );
        Ok(Self {
            service,
            clock,
            outbox,
        })
    }

    /// Queue evidence; the returned job id is meaningful only once the writes are stored.
    pub fn submit(
        &self,
        family: u16,
        match_bytes: &[u8],
        payload: Vec<u8>,
        priority: u8,
        deadline: Option<u64>,
        now: u64,
    ) -> Result<JobId, String> {
        self.clock.set(now);
        let priority = match priority {
            0 => Priority::High,
            1 => Priority::Normal,
            _ => Priority::Low,
        };
        let spec = JobSpec {
            family: Family(family),
            match_id: match_id(match_bytes)?,
            payload,
            priority,
            deadline,
            deps: Vec::new(),
        };
        self.service
            .submit(spec)
            .map(|s| s.id())
            .map_err(|e| e.to_string())
    }

    /// Verify one batch of ready jobs; 0 means nothing was ready.
    pub fn step(&self, now: u64) -> Result<usize, String> {
        self.clock.set(now);
        self.service.step().map_err(|e| e.to_string())
    }

    /// The job's state code (see `JobState`), or `None` for an unknown job.
    pub fn state(&self, id: &[u8]) -> Option<u8> {
        let job = self.service.job(&job_id(id)?)?;
        Some(job.state as u8)
    }

    /// The match's aggregate status under the required evidence families.
    pub fn match_status(&self, match_bytes: &[u8], required: &[u16]) -> Result<String, String> {
        let required: Vec<Family> = required.iter().map(|f| Family(*f)).collect();
        let status = self
            .service
            .match_status(&match_id(match_bytes)?, &required);
        Ok(describe(&status))
    }

    /// Notifications after `cursor` as JSON: `{"gap":bool,"events":[{seq,at,job,match,family,state}]}`.
    pub fn events_after(&self, cursor: u64, limit: usize) -> String {
        let page = self.service.events_after(cursor, limit);
        let events: Vec<String> = page
            .events
            .iter()
            .map(|e| {
                format!(
                    "{{\"seq\":{},\"at\":{},\"job\":\"{}\",\"match\":\"{}\",\"family\":{},\"state\":{}}}",
                    e.seq,
                    e.at,
                    hex(&e.job),
                    hex(&e.match_id),
                    e.family.0,
                    e.state as u8
                )
            })
            .collect();
        format!("{{\"gap\":{},\"events\":[{}]}}", page.gap, events.join(","))
    }

    /// Everything the page must store, oldest first: each entry is a kind byte (0 append, 1
    /// replace everything) followed by the packed records.
    pub fn take_writes(&self) -> Vec<Vec<u8>> {
        self.outbox.take().iter().map(encode_write).collect()
    }
}

/// The records the stored blobs add up to: appends extend, a rewrite replaces everything.
fn replay(stored: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
    let mut records: Vec<Vec<u8>> = Vec::new();
    for blob in stored {
        let (kind, body) = blob.split_first().ok_or("empty stored write")?;
        let items = unpack(body).ok_or("corrupt stored write")?;
        let items = items.into_iter().map(<[u8]>::to_vec);
        match *kind {
            APPEND => records.extend(items),
            REWRITE => records = items.collect(),
            _ => return Err("unknown stored write kind".into()),
        }
    }
    Ok(records)
}

fn encode_write(w: &Write) -> Vec<u8> {
    let (kind, records) = match w {
        Write::Append(r) => (APPEND, r),
        Write::Rewrite(r) => (REWRITE, r),
    };
    let mut out = vec![kind];
    out.extend(pack(records));
    out
}

fn describe(status: &MatchStatus) -> String {
    match status {
        MatchStatus::Unknown => "unknown".into(),
        MatchStatus::Pending => "pending".into(),
        MatchStatus::Processing => "processing".into(),
        MatchStatus::Verified => "verified".into(),
        MatchStatus::Certified => "certified".into(),
        MatchStatus::Uncertified => "uncertified".into(),
        MatchStatus::Expired => "expired".into(),
        MatchStatus::Failed => "failed".into(),
        MatchStatus::ViolationProven { accused } => {
            let ids: Vec<String> = accused.iter().map(|a| hex(a)).collect();
            format!("violation:{}", ids.join(","))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HostQueue;
    use crate::verify::pack;
    use crate::Family;
    use gv_codec::{EventBatch, EventBody, SignedEventBatch};
    use gv_sig::SigningKey;

    const M: [u8; 32] = [7; 32];

    fn evidence() -> Vec<u8> {
        let k = SigningKey::from_seed([1; 32]);
        let batch = SignedEventBatch::sign(
            EventBatch {
                match_id: M,
                participant: k.id(),
                previous_batch_hash: [0; 32],
                start_tick: 0,
                tick_count: 20,
                body: EventBody::Held {
                    initial: vec![1, 0],
                    changes: vec![],
                },
            },
            &k,
        )
        .unwrap();
        pack(&[batch.encode().unwrap()])
    }

    fn open(stored: &[Vec<u8>]) -> HostQueue {
        HostQueue::open(stored, &[], 1_000, 1 << 20).unwrap()
    }

    fn submit(q: &HostQueue, payload: Vec<u8>) -> [u8; 32] {
        q.submit(Family::SIGNED_INPUTS.0, &M, payload, 1, None, 1_000)
            .unwrap()
    }

    #[test]
    fn evidence_is_verified_and_the_page_is_told_what_to_store() {
        let q = open(&[]);
        let id = submit(&q, evidence());
        assert_eq!(q.step(1_001).unwrap(), 1);
        assert_eq!(q.state(&id), Some(2), "verified");
        let (inputs, commitment) = (Family::SIGNED_INPUTS.0, Family::COMMITMENT.0);
        assert_eq!(q.match_status(&M, &[inputs]).unwrap(), "certified");
        assert_eq!(
            q.match_status(&M, &[inputs, commitment]).unwrap(),
            "verified",
            "a required family is still missing"
        );
        let writes = q.take_writes();
        assert!(!writes.is_empty() && writes.iter().all(|w| w[0] <= 1));
        assert!(q.take_writes().is_empty(), "drained once");
        let events = q.events_after(0, 10);
        assert!(
            events.contains("\"gap\":false") && events.contains("\"state\":2"),
            "{events}"
        );
    }

    #[test]
    fn a_queue_reopened_from_the_stored_blobs_has_the_same_jobs() {
        let q = open(&[]);
        let good = submit(&q, evidence());
        let bad = submit(&q, pack(&[vec![1u8, 2, 3]]));
        q.step(1_001).unwrap();
        let stored = q.take_writes();

        let again = open(&stored);
        assert_eq!(again.state(&good), q.state(&good));
        assert_eq!(again.state(&bad), q.state(&bad));
        assert_eq!(again.events_after(0, 100), q.events_after(0, 100));
    }

    #[test]
    fn bad_input_is_an_error_not_a_panic() {
        let q = open(&[]);
        assert!(q.submit(1, &[1, 2], vec![], 1, None, 1_000).is_err());
        assert!(q.match_status(&[1], &[]).is_err());
        assert_eq!(q.state(&[1, 2, 3]), None);
        for stored in [vec![vec![]], vec![vec![0, 1, 2]], vec![vec![9, 0, 0, 0, 0]]] {
            assert!(HostQueue::open(&stored, &[], 0, 1 << 20).is_err());
        }
    }

    #[test]
    fn a_page_that_never_stores_makes_the_queue_refuse_work() {
        let q = HostQueue::open(&[], &[], 1_000, 400).unwrap();
        let mut refused = false;
        for n in 0..50u8 {
            let r = q.submit(1, &M, pack(&[vec![n; 64]]), 1, None, 1_000);
            refused |= r.is_err();
        }
        assert!(refused, "outbox backpressure");
    }
}
