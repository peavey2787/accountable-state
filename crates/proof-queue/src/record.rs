//! Journal records: every queue transition is one record, appended before it takes effect.
use crate::job::{Event, Family, Job, JobId, JobSpec, JobState, Priority};
use gv_core::MatchId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// A job as first accepted, or as kept by a compaction snapshot.
    Job(Box<Job>),
    Lease {
        id: JobId,
        until: u64,
    },
    Retry {
        id: JobId,
        not_before: u64,
        reason: String,
    },
    Requeue {
        id: JobId,
    },
    Finish {
        id: JobId,
        state: JobState,
        at: u64,
        reason: String,
        accused: Option<[u8; 32]>,
        evidence: Vec<u8>,
    },
    Remove {
        id: JobId,
    },
    /// An event kept by a compaction snapshot.
    Event(Event),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Malformed;

struct W(Vec<u8>);

impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn raw(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }
    fn bytes(&mut self, v: &[u8]) {
        self.u32(u32::try_from(v.len()).unwrap_or(u32::MAX));
        self.raw(v);
    }
}

struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        let (head, tail) = self.0.split_at_checked(n).ok_or(Malformed)?;
        self.0 = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, Malformed> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Malformed)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, Malformed> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| Malformed)?,
        ))
    }
    fn id(&mut self) -> Result<[u8; 32], Malformed> {
        self.take(32)?.try_into().map_err(|_| Malformed)
    }
    fn bytes(&mut self) -> Result<Vec<u8>, Malformed> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn string(&mut self) -> Result<String, Malformed> {
        String::from_utf8(self.bytes()?).map_err(|_| Malformed)
    }
    fn state(&mut self) -> Result<JobState, Malformed> {
        JobState::from_code(self.u8()?).ok_or(Malformed)
    }
    fn done(&self) -> Result<(), Malformed> {
        self.0.is_empty().then_some(()).ok_or(Malformed)
    }
}

fn put_job(w: &mut W, j: &Job) {
    let s = &j.spec;
    w.u16_family(s.family);
    w.raw(&s.match_id);
    w.bytes(&s.payload);
    w.u8(s.priority as u8);
    w.u64(s.deadline.map_or(0, |d| d.max(1)));
    w.u8(u8::from(s.deadline.is_some()));
    w.u32(u32::try_from(s.deps.len()).unwrap_or(0));
    s.deps.iter().for_each(|d| w.raw(d));
    w.u8(j.state.code());
    w.u32(j.attempts);
    w.u64(j.submitted_at);
    w.u64(j.finished_at);
    w.u64(j.not_before);
    w.bytes(j.reason.as_bytes());
    put_opt_id(w, j.accused);
    w.bytes(&j.evidence);
    w.u64(j.seq);
}

impl W {
    fn u16_family(&mut self, f: Family) {
        self.0.extend_from_slice(&f.0.to_le_bytes());
    }
}

fn put_opt_id(w: &mut W, v: Option<[u8; 32]>) {
    w.u8(u8::from(v.is_some()));
    w.raw(&v.unwrap_or([0; 32]));
}

fn get_opt_id(r: &mut R<'_>) -> Result<Option<[u8; 32]>, Malformed> {
    let present = r.u8()? == 1;
    let id = r.id()?;
    Ok(present.then_some(id))
}

fn get_family(r: &mut R<'_>) -> Result<Family, Malformed> {
    Ok(Family(u16::from_le_bytes(
        r.take(2)?.try_into().map_err(|_| Malformed)?,
    )))
}

fn get_job(r: &mut R<'_>) -> Result<Job, Malformed> {
    let family = get_family(r)?;
    let match_id: MatchId = r.id()?;
    let payload = r.bytes()?;
    let priority = Priority::from_u8(r.u8()?).ok_or(Malformed)?;
    let deadline_value = r.u64()?;
    let has_deadline = r.u8()? == 1;
    let n = r.u32()? as usize;
    let deps = (0..n).map(|_| r.id()).collect::<Result<Vec<_>, _>>()?;
    let spec = JobSpec {
        family,
        match_id,
        payload,
        priority,
        deadline: has_deadline.then_some(deadline_value),
        deps,
    };
    Ok(Job {
        id: spec.id(),
        spec,
        state: r.state()?,
        attempts: r.u32()?,
        submitted_at: r.u64()?,
        finished_at: r.u64()?,
        not_before: r.u64()?,
        lease_until: 0,
        reason: r.string()?,
        accused: get_opt_id(r)?,
        evidence: r.bytes()?,
        seq: r.u64()?,
    })
}

impl Record {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        match self {
            Self::Job(j) => {
                w.u8(1);
                put_job(&mut w, j);
            }
            Self::Lease { id, until } => {
                w.u8(2);
                w.raw(id);
                w.u64(*until);
            }
            Self::Retry {
                id,
                not_before,
                reason,
            } => {
                w.u8(3);
                w.raw(id);
                w.u64(*not_before);
                w.bytes(reason.as_bytes());
            }
            Self::Requeue { id } => {
                w.u8(4);
                w.raw(id);
            }
            Self::Finish {
                id,
                state,
                at,
                reason,
                accused,
                evidence,
            } => {
                w.u8(5);
                w.raw(id);
                w.u8(state.code());
                w.u64(*at);
                w.bytes(reason.as_bytes());
                put_opt_id(&mut w, *accused);
                w.bytes(evidence);
            }
            Self::Remove { id } => {
                w.u8(6);
                w.raw(id);
            }
            Self::Event(e) => {
                w.u8(7);
                w.u64(e.seq);
                w.u64(e.at);
                w.raw(&e.job);
                w.raw(&e.match_id);
                w.u16_family(e.family);
                w.u8(e.state.code());
            }
        }
        w.0
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Malformed> {
        let mut r = R(bytes);
        let rec = match r.u8()? {
            1 => Self::Job(Box::new(get_job(&mut r)?)),
            2 => Self::Lease {
                id: r.id()?,
                until: r.u64()?,
            },
            3 => Self::Retry {
                id: r.id()?,
                not_before: r.u64()?,
                reason: r.string()?,
            },
            4 => Self::Requeue { id: r.id()? },
            5 => Self::Finish {
                id: r.id()?,
                state: r.state()?,
                at: r.u64()?,
                reason: r.string()?,
                accused: get_opt_id(&mut r)?,
                evidence: r.bytes()?,
            },
            6 => Self::Remove { id: r.id()? },
            7 => Self::Event(Event {
                seq: r.u64()?,
                at: r.u64()?,
                job: r.id()?,
                match_id: r.id()?,
                family: get_family(&mut r)?,
                state: r.state()?,
            }),
            _ => return Err(Malformed),
        };
        r.done()?;
        Ok(rec)
    }
}
