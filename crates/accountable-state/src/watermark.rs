//! What this participant has ever released: the tick up to which it signed input batches, and the
//! batches themselves (the most recent ones). A batch is recorded durably before it
//! leaves, so a restarted process resumes after it: re-signing a tick it already signed, with
//! different inputs, would be equivocation by an honest player. The recorded batches are sent again
//! on restart (the same bytes, never a new signature), so an epoch still certifies when every
//! process of a match died in the middle of it.
use crate::config::DurableStorage;
use crate::io::OpenError;
use gv_codec::SignedEventBatch;
use gv_core::ParticipantId;
use gv_edge::audit::fsync::replace_file;
use gv_edge::live::PipeMsg;
use std::io;
use std::path::PathBuf;

const SUFFIX: &str = ".signed-through";
const MARK: usize = 8;
const LENGTH: usize = 4;
/// How many released batches are kept: enough to replay several epochs when a match is resumed
/// from an earlier shared point.
const RETAINED: usize = 16;

pub(crate) struct Watermark {
    path: PathBuf,
    through: u64,
    batches: Vec<SignedEventBatch>,
}

fn end_of(b: &SignedEventBatch) -> u64 {
    b.record.start_tick + u64::from(b.record.tick_count)
}

fn encode(through: u64, batches: &[SignedEventBatch]) -> io::Result<Vec<u8>> {
    let mut out = through.to_le_bytes().to_vec();
    for b in batches {
        let bytes = b.encode().map_err(|e| io::Error::other(format!("{e:?}")))?;
        let len = u32::try_from(bytes.len()).map_err(io::Error::other)?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

fn decode(bytes: &[u8]) -> Option<(u64, Vec<SignedEventBatch>)> {
    let (mark, mut rest) = bytes.split_at_checked(MARK)?;
    let through = u64::from_le_bytes(mark.try_into().ok()?);
    let mut batches = Vec::new();
    while !rest.is_empty() {
        let (len, tail) = rest.split_at_checked(LENGTH)?;
        let len = usize::try_from(u32::from_le_bytes(len.try_into().ok()?)).ok()?;
        let (body, tail) = tail.split_at_checked(len)?;
        batches.push(SignedEventBatch::decode(body).ok()?);
        rest = tail;
    }
    Some((through, batches))
}

impl Watermark {
    /// A missing file means nothing was ever released; a corrupt one is an error (guessing low
    /// could re-sign a released tick).
    pub(crate) fn open(storage: &DurableStorage) -> Result<Self, OpenError> {
        let path = storage.file(SUFFIX);
        let fail = |e: String| OpenError::Storage {
            file: path.display().to_string(),
            error: e,
        };
        let (through, batches) = match std::fs::read(&path) {
            Ok(b) => decode(&b).ok_or_else(|| fail("corrupt signed-through mark".into()))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => (0, Vec::new()),
            Err(e) => return Err(fail(e.to_string())),
        };
        Ok(Self {
            path,
            through,
            batches,
        })
    }

    pub(crate) fn through(&self) -> u64 {
        self.through
    }

    /// The most recent released batches, oldest first.
    pub(crate) fn retained(&self) -> &[SignedEventBatch] {
        &self.batches
    }

    /// Record, durably, that `msg` is about to be released. Only my own batches count. An error
    /// means the batch must not leave: it could not be remembered.
    pub(crate) fn before_release(&mut self, msg: &PipeMsg, me: &ParticipantId) -> io::Result<()> {
        let PipeMsg::Batch(b) = msg else {
            return Ok(());
        };
        if b.record.participant != *me || self.batches.iter().any(|x| x.record == b.record) {
            return Ok(());
        }
        let mut batches = self.batches.clone();
        batches.push(b.clone());
        let surplus = batches.len().saturating_sub(RETAINED);
        batches.drain(..surplus);
        let through = self.through.max(end_of(b));
        replace_file(&self.path, &encode(through, &batches)?)?;
        self.through = through;
        self.batches = batches;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gv_codec::{EventBatch, EventBody, SignedEventBatch};
    use gv_sig::SigningKey;

    fn batch(key: &SigningKey, start: u64) -> PipeMsg {
        let signed = SignedEventBatch::sign(
            EventBatch {
                match_id: [1; 32],
                participant: key.id(),
                previous_batch_hash: [0; 32],
                start_tick: start,
                tick_count: 20,
                body: EventBody::Held {
                    initial: vec![0, 0],
                    changes: vec![],
                },
            },
            key,
        )
        .unwrap();
        PipeMsg::Batch(signed)
    }

    #[test]
    fn my_released_batches_are_remembered_across_opens_and_only_they_count() {
        let dir = std::env::temp_dir().join(format!("gv-wm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let storage = DurableStorage::at(dir.join("node"));
        let (me, other) = (
            SigningKey::from_seed([1; 32]),
            SigningKey::from_seed([2; 32]),
        );

        let mut w = Watermark::open(&storage).unwrap();
        assert_eq!(w.through(), 0);
        w.before_release(&batch(&me, 0), &me.id()).unwrap();
        assert_eq!(w.through(), 20);
        w.before_release(&batch(&other, 100), &me.id()).unwrap();
        assert_eq!(w.through(), 20, "someone else's batch is not mine");
        w.before_release(&batch(&me, 0), &me.id()).unwrap();
        assert_eq!(w.through(), 20, "a resent batch does not move it");
        w.before_release(&PipeMsg::AnchorReq, &me.id()).unwrap();
        w.before_release(&batch(&me, 20), &me.id()).unwrap();
        assert_eq!(w.through(), 40);

        assert_eq!(Watermark::open(&storage).unwrap().through(), 40);
        std::fs::write(storage.file(SUFFIX), b"xx").unwrap();
        assert!(Watermark::open(&storage).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn ends(w: &Watermark) -> Vec<u64> {
        w.retained().iter().map(end_of).collect()
    }

    #[test]
    fn released_batches_are_kept_in_order_and_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("gv-wm-keep-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let storage = DurableStorage::at(dir.join("node"));
        let me = SigningKey::from_seed([1; 32]);
        let mut w = Watermark::open(&storage).unwrap();
        w.before_release(&batch(&me, 0), &me.id()).unwrap();
        w.before_release(&batch(&me, 0), &me.id()).unwrap();
        assert_eq!(ends(&w), vec![20], "a resent batch is stored once");
        w.before_release(&batch(&me, 20), &me.id()).unwrap();
        assert_eq!(ends(&w), vec![20, 40]);
        assert_eq!(ends(&Watermark::open(&storage).unwrap()), vec![20, 40]);

        for n in 2..(RETAINED as u64 + 3) {
            w.before_release(&batch(&me, n * 20), &me.id()).unwrap();
        }
        assert_eq!(
            w.retained().len(),
            RETAINED,
            "only the most recent are kept"
        );
        assert_eq!(w.through(), (RETAINED as u64 + 3) * 20);
        assert_eq!(w.retained().last().map(end_of), Some(w.through()));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_truncated_batch_record_is_a_corrupt_mark() {
        let dir = std::env::temp_dir().join(format!("gv-wm-trunc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let storage = DurableStorage::at(dir.join("node"));
        let me = SigningKey::from_seed([1; 32]);
        let mut w = Watermark::open(&storage).unwrap();
        w.before_release(&batch(&me, 0), &me.id()).unwrap();
        let mut bytes = std::fs::read(storage.file(SUFFIX)).unwrap();
        bytes.pop();
        std::fs::write(storage.file(SUFFIX), &bytes).unwrap();
        assert!(Watermark::open(&storage).is_err());
        std::fs::write(storage.file(SUFFIX), 20u64.to_le_bytes()).unwrap();
        assert_eq!(
            Watermark::open(&storage).unwrap().through(),
            20,
            "an old mark-only file opens"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_batch_whose_release_cannot_be_recorded_is_refused_and_nothing_moves() {
        let dir = std::env::temp_dir().join(format!("gv-wm-full-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let storage = DurableStorage::at(dir.join("node"));
        let me = SigningKey::from_seed([1; 32]);
        let mut w = Watermark::open(&storage).unwrap();
        w.before_release(&batch(&me, 0), &me.id()).unwrap();

        // A directory where the mark belongs makes the write fail, as a full or failing disk does.
        let mark = storage.file(SUFFIX);
        std::fs::remove_file(&mark).unwrap();
        std::fs::create_dir(&mark).unwrap();
        assert!(w.before_release(&batch(&me, 20), &me.id()).is_err());
        assert_eq!(
            w.through(),
            20,
            "an unrecorded batch is not counted as released"
        );

        std::fs::remove_dir(&mark).unwrap();
        w.before_release(&batch(&me, 20), &me.id()).unwrap();
        assert_eq!(Watermark::open(&storage).unwrap().through(), 40);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
