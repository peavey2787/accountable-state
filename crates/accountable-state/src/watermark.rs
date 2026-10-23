//! The tick up to which this participant has ever released a signed input batch. A batch is
//! recorded durably before it leaves, so a restarted process resumes after it: re-signing a tick
//! it already signed, with different inputs, would be equivocation by an honest player. The
//! ticks in between are certified from the batches its peers kept.
use crate::config::DurableStorage;
use crate::io::OpenError;
use gv_core::ParticipantId;
use gv_edge::audit::fsync::replace_file;
use gv_edge::live::PipeMsg;
use std::io;
use std::path::PathBuf;

const SUFFIX: &str = ".signed-through";

pub(crate) struct Watermark {
    path: PathBuf,
    through: u64,
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
        let through = match std::fs::read(&path) {
            Ok(b) => <[u8; 8]>::try_from(b.as_slice())
                .map(u64::from_le_bytes)
                .map_err(|_| fail("corrupt signed-through mark".into()))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
            Err(e) => return Err(fail(e.to_string())),
        };
        Ok(Self { path, through })
    }

    pub(crate) fn through(&self) -> u64 {
        self.through
    }

    /// Record, durably, that `msg` is about to be released. Only my own batches count. An error
    /// means the batch must not leave: it could not be remembered.
    pub(crate) fn before_release(&mut self, msg: &PipeMsg, me: &ParticipantId) -> io::Result<()> {
        let PipeMsg::Batch(b) = msg else {
            return Ok(());
        };
        let end = b.record.start_tick + u64::from(b.record.tick_count);
        if b.record.participant != *me || end <= self.through {
            return Ok(());
        }
        replace_file(&self.path, &end.to_le_bytes())?;
        self.through = end;
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
}
