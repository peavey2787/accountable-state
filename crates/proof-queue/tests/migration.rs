//! On-disk compatibility: a journal written by the first released format must open unchanged. If a
//! change makes this fail, the format changed: add a migration and a new fixture, never edit this one.
use gv_proof_queue::{
    Config, Family, FileJournal, JobSpec, JobState, Outcome, Priority, Queue, Submitted,
};
use std::path::{Path, PathBuf};

const F: Family = Family::EQUIVOCATION;
const FIXTURE: &str = "tests/fixtures/journal-v1.bin";

fn spec(n: u8) -> JobSpec {
    JobSpec {
        family: F,
        match_id: [9; 32],
        payload: vec![n; 40],
        priority: Priority::High,
        deadline: Some(5_000),
        deps: vec![],
    }
}

fn write_reference_journal(path: &Path) {
    let opened = FileJournal::open(path).unwrap();
    let mut q = Queue::open(opened, Config::default(), 1_000).unwrap();
    let Submitted::New(done) = q.submit(spec(1), 1_000).unwrap() else {
        panic!("first submit queues");
    };
    q.submit(spec(2), 1_001).unwrap();
    let lease = q.lease(1_002, &[F]).unwrap().unwrap();
    assert_eq!(lease.id, done);
    q.complete(&lease.id, Outcome::Invalid("fixture".into()), 1_003)
        .unwrap();
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gv-migration-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("q.journal")
}

/// Rewrites the fixture. Run only when the format is changed on purpose, alongside a migration:
/// `cargo test -p gv-proof-queue --test migration -- --ignored`.
#[test]
#[ignore = "regenerates the committed fixture"]
fn regenerate_fixture() {
    let path = scratch("regen");
    let _ = std::fs::remove_file(&path);
    write_reference_journal(&path);
    std::fs::copy(&path, FIXTURE).unwrap();
}

#[test]
fn the_first_released_journal_format_still_opens_with_its_jobs_and_verdicts() {
    let path = scratch("open");
    std::fs::copy(FIXTURE, &path).unwrap();
    let opened = FileJournal::open(&path).unwrap();
    assert_eq!(opened.truncated, 0, "a clean file loses nothing");
    let q = Queue::open(opened, Config::default(), 2_000).unwrap();

    let stats = q.stats();
    assert_eq!(stats.retained, 2);
    let states: Vec<JobState> = q
        .jobs_of_match(&[9; 32])
        .map(|j| j.state)
        .collect::<Vec<_>>();
    assert!(states.contains(&JobState::Failed));
    assert!(states.contains(&JobState::Pending));
    let events = q.events_after(0, 10).events;
    assert!(events.iter().any(|e| e.state == JobState::Failed));
}

#[test]
fn the_reference_journal_is_byte_for_byte_what_the_current_code_writes() {
    let path = scratch("bytes");
    let _ = std::fs::remove_file(&path);
    write_reference_journal(&path);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        std::fs::read(FIXTURE).unwrap(),
        "the journal format changed; add a migration and a new versioned fixture"
    );
}
