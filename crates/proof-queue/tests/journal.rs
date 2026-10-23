use gv_proof_queue::{FileJournal, Journal, MemJournal, OutboxJournal, Write};

fn rec(n: usize) -> Vec<u8> {
    vec![n as u8; n]
}

/// The per-record framing overhead, measured rather than assumed.
fn frame(j: &mut MemJournal) -> u64 {
    j.append(&[vec![]]).unwrap();
    j.size()
}

#[test]
fn a_memory_journal_accounts_for_every_byte_it_holds() {
    let mut j = MemJournal::new();
    let f = frame(&mut j);
    j.append(&[rec(10), rec(20)]).unwrap();
    assert_eq!(j.size(), f + (10 + f) + (20 + f));
    assert_eq!(j.records().len(), 3);
}

#[test]
fn capacity_is_inclusive_for_appends() {
    let mut j = MemJournal::new();
    let f = frame(&mut j);
    j.set_capacity(Some(f + 10 + f));
    j.append(&[rec(10)]).unwrap();
    assert!(j.append(&[vec![]]).is_err(), "one record over");
    assert_eq!(j.records().len(), 2, "the refused append wrote nothing");
}

#[test]
fn capacity_is_inclusive_for_rewrites_and_a_rewrite_replaces_everything() {
    let mut j = MemJournal::new();
    let f = frame(&mut j);
    j.append(&[rec(50)]).unwrap();
    j.set_capacity(Some(10 + f));
    assert!(j.rewrite(&[rec(11)]).is_err());
    j.rewrite(&[rec(10)]).unwrap();
    assert_eq!(j.records(), vec![rec(10)]);
    assert_eq!(j.size(), 10 + f);
    j.rewrite(&[rec(3)]).unwrap();
    assert_eq!(j.size(), 3 + f);
}

#[test]
fn a_failing_journal_refuses_appends_and_rewrites_until_it_recovers() {
    let mut j = MemJournal::new();
    j.set_failing(true);
    assert!(j.append(&[rec(1)]).is_err());
    assert!(j.rewrite(&[rec(1)]).is_err());
    assert!(j.records().is_empty());
    j.set_failing(false);
    j.append(&[rec(1)]).unwrap();
    j.rewrite(&[rec(2)]).unwrap();
}

#[test]
fn truncating_keeps_the_first_records_and_resizes() {
    let mut j = MemJournal::new();
    let f = frame(&mut j);
    j.append(&[rec(5), rec(6), rec(7)]).unwrap();
    j.truncate_to(2);
    assert_eq!(j.records(), vec![vec![], rec(5)]);
    assert_eq!(j.size(), f + 5 + f);
}

#[test]
fn a_file_journal_grows_with_appends_and_a_rewrite_replaces_its_content() {
    let dir = std::env::temp_dir().join(format!("gv-pq-journal-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("queue.journal");
    let mut j = FileJournal::open(&path).unwrap().journal;
    assert_eq!(j.size(), 0);
    j.append(&[rec(100)]).unwrap();
    let grown = j.size();
    assert!(grown > 100);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), grown);

    j.rewrite(&[rec(5), rec(6)]).unwrap();
    assert!(j.size() < grown);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), j.size());
    assert!(!path.with_extension("compact").exists());
    drop(j);
    let again = FileJournal::open(&path).unwrap();
    assert_eq!(again.records, vec![rec(5), rec(6)]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Framing overhead of one record, measured on an outbox rather than assumed.
fn outbox_frame() -> u64 {
    let mut j = OutboxJournal::open(vec![], u64::MAX).journal;
    j.append(&[vec![]]).unwrap();
    j.size()
}

#[test]
fn an_outbox_journal_starts_with_the_size_of_what_the_host_stored() {
    let f = outbox_frame();
    let opened = OutboxJournal::open(vec![rec(10), rec(20)], u64::MAX);
    assert_eq!(opened.journal.size(), (10 + f) + (20 + f));
    assert_eq!(opened.records, vec![rec(10), rec(20)]);
}

#[test]
fn an_outbox_journal_tracks_its_size_through_appends_and_rewrites() {
    let f = outbox_frame();
    let mut j = OutboxJournal::open(vec![rec(10)], u64::MAX).journal;
    j.append(&[rec(5), rec(6)]).unwrap();
    assert_eq!(j.size(), (10 + f) + (5 + f) + (6 + f));
    j.append(&[rec(1)]).unwrap();
    assert_eq!(j.size(), (10 + f) + (5 + f) + (6 + f) + (1 + f));
    j.rewrite(&[rec(2), rec(3)]).unwrap();
    assert_eq!(j.size(), (2 + f) + (3 + f));
}

#[test]
fn the_host_drains_exactly_what_was_written_in_order() {
    let mut j = OutboxJournal::open(vec![], u64::MAX).journal;
    j.append(&[rec(1)]).unwrap();
    j.rewrite(&[rec(2)]).unwrap();
    let drained = j.take();
    assert!(matches!(&drained[0], Write::Append(r) if r == &vec![rec(1)]));
    assert!(matches!(&drained[1], Write::Rewrite(r) if r == &vec![rec(2)]));
    assert!(j.take().is_empty());
}

#[test]
fn an_outbox_accepts_writes_up_to_its_limit_and_refuses_beyond_until_drained() {
    let f = outbox_frame();
    let mut j = OutboxJournal::open(vec![], (10 + f) + (4 + f)).journal;
    j.append(&[rec(10)]).unwrap();
    j.append(&[rec(4)]).unwrap();
    assert!(j.append(&[vec![]]).is_err(), "one record over the limit");
    assert!(j.rewrite(&[vec![]]).is_err());
    assert_eq!(
        j.size(),
        (10 + f) + (4 + f),
        "a refused write changes nothing"
    );
    j.take();
    j.append(&[rec(10)]).unwrap();
}
