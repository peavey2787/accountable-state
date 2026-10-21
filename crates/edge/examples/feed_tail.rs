//! External subscriber for the authenticated evidence feed.
//!
//!   cargo run -p gv-edge --example feed_tail -- FEED_FILE MATCH_ID_HEX PUBLISHER.pub [FROM_ID] [--follow]
//!
//! Prints every event with id > FROM_ID (default 0) whose ML-DSA-65 signature verifies against
//! the pinned publisher key, and fails on a gap in ids. Remember the last id printed: restarting
//! with it as FROM_ID resumes exactly where this subscriber stopped, however many events were
//! missed meanwhile. `--follow` keeps polling the file.
use gv_edge::export::ExportEvent;
use gv_edge::feed::read_since;
use gv_sig::decode_public_key_file;
use std::process::ExitCode;
use std::time::Duration;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let follow = args.iter().any(|a| a == "--follow");
    let pos: Vec<&String> = args.iter().filter(|a| *a != "--follow").collect();
    if pos.len() < 3 {
        eprintln!("usage: feed_tail FEED_FILE MATCH_ID_HEX PUBLISHER.pub [FROM_ID] [--follow]");
        return ExitCode::from(2);
    }
    let Ok(raw) = std::fs::read(pos[2]) else {
        eprintln!("cannot read {}", pos[2]);
        return ExitCode::from(2);
    };
    let Ok(publisher) = decode_public_key_file(&raw) else {
        eprintln!("bad public key file");
        return ExitCode::from(2);
    };
    let mut last: u64 = pos.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
    loop {
        for e in read_since(std::path::Path::new(pos[0]), last, 4096) {
            if e.publisher != publisher || hex(&e.match_id) != *pos[1] {
                eprintln!("event {} is from another publisher or match: ignored", e.id);
                continue;
            }
            if e.id != last + 1 {
                eprintln!("GAP: expected event {} but found {}", last + 1, e.id);
                return ExitCode::from(1);
            }
            last = e.id;
            match &e.event {
                ExportEvent::Evidence {
                    accused,
                    commitment,
                } => println!(
                    "{} EVIDENCE accused={}.. kind={:?} fraud={:?} package={}",
                    e.id,
                    hex(&accused[..4]),
                    commitment.kind,
                    commitment.fraud,
                    hex(&commitment.id)
                ),
                ExportEvent::Checkpoint { epoch_start, hash } => {
                    println!(
                        "{} CHECKPOINT epoch_start={epoch_start} hash={}",
                        e.id,
                        hex(hash)
                    )
                }
                ExportEvent::Audit { challenge, status } => {
                    println!(
                        "{} AUDIT challenge={} status={}",
                        e.id,
                        hex(&challenge[..4]),
                        status.name()
                    )
                }
            }
        }
        if !follow {
            println!("LAST_ID {last}");
            return ExitCode::SUCCESS;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
