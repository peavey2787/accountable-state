//! The committed size vectors that `scripts/bench-packing.mjs` re-derives independently.
//! Regenerate with `GV_REGEN_VECTORS=1 cargo test -p gv-codec packing_size_vectors`.
use crate::aggregate::MAX_AGGREGATE_RECORDS;
use crate::batch::{EventBatch, EventBody, HeldChange};
use crate::signed::SignedEventBatch;
use crate::wire::push_varint;
use gv_sig::{SigningKey, SIG_LEN};

/// One scenario: `players` each emit `events_per_second` control changes for `seconds` at the
/// `ticks_per_second` the application chose (alternating 1/0 so every change is a real change).
/// `batch_ticks == 0` is one record per participant for the whole span (archive form); otherwise
/// a signed record per `batch_ticks` ticks, as a live session signs one per epoch. Records are
/// real encodings carrying a zero-filled signature of the real ML-DSA-65 length.
struct Sizing {
    name: &'static str,
    players: usize,
    seconds: u32,
    ticks_per_second: u32,
    events_per_second: u32,
    batch_ticks: u32,
}

fn records_for(sc: &Sizing, player: usize) -> Vec<EventBatch> {
    let ticks = sc.seconds * sc.ticks_per_second;
    let gap = sc.ticks_per_second / sc.events_per_second;
    let span = if sc.batch_ticks == 0 {
        ticks
    } else {
        sc.batch_ticks
    };
    let mut records = Vec::new();
    let mut state = 0u8;
    let mut start = 0u32;
    let mut next_event = gap;
    while start < ticks {
        let count = span.min(ticks - start);
        if next_event == start {
            // a change on the batch boundary is the batch's initial state
            state = 1 - state;
            next_event += gap;
        }
        let initial = state;
        let mut changes = Vec::new();
        while next_event < start + count {
            state = 1 - state;
            changes.push(HeldChange {
                offset: next_event - start,
                payload: vec![state],
            });
            next_event += gap;
        }
        records.push(EventBatch {
            match_id: [9; 32],
            participant: [player as u8 + 1; 32],
            previous_batch_hash: [0; 32],
            start_tick: u64::from(start),
            tick_count: count,
            body: EventBody::Held {
                initial: vec![initial],
                changes,
            },
        });
        start += count;
    }
    records
}

fn sizing(sc: &Sizing) -> (usize, usize, usize) {
    let (mut records_total, mut bytes_total, mut aggregates) = (0, 0, 0);
    for player in 0..sc.players {
        let records = records_for(sc, player);
        records_total += records.len();
        for chunk in records.chunks(MAX_AGGREGATE_RECORDS) {
            let mut out = b"GVAG".to_vec();
            out.push(crate::batch::VERSION);
            push_varint(chunk.len() as u32, &mut out);
            for r in chunk {
                let len = r.encode().unwrap().len() + SIG_LEN;
                push_varint(len as u32, &mut out);
                out.resize(out.len() + len, 0);
            }
            bytes_total += out.len();
            aggregates += 1;
        }
    }
    (records_total, aggregates, bytes_total)
}

#[test]
fn packing_size_vectors() {
    let scenario =
        |name, players, seconds, ticks_per_second, events_per_second, batch_ticks| Sizing {
            name,
            players,
            seconds,
            ticks_per_second,
            events_per_second,
            batch_ticks,
        };
    let scenarios = [
        scenario(
            "1v1, 10 min, 2 changes/s, one record per player",
            2,
            600,
            60,
            2,
            0,
        ),
        scenario(
            "1v1, 1 h, 2 changes/s, one record per player",
            2,
            3600,
            60,
            2,
            0,
        ),
        scenario(
            "16 players, 10 min, 2 changes/s, one record per player",
            16,
            600,
            60,
            2,
            0,
        ),
        scenario(
            "1v1, 1 h, 60 Hz digital updates, one record per player",
            2,
            3600,
            60,
            60,
            0,
        ),
        scenario(
            "1v1, 10 min, 2 changes/s, live epochs of 20 ticks",
            2,
            600,
            60,
            2,
            20,
        ),
        scenario(
            "1v1, 1 h, 2 changes/s, live epochs of 20 ticks",
            2,
            3600,
            60,
            2,
            20,
        ),
        scenario(
            "4 players, 10 min at 30 Hz, 2 changes/s, epochs of 30 ticks",
            4,
            600,
            30,
            2,
            30,
        ),
    ];
    let mut json =
        String::from("{\n  \"format\": \"GV-PACKING-SIZES-V2\",\n  \"signature_bytes\": ");
    json.push_str(&format!(
        "{},\n  \"max_aggregate_records\": {},\n  \"scenarios\": [\n",
        SIG_LEN, MAX_AGGREGATE_RECORDS
    ));
    for (i, sc) in scenarios.iter().enumerate() {
        let (records, aggregates, bytes) = sizing(sc);
        json.push_str(&format!(
            "    {{\"name\": \"{}\", \"players\": {}, \"seconds\": {}, \"ticks_per_second\": {}, \"events_per_second\": {}, \"width\": 1, \"batch_ticks\": {}, \"records\": {}, \"aggregates\": {}, \"bytes\": {}}}{}\n",
            sc.name, sc.players, sc.seconds, sc.ticks_per_second, sc.events_per_second,
            sc.batch_ticks, records, aggregates, bytes,
            if i + 1 < scenarios.len() { "," } else { "" }
        ));
    }
    json.push_str("  ]\n}\n");
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/interoperability/packing_sizes_v2.json"
    );
    if std::env::var("GV_REGEN_VECTORS").is_ok() {
        std::fs::write(path, &json).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        json,
        "size vectors are stale"
    );
    // One really signed record has exactly the size the zero-signature model assumes.
    let key = SigningKey::from_seed([7; 32]);
    let mut record = records_for(&scenarios[0], 0).remove(0);
    record.participant = key.id();
    let real = SignedEventBatch::sign(record.clone(), &key)
        .unwrap()
        .encode()
        .unwrap();
    assert_eq!(real.len(), record.encode().unwrap().len() + SIG_LEN);
}
