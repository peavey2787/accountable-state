//! Per-component cost of the accountable-state pipeline, as a Markdown table:
//! `cargo run --release -p gv-proof-queue --example perf_report`.
//! The game thread only ever pays for the rows under "game thread"; everything else runs on workers.
use gv_codec::{EventBatch, EventBody, HeldChange, SignedEventBatch};
use gv_edge::audit::Evidence;
use gv_proof_queue::verify::{pack, Equivocation, Registry};
use gv_proof_queue::{
    Config, FileJournal, JobSpec, Journal, MemJournal, Priority, Queue, Service, ServiceConfig,
    SystemClock, WorkerPool,
};
use gv_sig::SigningKey;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MATCH: [u8; 32] = [7; 32];

fn batch(k: &SigningKey, start: u64, init: u16) -> SignedEventBatch {
    SignedEventBatch::sign(
        EventBatch {
            match_id: MATCH,
            participant: k.id(),
            previous_batch_hash: [0; 32],
            start_tick: start,
            tick_count: 20,
            body: EventBody::Held {
                initial: init.to_le_bytes().to_vec(),
                changes: vec![HeldChange {
                    offset: 1,
                    payload: u16::MAX.to_le_bytes().to_vec(),
                }],
            },
        },
        k,
    )
    .unwrap()
}

fn evidence(k: &SigningKey, n: u16) -> Vec<u8> {
    Evidence::ConflictingBatches(batch(k, 0, n), batch(k, 5, n + 1))
        .encode()
        .unwrap()
}

fn spec(k: &SigningKey, n: u16) -> JobSpec {
    JobSpec {
        family: gv_proof_queue::Family::EQUIVOCATION,
        match_id: MATCH,
        payload: pack(&[evidence(k, n)]),
        priority: Priority::High,
        deadline: None,
        deps: vec![],
    }
}

fn per_op(label: &str, n: u32, mut f: impl FnMut(u32)) {
    let t = Instant::now();
    (0..n).for_each(&mut f);
    let us = t.elapsed().as_secs_f64() * 1e6 / f64::from(n);
    println!("| {label} | {us:.1} µs | {:.0} /s |", 1e6 / us);
}

fn service(journal: impl Journal + 'static) -> Arc<Service> {
    let queue = Queue::open(
        gv_proof_queue::Opened {
            journal,
            records: vec![],
            truncated: 0,
        },
        Config::default(),
        0,
    )
    .unwrap();
    Arc::new(Service::new(
        queue,
        Registry::new().with(Equivocation { witnesses: None }),
        Box::new(SystemClock),
        ServiceConfig::default(),
    ))
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    sorted[((sorted.len() as f64 - 1.0) * p) as usize]
}

fn main() {
    let key = SigningKey::from_seed([3; 32]);
    println!("| Component | Cost per operation | Rate |\n| --- | --- | --- |");
    println!("| **crypto and codec** | | |");
    per_op("ML-DSA-65 sign (150 B)", 200, |_| {
        std::hint::black_box(key.sign("gv/perf", &[1; 150]));
    });
    let sig = key.sign("gv/perf", &[1; 150]);
    per_op("ML-DSA-65 verify", 200, |_| {
        gv_sig::verify(&key.id(), "gv/perf", &[1; 150], &sig).unwrap();
    });
    let signed = batch(&key, 0, 1);
    per_op("input batch sign + encode", 100, |n| {
        std::hint::black_box(batch(&key, u64::from(n), 1).encode().unwrap());
    });
    let bytes = signed.encode().unwrap();
    per_op("input batch decode + verify", 100, |_| {
        std::hint::black_box(SignedEventBatch::decode(&bytes).unwrap());
    });
    println!("| **proof queue (worker side)** | | |");
    let mem = service(MemJournal::new());
    let mut specs: Vec<JobSpec> = (0..200u16).map(|n| spec(&key, n)).collect();
    per_op("submit, in-memory journal", 200, |_| {
        mem.submit(specs.pop().unwrap()).unwrap();
    });
    per_op("verify one equivocation job", 200, |_| {
        mem.step().unwrap();
    });
    let dir = std::env::temp_dir().join(format!("gv-perf-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = service(FileJournal::open(&dir.join("q.journal")).unwrap().journal);
    let mut specs: Vec<JobSpec> = (0..100u16).map(|n| spec(&key, 1000 + n)).collect();
    per_op("submit, durable file journal (fsync)", 100, |_| {
        file.submit(specs.pop().unwrap()).unwrap();
    });
    per_op("verify + record verdict, file journal", 100, |_| {
        file.step().unwrap();
    });
    let _ = std::fs::remove_dir_all(&dir);

    println!(
        "\n**Game thread under load.** `submit` latency while four workers verify a backlog:\n"
    );
    let busy = service(MemJournal::new());
    (0..400u16).for_each(|n| {
        busy.submit(spec(&key, n)).unwrap();
    });
    let pool = WorkerPool::start(Arc::clone(&busy), 4);
    let mut lat: Vec<Duration> = (0..300u16)
        .map(|n| {
            let s = spec(&key, 2000 + n);
            let t = Instant::now();
            busy.submit(s).unwrap();
            t.elapsed()
        })
        .collect();
    drop(pool);
    lat.sort();
    println!(
        "p50 {:?}, p99 {:?}, max {:?} (a 60 Hz frame is 16.6 ms)",
        percentile(&lat, 0.5),
        percentile(&lat, 0.99),
        lat[lat.len() - 1]
    );
}
