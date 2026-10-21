//! ML-DSA-65 signing cost and wire sizes: `cargo run --release -p gv-sig --example bench`.
use gv_sig::SigningKey;

/// ML-DSA-65 signing cost and wire sizes. Only ML-DSA-65 exists in the project.
fn bench_sig() -> Result<(), String> {
    const N: u32 = 300;
    let body = [0x5au8; 150];
    let key = SigningKey::from_seed([7u8; 32]);
    let id = gv_sig::register_key(key.public_key()).map_err(|e| format!("{e:?}"))?;
    let sig = key.sign("gv/bench/v1", &body);
    let t = std::time::Instant::now();
    for _ in 0..N {
        std::hint::black_box(key.sign("gv/bench/v1", &body));
    }
    let sign_us = t.elapsed().as_secs_f64() * 1e6 / f64::from(N);
    let t = std::time::Instant::now();
    for _ in 0..N {
        gv_sig::verify(&id, "gv/bench/v1", &body, &sig).map_err(|e| format!("{e:?}"))?;
    }
    let verify_us = t.elapsed().as_secs_f64() * 1e6 / f64::from(N);
    println!("scheme       sign us   verify us   signature B   verifying key B");
    println!(
        "ML-DSA-65    {sign_us:>7.1}   {verify_us:>9.1}   {:>11}   {:>15}",
        gv_sig::SIG_LEN,
        key.public_key().len()
    );
    println!(
        "signed bytes per peer per second at 3 signed messages/epoch, 3 epochs/s: {}",
        9 * gv_sig::SIG_LEN
    );
    println!("A 60 Hz sim signs per batch/head, never per tick: signing cost is amortised over the epoch.");
    Ok(())
}

fn main() {
    if let Err(e) = bench_sig() {
        eprintln!("FAIL: {e}");
        std::process::exit(1);
    }
}
