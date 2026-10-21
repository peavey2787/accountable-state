//! Two independent peers playing a real-time (60 Hz) deterministic match over
//! p2p-net + Hydra. Gameplay never waits for the network or for cryptography;
//! signed inputs, replay, checkpoint co-signing and fraud proofs run in a
//! separate pipeline a few hundred milliseconds behind. Commit-lock-reveal is
//! used only for the hidden window.
#![forbid(unsafe_code)]
mod bounded;
mod game;
mod ui;
mod witness_net;
use gv_core::{MatchId, PlayerId};
use gv_edge::{
    evidence_violations, ArenaRules, ArenaState, CertifiedMatch, CheckpointEvidence,
    EvidenceVerdict, FraudBundle, PublicRules,
};
use gv_p2p::native::{parse_multiaddr, parse_peer, LiveLink};
use gv_sig::{decode_public_key_file, encode_public_key_file, SigningKey};
use hydra_msg::Hydra;
use p2p_net::NodeConfig;
use std::{env, fs, path::Path};
use ui::ArenaUi;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn decode_hex<const N: usize>(s: &str) -> Result<[u8; N], String> {
    if s.len() != N * 2 {
        return Err("wrong hex byte length".into());
    }
    let mut b = [0u8; N];
    for (i, v) in b.iter_mut().enumerate() {
        *v = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| "invalid hex")?;
    }
    Ok(b)
}
fn password() -> Result<String, String> {
    env::var("GV_HYDRA_PASSWORD").map_err(|_| "set GV_HYDRA_PASSWORD".into())
}
fn local_signing() -> Result<SigningKey, String> {
    let seed = env::var("GV_PLAYER_SEED_HEX")
        .map_err(|_| "set GV_PLAYER_SEED_HEX (32-byte secret seed)".to_string())?;
    Ok(SigningKey::from_seed(decode_hex::<32>(&seed)?))
}
fn init(path: &str, card_path: &str, pubkey_path: &str) -> Result<(), String> {
    let pw = password()?;
    let mut hydra = Hydra::open(path, &pw).map_err(|e| e.to_string())?;
    let ids = hydra.list_ids();
    let id = if let Some(x) = ids.first() {
        x.id()
    } else {
        hydra.generate_id(&pw).map_err(|e| e.to_string())?
    };
    hydra.set_active_id(id, &pw).map_err(|e| e.to_string())?;
    fs::write(
        card_path,
        hydra.create_contact_card().map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!("Trusted card exported: {card_path}");
    let key = local_signing()?;
    fs::write(pubkey_path, encode_public_key_file(key.public_key())).map_err(|e| e.to_string())?;
    println!("Player public key file: {pubkey_path}");
    println!("Player ML-DSA-65 id: {}", hex(&key.id()));
    Ok(())
}
/// Micro-benchmark of the Hydra layer alone (no network): cost of one encrypted
/// send / receive of a typical game frame, to separate crypto from transport.
fn bench_hydra(prune: bool) -> Result<(), String> {
    use hydra_msg::HydraMessage;
    let dir = env::temp_dir().join(format!("gv-hydra-bench-{}", std::process::id()));
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let (pa, pb) = ("alice-password-1234567890", "bob-password-1234567890");
    let mut a = Hydra::open(dir.join("a"), pa).map_err(|e| e.to_string())?;
    let mut b = Hydra::open(dir.join("b"), pb).map_err(|e| e.to_string())?;
    for (h, pw) in [(&mut a, pa), (&mut b, pb)] {
        h.set_packet_size(4096).map_err(|e| e.to_string())?;
        let id = h.generate_id(pw).map_err(|e| e.to_string())?;
        h.set_active_id(id, pw).map_err(|e| e.to_string())?;
    }
    let (ca, cb) = (
        a.create_contact_card().map_err(|e| e.to_string())?,
        b.create_contact_card().map_err(|e| e.to_string())?,
    );
    let to_b = a.add_contact(&cb).map_err(|e| e.to_string())?;
    let to_a = b.add_contact(&ca).map_err(|e| e.to_string())?;
    a.verify_contact(to_b.id(), to_b.safety_code())
        .map_err(|e| e.to_string())?;
    b.verify_contact(to_a.id(), to_a.safety_code())
        .map_err(|e| e.to_string())?;
    let offer = a.init_handshake(to_b.id()).map_err(|e| e.to_string())?;
    let answer = b.reply_handshake(offer).map_err(|e| e.to_string())?;
    let finish = a.finish_handshake(answer).map_err(|e| e.to_string())?;
    b.accept_handshake_finish(finish)
        .map_err(|e| e.to_string())?;
    // Cost as a function of how many messages the session has already carried:
    // a healthy ratchet is flat; growth here is a transport-crypto problem.
    let payload = vec![7u8; 150];
    let mut sent = 0u32;
    println!(
        "history pruning: {}",
        if prune { "every 20 messages" } else { "off" }
    );
    println!(
        "messages   send avg/max (us)   receive avg/max (us)   (150 B payloads, Lite packets)"
    );
    for bucket in 0..8 {
        let n = if bucket == 0 { 100 } else { 500 };
        let (mut st, mut rt) = (std::time::Duration::ZERO, std::time::Duration::ZERO);
        let (mut smax, mut rmax) = (0u128, 0u128);
        for _ in 0..n {
            let t = std::time::Instant::now();
            let packets = a
                .send(to_b.id(), HydraMessage::bytes(payload.clone()))
                .map_err(|e| e.to_string())?;
            let d = t.elapsed();
            st += d;
            smax = smax.max(d.as_micros());
            for p in packets {
                let t = std::time::Instant::now();
                let _ = b.receive(p).map_err(|e| e.to_string())?;
                let d = t.elapsed();
                rt += d;
                rmax = rmax.max(d.as_micros());
            }
            sent += 1;
            // Hydra keeps every message in a per-contact history and rewrites the
            // whole encrypted state on each call; game frames must not accumulate.
            if prune && sent.is_multiple_of(20) {
                a.clear_messages(to_b.id()).map_err(|e| e.to_string())?;
                b.clear_messages(to_a.id()).map_err(|e| e.to_string())?;
            }
        }
        println!(
            "{sent:8}   {:7.0} / {smax:7}   {:8.0} / {rmax:7}",
            st.as_micros() as f64 / f64::from(n),
            rt.as_micros() as f64 / f64::from(n)
        );
    }
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}
/// Reads a `GV-PUBKEY/V1` file and interns the key; the pinned roster is these keys.
fn load_public_key(path: &str) -> Result<PlayerId, String> {
    let bytes = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    decode_public_key_file(&bytes).map_err(|e| format!("{path}: invalid public key file: {e:?}"))
}
fn trusted_args(args: &[String]) -> Result<(MatchId, [PlayerId; 2]), String> {
    if args.len() != 5 {
        return Err(
            "verify <artifact.bin> <match-id-hex> <first-player.pub> <second-player.pub>".into(),
        );
    }
    let match_id = decode_hex::<32>(&args[2])?;
    let mut roster = [load_public_key(&args[3])?, load_public_key(&args[4])?];
    roster.sort();
    if roster[0] == roster[1] {
        return Err("same key in both player slots".into());
    }
    Ok((match_id, roster))
}
fn verify_file(args: &[String]) -> Result<(), String> {
    let (match_id, roster) = trusted_args(args)?;
    let bytes = fs::read(&args[1]).map_err(|e| e.to_string())?;
    let rules = ArenaRules::new(roster);
    if bytes.starts_with(b"GV-CERTIFIED-MATCH/V1\0") {
        let archive = CertifiedMatch::decode(&bytes).map_err(|e| format!("decode: {e:?}"))?;
        let replica = archive
            .restore(match_id, roster, rules)
            .map_err(|e| format!("INVALID certified history: {e:?}"))?;
        println!(
            "VALID certified match, {} ticks, {} epochs; final state {:?}",
            replica.next_tick(),
            replica.accepted().len(),
            ArenaState::decode(replica.state())
        );
        return Ok(());
    }
    if bytes.starts_with(b"GV-FRAUD-BUNDLE/V1\0") {
        let proof = FraudBundle::decode(&bytes).map_err(|e| format!("decode: {e:?}"))?;
        let verdict = proof.verify(match_id, roster, rules);
        println!("Independent chained-fraud verdict: {verdict:?}");
        return if verdict == EvidenceVerdict::ProvenInvalidState {
            Ok(())
        } else {
            Err("the allegation did NOT prove a fraudulent state claim".into())
        };
    }
    if bytes.starts_with(b"GV-EVIDENCE/V1\0") {
        let proof = CheckpointEvidence::decode(&bytes).map_err(|e| format!("decode: {e:?}"))?;
        let violations =
            evidence_violations(&rules, &proof).map_err(|e| format!("INVALID evidence: {e:?}"))?;
        if violations.is_empty() {
            return Err("the evidence is valid but contains no illegal input".into());
        }
        for v in &violations {
            println!(
                "PROVEN: player {} signed illegal control word {:#06x} at tick {}",
                hex(&v.player),
                v.control,
                v.tick
            );
        }
        return Ok(());
    }
    if bytes.starts_with(b"GV-EVIDENCE-PACKAGE/V1\0") {
        use gv_edge::export::{verify_package, TrustAnchor, Verified};
        use gv_replay::GameRules as _;
        let anchor = TrustAnchor {
            match_id,
            ruleset: rules.ruleset_hash(),
            roster,
        };
        return match verify_package(&bytes, &anchor, &rules) {
            Ok((c, Verified::Fraud { kind, accused })) => {
                println!("PROVEN {kind:?}: player {} (package {}; publishing this id is not fraud verification)", hex(&accused), hex(&c.id));
                Ok(())
            }
            Ok((c, other)) => {
                println!("VALID package {}: {other:?}", hex(&c.id));
                Ok(())
            }
            Err(e) => Err(format!("package does NOT verify: {e:?}")),
        };
    }
    if bytes.starts_with(b"GV-ACCOUNTABILITY-EVIDENCE/V1\0") {
        let ev = gv_edge::audit::Evidence::decode(&bytes).map_err(|e| format!("decode: {e:?}"))?;
        if ev.match_id() != match_id || !roster.contains(&ev.accused()) {
            return Err("evidence is for another match or an unpinned player".into());
        }
        return match ev.verify() {
            Ok(gv_edge::audit::Proof::Equivocation(p)) => {
                println!(
                    "PROVEN_EQUIVOCATION: player {} signed contradictory statements (evidence id {})",
                    hex(&p),
                    ev.id().map(|i| hex(&i)).unwrap_or_default()
                );
                Ok(())
            }
            Err(e) => Err(format!("evidence does NOT prove misbehavior: {e:?}")),
        };
    }
    Err(
        "unsupported artifact; use a signed full-match receipt, fraud proof or evidence file"
            .into(),
    )
}

/// Parse a `--name=value` option as a number within a range.
fn numeric(opt: &str, name: &str, lo: u64, hi: u64) -> Result<u64, String> {
    let v = opt
        .strip_prefix(name)
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| format!("bad {name}"))?;
    if !(lo..=hi).contains(&v) {
        return Err(format!("{name} must be {lo}..{hi}"));
    }
    Ok(v)
}

async fn run(args: &[String]) -> Result<(), String> {
    if args.len() < 8 {
        return Err("run <alice|bob> <node-config.json> <hydra-data-dir> <peer-card-file> <match-id-hex> <peer.pub> <artifact-out> [--ui-port=9001] [--epochs=N (headless)] [--epoch-ticks=20] [--hide-at=TICK] [--cheat-at=TICK] [--illegal-at=TICK] [--equivocate-at=TICK] [--withhold-at=TICK] [--accuse-falsely-at=TICK] [--resume=ARCHIVE]".into());
    }
    let initiator = match args[1].as_str() {
        "alice" => true,
        "bob" => false,
        _ => return Err("role must be alice or bob".into()),
    };
    let mut headless_epochs = 3usize;
    let mut resume_file = None;
    let mut ui_port = None;
    let mut epoch_ticks = 20u32;
    let mut hide_at = None;
    let mut cheat_at = None;
    let mut illegal_at = None;
    let mut equivocate_at = None;
    let mut withhold_at = None;
    let mut accuse_falsely_at = None;
    let mut witness_links = Vec::new();
    for opt in &args[8..] {
        if let Some(v) = opt.strip_prefix("--witness-link=") {
            witness_links.push(witness_net::parse_link(v)?);
            continue;
        }
        if opt.starts_with("--epochs=") {
            headless_epochs = numeric(opt, "--epochs=", 1, 100_000)? as usize;
        } else if let Some(v) = opt.strip_prefix("--resume=") {
            resume_file = Some(v.to_owned());
        } else if opt.starts_with("--ui-port=") {
            ui_port = Some(numeric(opt, "--ui-port=", 1, 65_535)? as u16);
        } else if opt.starts_with("--epoch-ticks=") {
            epoch_ticks = numeric(opt, "--epoch-ticks=", 6, 120)? as u32;
        } else if opt.starts_with("--hide-at=") {
            hide_at = Some(numeric(opt, "--hide-at=", 0, 10_000_000)?);
        } else if opt.starts_with("--cheat-at=") {
            cheat_at = Some(numeric(opt, "--cheat-at=", 0, 10_000_000)?);
        } else if opt.starts_with("--illegal-at=") {
            illegal_at = Some(numeric(opt, "--illegal-at=", 0, 10_000_000)?);
        } else if opt.starts_with("--equivocate-at=") {
            equivocate_at = Some(numeric(opt, "--equivocate-at=", 0, 10_000_000)?);
        } else if opt.starts_with("--withhold-at=") {
            withhold_at = Some(numeric(opt, "--withhold-at=", 0, 10_000_000)?);
        } else if opt.starts_with("--accuse-falsely-at=") {
            accuse_falsely_at = Some(numeric(opt, "--accuse-falsely-at=", 0, 10_000_000)?);
        } else {
            return Err(format!("unknown option: {opt}"));
        }
    }
    if 300 % epoch_ticks != 0 {
        return Err("--epoch-ticks must divide 300 (the 5 s hidden window)".into());
    }
    let config = NodeConfig::load_json_file(&args[2]).map_err(|e| e.to_string())?;
    let card = fs::read(&args[4]).map_err(|e| e.to_string())?;
    let match_id = decode_hex::<32>(&args[5])?;
    let other = load_public_key(&args[6])?;
    let key = local_signing()?;
    let me = key.id();
    let mut roster = [me, other];
    roster.sort();
    if roster[0] == roster[1] {
        return Err("duplicate player keys".into());
    }
    let rules = ArenaRules::new(roster);
    let resume = match resume_file.as_ref() {
        Some(path) => Some(
            CertifiedMatch::decode(&fs::read(path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("invalid recovery archive: {e:?}"))?,
        ),
        None => None,
    };
    let initial = match &resume {
        Some(archive) => ArenaState::decode(
            archive
                .restore(match_id, roster, rules.clone())
                .map_err(|e| format!("cannot authenticate recovered history: {e:?}"))?
                .state(),
        )
        .map_err(|e| format!("arena state: {e:?}"))?,
        None => ArenaState::decode(&rules.genesis(&roster))
            .map_err(|e| format!("arena state: {e:?}"))?,
    };
    let ui = match ui_port {
        Some(port) => {
            let gui = ArenaUi::start(port, usize::from(me == roster[1]), &initial).await?;
            gui.event("Ready: connecting over encrypted P2P");
            Some(gui)
        }
        None => None,
    };
    // Any error below must not destroy the local diagnostic HTTP server:
    // dropping its listener would leave the browser showing only "Offline".
    let reporter = ui.as_ref().map(ArenaUi::reporter);
    let outcome: Result<(), String> = async {
        let remote = env::var("GV_REMOTE_PEER_ID")
            .ok()
            .map(|v| parse_peer(&v).map_err(|e| format!("peer id: {e:?}")))
            .transpose()?;
        let dial = env::var("GV_REMOTE_MULTIADDR")
            .ok()
            .map(|v| parse_multiaddr(&v).map_err(|e| format!("multiaddr: {e:?}")))
            .transpose()?;
        let mut link = LiveLink::start(
            config,
            Path::new(&args[3]),
            &password()?,
            &card,
            match_id,
            remote,
            dial,
        )
        .await
        .map_err(|e| format!("start: {e:?}"))?;
        println!("Connected to {}. Hydra handshake...", link.peer);
        let handshake_started = std::time::Instant::now();
        tokio::time::timeout(
            std::time::Duration::from_secs(90),
            link.handshake(initiator),
        )
        .await
        .map_err(|_| "handshake/first-delivery readiness timed out after 90s".to_string())?
        .map_err(|e| format!("handshake/first-delivery readiness: {e:?}"))?;
        eprintln!(
            "startup: Hydra handshake + delivery barrier {:?}",
            handshake_started.elapsed()
        );
        let headless = ui.is_none();
        game::play(
            game::GameConfig {
                initiator,
                key,
                roster,
                match_id,
                epoch_ticks,
                headless_epochs: headless.then_some(headless_epochs),
                hide_at,
                cheat_at,
                illegal_at,
                equivocate_at,
                withhold_at,
                accuse_falsely_at,
                artifact_path: args[7].clone(),
                resume,
                witness_keys: witness_links
                    .iter()
                    .map(|l| load_public_key(&l.peer_pub))
                    .collect::<Result<_, _>>()?,
                witness_links,
            },
            link,
            ui,
        )
        .await
    }
    .await;
    if let Err(reason) = &outcome {
        eprintln!("EDGE MATCH FAILED: {reason}");
        if let Some(reporter) = &reporter {
            reporter.failure(reason);
            // Keep /state available so the browser can report the actual fault.
            std::future::pending::<()>().await;
        }
    }
    outcome
}
/// `witness <name> <match-id-hex> <a.pub> <b.pub> <out-dir> --link=cfg,hydra,card,player.pub,addr-file
/// [--link=...] [--run-secs=N] [--malicious] [--audit-every-ms=N]`
async fn witness(args: &[String]) -> Result<(), String> {
    if args.len() < 7 {
        return Err("witness <name> <match-id-hex> <a.pub> <b.pub> <out-dir> --link=... [--run-secs=N] [--malicious] [--audit-every-ms=N]".into());
    }
    let match_id = decode_hex::<32>(&args[2])?;
    let mut roster = [load_public_key(&args[3])?, load_public_key(&args[4])?];
    roster.sort();
    let (mut links, mut run_secs, mut malicious, mut audit_every_ms) =
        (Vec::new(), 60u64, false, 0u64);
    for opt in &args[6..] {
        if let Some(v) = opt.strip_prefix("--link=") {
            let spec = witness_net::parse_link(v)?;
            let player = load_public_key(&spec.peer_pub)?;
            if !roster.contains(&player) {
                return Err("link peer is not a pinned player".into());
            }
            links.push((spec, player));
        } else if opt.starts_with("--run-secs=") {
            run_secs = numeric(opt, "--run-secs=", 1, 86_400)?;
        } else if opt == "--malicious" {
            malicious = true;
        } else if opt.starts_with("--audit-every-ms=") {
            audit_every_ms = numeric(opt, "--audit-every-ms=", 0, 3_600_000)?;
        } else {
            return Err(format!("unknown option: {opt}"));
        }
    }
    witness_net::run_witness(witness_net::WitnessConfig {
        name: args[1].clone(),
        key: local_signing()?,
        roster,
        match_id,
        links,
        out_dir: args[5].clone().into(),
        run_secs,
        malicious,
        audit_every_ms,
    })
    .await
}
/// Regenerates the committed ML-DSA-65 interoperability vectors. Signing is
/// hedged, so each run produces a different (equally valid) signature; the
/// independent verifiers check whatever is committed.
fn write_vectors(dir: &str) -> Result<(), String> {
    use gv_codec::{Aggregate, ControlChange, PackedControls, SignedPackedControls};
    let key = SigningKey::from_seed([7; 32]);
    let label = "gv/test/vector/v1";
    let body = b"gv interoperability vector".to_vec();
    let sig = key.sign(label, &body);
    let digest = gv_sig::envelope_digest(label, &key.id(), &body);
    let signed_vector = format!(
        "{{\n  \"format\": \"GV-SIG-ML-DSA-65-V1\",\n  \"seed_hex\": \"{}\",\n  \"verifying_key_hex\": \"{}\",\n  \"player_id_hex\": \"{}\",\n  \"label\": \"{label}\",\n  \"body_hex\": \"{}\",\n  \"envelope_digest_hex\": \"{}\",\n  \"signature_hex\": \"{}\"\n}}\n",
        hex(&[7; 32]),
        hex(key.public_key()),
        hex(&key.id()),
        hex(&body),
        hex(&digest),
        hex(sig.as_bytes())
    );
    let record = PackedControls {
        match_id: [1; 32],
        player: key.id(),
        previous_batch_hash: [2; 32],
        start_tick: 500,
        tick_count: 180,
        control_bytes: 1,
        initial_state: 1,
        changes: vec![ControlChange {
            offset: 179,
            state: 0,
        }],
    };
    let signed = SignedPackedControls::sign(record.clone(), &key).map_err(|e| format!("{e:?}"))?;
    let aggregate = Aggregate {
        records: vec![signed.clone()],
    };
    let agg_bytes = aggregate.encode().map_err(|e| format!("{e:?}"))?;
    let packed_vector = format!(
        "{{\n  \"format\": \"GVEC-GVAG-v1\",\n  \"verifying_key_hex\": \"{}\",\n  \"player_id_hex\": \"{}\",\n  \"record_hex\": \"{}\",\n  \"signature_hex\": \"{}\",\n  \"signed_record_hash\": \"{}\",\n  \"aggregate_hash\": \"{}\",\n  \"aggregate_length\": {}\n}}\n",
        hex(key.public_key()),
        hex(&key.id()),
        hex(&record.encode().map_err(|e| format!("{e:?}"))?),
        hex(signed.signature.as_bytes()),
        hex(&signed.digest().map_err(|e| format!("{e:?}"))?),
        hex(&aggregate.digest().map_err(|e| format!("{e:?}"))?),
        agg_bytes.len()
    );
    fs::write(Path::new(dir).join("signed_mldsa65_v1.json"), signed_vector)
        .map_err(|e| e.to_string())?;
    fs::write(
        Path::new(dir).join("packed_controls_v1.json"),
        packed_vector,
    )
    .map_err(|e| e.to_string())?;
    println!("wrote ML-DSA-65 vectors to {dir}");
    Ok(())
}
/// ML-DSA-65 signing cost and wire sizes. Only ML-DSA-65 exists in the project.
fn bench_sig() -> Result<(), String> {
    const N: u32 = 300;
    let body = [0x5au8; 150];
    let key = gv_sig::SigningKey::from_seed([7u8; 32]);
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
#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("init") if args.len() == 4 => init(&args[1], &args[2], &args[3]),
        Some("verify") => verify_file(&args),
        Some("vectors") => write_vectors(args.get(1).map_or("tests/interoperability", String::as_str)),
        Some("bench-sig") => bench_sig(),
        Some("bench-hydra") => bench_hydra(args.get(1).is_some_and(|a| a == "prune")),
        Some("run") => run(&args).await,
        Some("witness") => witness(&args).await,
        _ => Err("Usage: gv-edge-p2p-demo init <hydra-dir> <card-file> <pubkey-file> | verify <artifact> <match-id-hex> <alice.pub> <bob.pub> | run <alice|bob> <node-config> <hydra-dir> <peer-card> <match-id-hex> <peer.pub> <artifact-out> [--ui-port=9001] [--epochs=N] [--epoch-ticks=20] [--hide-at=TICK] [--cheat-at=TICK] [--illegal-at=TICK] [--equivocate-at=TICK] [--withhold-at=TICK] [--accuse-falsely-at=TICK] [--resume=ARCHIVE]".into()),
    };
    if let Err(e) = result {
        eprintln!("FAIL: {e}");
        std::process::exit(1)
    }
}
