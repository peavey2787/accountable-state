//! Independent verification of an exported evidence package, with nothing but pinned facts.
//!
//!   cargo run -p gv-edge --example verify_package -- PACKAGE MATCH_ID_HEX FIRST.pub SECOND.pub
//!
//! The verifier trusts only the match id, the two player public-key files and the ruleset it
//! compiles in. It never contacts a witness, a server or a ledger. A package that merely sits
//! behind a published hash proves nothing: only a successful `verify_package` does.
use gv_edge::export::{verify_package, TrustAnchor, Verified};
use gv_edge::ArenaRules;
use gv_replay::GameRules as _;
use gv_sig::decode_public_key_file;
use std::process::ExitCode;

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn run(args: &[String]) -> Result<String, String> {
    let [_, package, match_id, first, second] = args else {
        return Err("usage: verify_package PACKAGE MATCH_ID_HEX FIRST.pub SECOND.pub".into());
    };
    let bytes = std::fs::read(package).map_err(|e| format!("{package}: {e}"))?;
    let key = |p: &String| -> Result<_, String> {
        let raw = std::fs::read(p).map_err(|e| format!("{p}: {e}"))?;
        decode_public_key_file(&raw).map_err(|e| format!("{p}: {e:?}"))
    };
    let mut roster = [key(first)?, key(second)?];
    roster.sort();
    let rules = ArenaRules::new(roster);
    let anchor = TrustAnchor {
        match_id: hex32(match_id).ok_or("match id must be 64 hex characters")?,
        ruleset: rules.ruleset_hash(),
        roster,
    };
    let (commitment, verified) =
        verify_package(&bytes, &anchor, &rules).map_err(|e| format!("NOT VERIFIED: {e:?}"))?;
    let id: String = commitment.id.iter().map(|b| format!("{b:02x}")).collect();
    Ok(match verified {
        Verified::Fraud { kind, accused } => {
            let who: String = accused.iter().take(8).map(|b| format!("{b:02x}")).collect();
            format!("PROVEN {kind:?} by player {who}…  package {id}")
        }
        Verified::Match { ticks, epochs, disputed, segments } => format!(
            "VALID match archive: {ticks} ticks, {epochs} epochs ({disputed} disputed, {segments} certified segment(s))  package {id}"
        ),
        Verified::Audit { authenticators, segments, proven, .. } => format!(
            "VALID audit export: {authenticators} heads, {segments} segments, {} proven equivocator(s)  package {id}",
            proven.len()
        ),
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
