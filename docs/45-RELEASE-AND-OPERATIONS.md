# Release evidence, compatibility and credential rotation

## Release evidence
Every release is built from a clean, committed tree with the committed `Cargo.lock` (`--locked`).

| Artifact | Produced by | What it proves |
| --- | --- | --- |
| `provenance.json` | `node scripts/release-manifest.mjs` | commit, lockfile hash, rustc/cargo versions, builder, artifact hashes |
| `sbom.cdx.json` | same | CycloneDX 1.5 component list from `cargo metadata --locked`, with licenses and registry checksums from `Cargo.lock` (replaces `cargo-cyclonedx`, which is not installed) |
| `SHA256SUMS` | same | the `git archive` tarball, `Cargo.lock`, and every built artifact named on the command line |
| scan result | same, and `node scripts/inspect-release.mjs` | no private key blocks and no local build paths inside artifacts; no key files, VCS data or build output in what git would publish |
| reproducibility | `node scripts/repro-check.mjs` | two independent release builds of the C ABI library are byte-identical (paths remapped, `/Brepro` on Windows) |

`cargo audit` (RustSec) runs in both `run-all` scripts. The licence of this
workspace and of its Hydra signing dependency is GPL-2.0-or-later ([docs/44](44-LICENSING-AUDIT.md)).

## Compatibility
* **Wire protocol:** `crates/edge/tests/wire_compat.rs` pins the `PipeMsg` tags and requires unknown,
  empty and truncated messages to be refused without a panic. The codec's byte-exact vectors are
  `tests/interoperability/` (checked in Rust and, independently, by `scripts/verify-*.mjs`).
* **On-disk format:** `crates/proof-queue/tests/fixtures/journal-v1.bin` is a journal written by the
  first released format. `tests/migration.rs` requires it to open with its jobs and verdicts, and
  requires the current code to write the same bytes. A format change must add a migration and a new
  versioned fixture; the old fixture is never edited.
* **Corruption on open:** torn tails and bit rot are truncated and reported
  (`a_file_journal_survives_restart_torn_tails_and_bit_rot`); a corrupt signing mark refuses to open,
  because guessing low could re-sign a released tick.

## Credential rotation
Keys never move between roles, and no key is ever shared between matches' trust decisions.

* **Player identity key.** A player is its ML-DSA-65 verifying key. Rotating it creates a new
  participant id, which is a new roster entry: do it between matches by generating a new key,
  registering it with the match organiser, and retiring the old key file. Evidence already issued
  against the old key remains verifiable forever because it carries the key. Each node keeps a
  `.signed-through` mark beside its storage; delete it only together with the old identity, never
  while keeping the key.
* **Witness keys.** The pinned witness set is part of the node configuration (`Config::witnesses`)
  and of verification (`Equivocation { witnesses }`). To rotate, publish the new set for new matches
  and run old matches to completion under the old set; a witness is never edited in place during a
  match. Witness register cells (`FileCellStore`) belong to one match and are removed with it.
* **Compromise.** Treat a suspected leaked player key as an equivocation risk: stop using it, retire
  it, and keep its evidence. Treat a leaked witness key as a lost fault-tolerance unit: replace it in
  the next set; safety holds while fewer than the quorum threshold are compromised.
* **Never commit key material.** `.gitignore` excludes identity directories, `*.key`, `*.secret`,
  `*-identity/`; `scripts/inspect-release.mjs` fails a release that would include them.

## Network impairment (no WSL)
`crates/accountable-state/tests/tcp_processes.rs` runs three real player processes and four witnesses
over TCP on any OS. Its relay can drop, duplicate, delay and reorder gameplay frames; one test runs
at 5 % loss, 5 % duplication and 30 ms plus up to 60 ms jitter and requires every player to keep
certifying with no accusation. Linux-only `tc netem` runs for the anti-cheat arena stay in that repository.

Real wide-area testing needs two separated networks (for example one machine on and one off a VPN)
and is not run here.

## Concurrency and memory-safety gates
| Gate | How | Status in this environment |
| --- | --- | --- |
| ThreadSanitizer | `scripts/tsan-linux.sh` (nightly, `-Zsanitizer=thread -Zbuild-std`) over the service and worker pool; in `run-all-linux.sh` | runs under WSL; no data races |
| Miri | `cargo +nightly miri test -p gv-capi` over every `unsafe` function in the C ABI | runs; it found an out-of-bounds read in a test (a short buffer passed where the contract says 32 bytes) and a real leak (a null output pointer leaked the bytes already produced); both fixed. The full suite takes about 20 minutes under Miri because of ML-DSA |
| AddressSanitizer fuzzing | `cargo fuzz` targets in `fuzz/` | five targets run |
| Mutation testing | `cargo mutants` over `crates/proof-queue`, `host.rs`, `offload.rs`, the C ABI | surviving mutants are killed with tests, never allow-listed |

## Performance
`cargo run --release -p gv-proof-queue --example perf_report` prints a per-component table
(signing, verification, codec, queue submit and verify with an in-memory and a durable journal) and
the game thread's `submit` latency while four workers verify a backlog. Recorded figures are in
[docs/46](46-PERFORMANCE-REPORT.md).
