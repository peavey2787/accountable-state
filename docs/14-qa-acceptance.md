# 14 — Security QA, executable gates, and release acceptance

## Acceptance rule

**No production-ready label until independent code review and executable checks substantiate every claimed guarantee.** A compiled Rust workspace is not the same thing as proof of Byzantine consensus safety or on-chain Groth16 soundness. All checks are required to fail closed with actionable diagnostics. The package-building environment did not have Rust tooling, therefore compile/test status must be verified by the recipient.

## Build and quality gates

From repository root use `./run-all-linux.sh` (Linux/macOS) or `run-all-windows.cmd` (Windows). These refresh p2p-net to its newest main, then run read-only `cargo fmt --all -- --check` (run `cargo fmt --all` manually to repair formatting), then `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace --all-targets`. Before release additionally run `cargo audit` on lockfile, `cargo deny` for licensing/dependencies if installed, `cargo llvm-cov` or suitable coverage tooling, Miri where supported, fuzzing, and secret scanning. CI should pin Rust toolchain and all dependencies with a committed Cargo.lock after it is generated, and compile in release mode on target architectures.

## Required vectors and negative tests

| Topic | Positive | Adversarial/negative |
|---|---|---|
| SHA-256/Merkle | Empty, 1, 2, odd 3/5/17 leaves, exact byte vectors | Wrong count/index, excessive/fewer path siblings, altered leaf, wrong odd edge, replay wrong domain |
| Signatures | Independently verified ML-DSA-65 vectors (OpenSSL) | Wrong match/epoch/key/sequence, altered payload, duplicate key, invalid point/sig, noncanonical encoding |
| Commit/reveal | Nonce and opening restore exact locked choice | Different state, empty/weak nonce, dictionary attack demonstration, wrong domain/round/player |
| Replay | Full real game golden fixtures Windows/Linux/WASM identical | Overflow, negative/NaN/infinite, race, nondeterministic RNG, buff/collision/teleport edge cases |
| Fraud | Accepted malicious proposed transition produces reproducible contradiction | Honest accused, fabricated accepted root, unrelated signed input, omitted inputs, fake roster, altered witness |
| QCs | `n=4,f=1,q=3`, authenticated epoch/round | Double-signing, roster injection, 2 vs 3 signatures, duplicate, excessive roster size, wrong lock, restart vote reuse |
| P2P | Reordering, reconnect, partial outage, recovery | Eclipse, Sybil roster, withheld reveal, equivocation, partition, delayed packet, replay, congestion |
| Data custody | Signed durable receipts, retrieval, repair | Missing chunks, false receipts, ciphertext-only keys missing, expiry before challenge, crash mid-write |
| Privacy | Owner/team/view denial tests and delayed reveal | Opponent wallhack receive, spectator/telemetry leak, side-channel IDs/timing, post-match overdisclosure |
| External publication | Export package round-trips and verifies offline ([38](38-EVIDENCE-EXPORT.md)) | Tampered, truncated, wrong-anchor, oversized and wrong-domain packages are rejected |
| Resource | Bounded frame sizes, memory, CPU, proof depth | Decompression bomb, giant batches, timeouts, unbounded recursion, costly malformed proof |

## Fault-injection campaigns

1. Kill/restore validators immediately before/after durable lock/vote and DA receipt; prove no double-signing.
2. Reorder/delay/drop 5–50% of messages, with eventual recovery under partial synchrony; verify quorum safety and liveness assumptions.
3. Run `n=3f+1` with all combinations of up to `f` malicious validators, including malicious proposer and equivocation.
4. Corrupt persisted checkpoints/custody chunks and replay from durable verified parent.
5. Trigger simultaneous competing fraud challenges during the last tick of challenge window.
6. Test data withholding by producer and multiple custodians and ensure *forfeit* is not called cryptographically proven physics cheating.
7. Send deliberately hidden enemy state through all output channels and assert unauthorized observer receives no bytes.
8. Cross-check proof-generation inputs against a second verifier implementation, with mutation tests for missing input and missing accepted-root bindings.

## Security coverage targets

For future development, target 100% coverage for safety-critical crypto encoding branches, canonical parser rejection and fraud proof acceptance, with mutation and property testing on all invariants. Coverage percent alone does not establish cryptographic soundness. Add formal/model checking of quorum locking, view change, checkpoint ancestry and challenge/finality transitions. Test actual player hardware performance before adopting any proof batching cadence.

## Release gate states

- `DESIGN`: described only.
- `IMPLEMENTED_UNVERIFIED`: source exists, no full execution validation.
- `UNIT_VERIFIED`: portable unit tests pass.
- `INTEROP_VERIFIED`: independently produced Rust/JS/native golden vectors pass.
- `ADVERSARIAL_VERIFIED`: fuzz, chaos, Byzantine/finality/data availability tests pass.
- `SECURITY_REVIEWED`: independent audit and corrective tests complete.

Each module gets a separate state. As delivered, cryptographic helper code exists but tests have not been run in the packaging environment; most distributed-system and ZK items remain `DESIGN`.

## r3 signed event batching / independent 1v1 evidence

Added r3 gates: canonical `GVEC/GVAG/GVKC` independent golden vectors; event-state determinism; strict signed batch reconstruction; replays with missing preceding batch; malformed/truncated/nonminimal varints; duplicated/missing/reordered chunks; max aggregate and input budget; 1v1 unilateral valid evidence with a silent malicious opponent; chain acceptance simulation vs node actual mass/fees. See [r3 acceptance criteria](22-INPUT-PACKING-AND-DECENTRALIZED-1V1.md).
