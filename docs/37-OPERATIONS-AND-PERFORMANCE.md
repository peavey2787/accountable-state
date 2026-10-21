# Operations: recovery, performance, APIs

## Recovery and storage

* `<artifact>.evidence-ledger` is an append-only record file (`audit/store.rs`): each record
  is length-prefixed and checksummed, synced on append, and on open the longest valid prefix
  is kept and a torn or corrupt tail is truncated. Total size is capped at 256 MiB.
* `<artifact>.auditlog` is the audit log snapshot, saved atomically every 5 s. Heads are
  recomputed on load, so a corrupt file cannot smuggle in a forged head.
* On restart the demo calls `Auditor::restore(log, evidence)`: the log is adopted only if it
  is this player's, for this match, and at least as long as the live one; every persisted
  evidence record is re-verified and silently dropped if it no longer verifies.
* Pruning keeps the newest 8192 entries and never passes a pin (`AuditLog::pin`). Challenges
  are answered synchronously on receipt, so no range needs to stay pinned between messages;
  a `LogSegment` request for an already-pruned range gets no answer (never a fabricated
  one), so the challenger ends at SUSPECTED / UNAVAILABLE, not at a proof.
* `--resume=ARCHIVE` replays the certified-epoch archive from canonical genesis.

## Performance (this machine, 2 native processes, encrypted Hydra P2P, 20-tick epochs)

Same definitions as the baseline run (`scripts/bench-realtime-linux.sh`, `BENCH_SECONDS=20`).
The baseline column is the earlier recorded figure; "after" is a fresh run of this tree.

| Metric | Baseline | After (this tree) |
|---|---|---|
| Simulation | 60 Hz | 60.0 Hz (min 60.0, max 60.1; jitter median 0.50 / max 0.70 ms) |
| Input -> screen | p50 ~12.6 ms | p50 12.6, p95 13.6, max 14.5 ms (n=60) |
| Finality | p50 ~17, p95 ~20 ms | p50 20.0, p95 25.0, max 27.0 ms (n=122); none over 100 ms |
| CPU per process | ~14 % of a core | 15.5 % / 15.2 % |
| Payload per direction | ~252 kbps | median 252.6 tx / 252.9 rx, max ~397 kbps |
| Rollbacks | n/a | (95, 211), max depth 2 ticks; 0 violations |
| Hide (5 s window) | n/a | all hidden epochs certified 272 ms after close |

Finality is ~3 ms slower at p50 and ~5 ms at p95 than the baseline, and CPU ~1 point higher;
both are within run-to-run variation on a shared machine but are reported as measured, not
as parity. p99 is not emitted by the bench script; max stands in. Memory and evidence
backlog are not captured by this script. Signing cost is ML-DSA-65 (~0.5 ms sign, ~0.05 ms
verify); attribution was not weakened to gain speed (pairs are filtered by overlapping
ticks / same epoch slot before any signature is checked). An idle match sends only
keep-alives.

Reproduce: `scripts/bench-realtime-linux.sh` (`BENCH_SECONDS=20`),
`cargo run --release -p gv-edge-p2p-demo -- bench-sig`, `... bench-hydra`.

## Commands and APIs

```
run-all-linux.sh                    # fmt, clippy -D warnings (all features), tests, JS vectors
scripts/smoke-arena-linux.sh        # real encrypted two-process match, Hide cycle
scripts/headless-arena-linux.sh     # demos + offline verification of every evidence file
scripts/play-arena-linux.sh         # two windows to play
gv-edge-p2p-demo verify <artifact> <match-id-hex> <alice.pub> <bob.pub>   # offline verify
gv-edge-p2p-demo vectors <dir>      # regenerate interoperability vectors
```

Demo flags (`run ...`): `--cheat-at`, `--illegal-at`, `--equivocate-at` (sign two histories),
`--withhold-at` (stop answering challenges: suspicion then cleared), `--accuse-falsely-at`
(framing attempt that proves nothing), `--hide-at`.

Library surface (`gv-edge`): `audit::{AuditLog, Authenticator, Segment, Evidence, Proof,
Ledger, Outcome, Challenge, Response, ChallengeBook, ChallengeGate, Status,
compare_authenticators, assign_witnesses, missing_ids}`, `audit::store::RecordFile`,
`live::{Auditor, AuditEvent, AuditStats, Answers}`. `gv-sig`: `SigningKey`, `verify`,
`register_key`, `envelope_digest`, `Signature`, key-file codecs.

GUI: the Accountability panel shows pending challenges, proven fraud/equivocation, suspected,
cleared and evidence files/bytes (with a persistence error flag); finality, FPS and input
latency are in the telemetry panel. The red indicator reflects only cryptographic proof.
