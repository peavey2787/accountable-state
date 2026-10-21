# Operations: recovery, performance, APIs

## Recovery and storage

* `<artifact>.evidence-ledger` is an append-only record file (`audit/store.rs`): each record
  is length-prefixed and checksummed, synced on append, and on open the longest valid prefix
  is kept and a torn or corrupt tail is truncated. Total size is capped at 256 MiB.
* `<artifact>.auditlog` is the audit log snapshot, saved atomically every 5 s. Heads are
  recomputed on load, so a corrupt file cannot smuggle in a forged head.
* On restart `AccountableState::open` calls `Auditor::restore(log, evidence)`: the log is adopted only if it
  is this player's, for this match, and at least as long as the live one; every persisted
  evidence record is re-verified and silently dropped if it no longer verifies.
* Pruning keeps the newest 8192 entries and never passes a pin (`AuditLog::pin`). Challenges
  are answered synchronously on receipt, so no range needs to stay pinned between messages;
  a `LogSegment` request for an already-pruned range gets no answer (never a fabricated
  one), so the challenger ends at SUSPECTED / UNAVAILABLE, not at a proof.
* `Config::resume` replays the certified-epoch archive from canonical genesis.

## Performance

End-to-end measurements (60 Hz, finality, CPU, bandwidth over encrypted Hydra P2P) are taken
with the [anti-cheat](https://github.com/peavey2787/anti-cheat) arena and documented there. ML-DSA-65 cost:
`cargo run --release -p gv-sig --example bench`.

## Commands and APIs

```
run-all-linux.sh                    # locked validation, then newest-main compatibility
cargo run -p gv-codec --example interop_vectors -- tests/interoperability   # regenerate vectors
```

Facade (`accountable-state`): `AccountableState::{open, submit, receive, poll, state,
subscribe, export}`, `Verifier::verify_package`; feature `fault-injection` adds
`inject_false_checkpoint`, `equivocate_next`, `withhold_answers`, `accuse_falsely`.

Library surface (`gv-edge`): `audit::{AuditLog, Authenticator, Segment, Evidence, Proof,
Ledger, Outcome, Challenge, Response, ChallengeBook, ChallengeGate, Status,
compare_authenticators, assign_witnesses, missing_ids}`, `audit::store::RecordFile`,
`live::{Auditor, AuditEvent, AuditStats, Answers}`. `gv-sig`: `SigningKey`, `verify`,
`register_key`, `envelope_digest`, `Signature`, key-file codecs.
