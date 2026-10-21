# 19 — Protocol state machines and transition tables

This describes target behavior to implement and model-check. The current code does **not** implement these asynchronous machines. All timestamps are authenticated *logical* deadlines relative to an agreed clock/tick policy, not the local time of an untrusted client.

## Match state machine

```text
CREATED -> MANIFEST_LOCKED -> GENESIS_CERTIFIED -> RUNNING
RUNNING -> PAUSED_PARTITION | MATCH_END_PROPOSED
PAUSED_PARTITION -> RUNNING | ABORTED
MATCH_END_PROPOSED -> CHALLENGE_WINDOW
CHALLENGE_WINDOW -> DISPUTED -> (CHALLENGE_WINDOW | ABORTED)
CHALLENGE_WINDOW -> APP_FINAL -> OPTIONAL_SETTLEMENT -> ARCHIVED
```

- `CREATED`: proposed participants and game version; no inputs authoritative.
- `MANIFEST_LOCKED`: signed policy, roster/epochs, visibility and retention fixed; invalid genesis proposals rejected.
- `GENESIS_CERTIFIED`: trusted spawn/world state root accepted by authorized policy, all players receive match ID and public ruleset.
- `RUNNING`: ordered signed inputs and authenticated checkpoint chain; local predictions distinct from accepted state.
- `PAUSED_PARTITION`: insufficient quorum or data custody; cannot settle or irrevocably finalize.
- `MATCH_END_PROPOSED`: terminal state under pinned game logic, eligible reveal obligations issued.
- `CHALLENGE_WINDOW`: state still provisional until all required openings and deadlines pass.
- `DISPUTED`: accepted scoped challenge; conflicting candidate descendants paused; evidence independently checked.
- `APP_FINAL`: BFT/canonical consensus and fraud-window requirements passed; final result is scoped and signed.
- `OPTIONAL_SETTLEMENT`: chain proof or attestation submitted under the preset settlement policy; separate chain finality.
- `ARCHIVED`: signed checkpoints, evidence, full retained witness per retention schedule; confidentiality preserved by policy.

## Per-checkpoint state machine

| From | Trigger | Checks | To |
|---|---|---|---|
| Proposed | Validated header, parent and input batch | Roster, exact ruleset, count, authorized signature, correct tick and safe parent | Prepared |
| Prepared | Custody quorum obtained | Hash/chunk/expiry validity and storage receipts | Available |
| Available | BFT vote/commit phases complete | Lock safety, quorum, round and ancestry | CertifiedProvisional |
| CertifiedProvisional | Challenge arrives within window | Bound proof hash, admission, no duplicate abuse | Challenged |
| CertifiedProvisional | Window elapses with required reveals complete | No unresolved challenge, safe chain | AppFinal |
| Challenged | Independent fraud reproduction succeeds | Accepted claim and exact witness or pinned ZK | Invalidated |
| Challenged | Evidence refuted | Authorized signed verdict, remain within deadline | CertifiedProvisional |
| Challenged | Data irretrievable or disputed verifier error | Recovery/forfeit policy; no false conviction | PausedOrInconclusive |
| Invalidated | Canonical correction authorized | BFT safe rollback/restart before application finality | Superseded |
| AppFinal | Optional chain settlement confirmed | Target chain finality/reorg policy | Settled |

**Forbidden:** `Proposed -> AppFinal` directly, `Invalidated -> AppFinal` silently, and `AppFinal -> Superseded` without explicit appeal/recovery protocol. Custody quorum is not vote quorum. A missing reveal is never converted to `InvalidTransition` without replay evidence.

## Challenge state machine

`CREATED -> ADMITTED -> WITNESS_AVAILABLE -> REPRODUCED -> VERDICT_CERTIFIED -> CLOSED`.

Alternative terminal states: `REJECTED_MALFORMED`, `REJECTED_EXPIRED`, `REJECTED_REFUTED`, `INCONCLUSIVE`, and `TIMEOUT_POLICY_APPLIED` (not a semantics conviction). Every state transition is signed, ordered and replay-resistant. A challenge opening is idempotent; duplicate challenges against identical committed witness are deduplicated.

## Crash recovery

Durably persist: current epoch/round, highest lock QC, last vote record, accepted checkpoint, committed DA receipts, queued challenges, disclosure deadlines, and finality status. On restart, verify data digest and authenticated recovery certificate; never cast a vote at a lower/equivocating slot. Receipt creation must occur **after** authenticated data is written durably. Replay pending outbox messages idempotently to prevent lost accepted inputs or duplicate penalties. Validators restarting with unavailable WAL MUST quarantine themselves until resynchronized from an independently certified checkpoint.

## Network partitions

Quorum loss pauses new app-final transitions. Peers may continue harmless predicted rendering locally but must label results provisional and roll back to the last safe checkpoint on reconnection. Under partition, different players can each have a local candidate; neither candidate is globally canonical until valid consensus certificate and ancestry are established. No fabricated 'cheat detected' event is emitted merely from missed heartbeats.

## r3 signed event batching / independent 1v1 evidence

A new transport branch precedes admission: `SIGNED_PACKED -> {INLINE_PLANNED | ROOT_COMMITTED} -> TX_CONFIRMED_OR_DA_CERTIFIED -> INPUT_ADMITTED`. An inline plan is **not** accepted until the real wallet/node validates serialized signed txs, actual chain inclusion and canonical chunk reassembly. Fraud evaluation remains a deterministic transition independent of any vote. See [r3 protocol](22-INPUT-PACKING-AND-DECENTRALIZED-1V1.md).
