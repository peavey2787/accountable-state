# 07 — Inputs, acceptance, deterministic replay, and fraud bisection

## Transcript lifecycle

An input record is `(match_id, player_key, tick, per_player_sequence, input_bytes, signature)`. A receiving peer validates size, bound identity, signature, monotonic sequence and any game-domain-specific input schema. Peers attach authenticated receipt time/tick only according to match policy. The global sequencer/consensus orders valid inputs for each tick before producing a batch root. All players then independently derive the same next state from the same previous state and the same ordered batch. The claimed state root plus batch root enters a checkpoint; its quorum authorization does not exempt it from replay.

Provisional checkpoint acceptance requires:

1. Genesis/parent checkpoint is known and authorized.
2. Match/epoch/ruleset/tick/parent identities match the accepted chain and roster.
3. All included inputs have acceptable signatures, ordering and bounds.
4. Data availability conditions are satisfied before validators sign custody/acceptance.
5. A quorum certificate meets the declared validator policy.
6. Checkpoint remains challenged/appealable until the agreed fraud window closes.

Independent game replay starts from a trusted opening/snapshot `S0`. For each accepted input batch `I_t`, calculate `S_{t+1} = F_v(S_t, I_t)` under the pinned ruleset `v`. Compare committed state serialization and additional public output checks. Use immutable simulation rules and no nondeterministic data access. A replay can terminate early when it identifies the first invalid accepted transition, or can generate a trace of intermediate states to minimize evidence.

## Replay fixture format — planned

```text
case_id, ruleset_hash, input_format_version, tick, initial_state_bytes,
ordered_input_bytes[], expected_next_state_bytes,
expected_rejection_code | none, source_platform, provenance
```

Fixtures must include real-world physics/animation interactions and boundary values. Exact bytes are authoritative—not pretty-printed JSON or screenshots. Test Windows/Linux/browser release builds against the same fixture corpus and fail on a single bit mismatch. Use checked fixed-point types for physics where possible; for faithfully reverse-engineered legacy games, preserve original semantics in the canonical verifier rather than blindly rewriting behavior.

## State checkpoints and witness generation

To avoid replaying the entire game for every challenge, custodians retain a periodic full state snapshot plus authenticated transcript slices. Checkpoint interval affects witness size and DoS resistance. Snapshots are not independently authoritative unless tied to a quorum-certified chain and a verified transition from an earlier trusted checkpoint. When a challenged tick is far from a trusted snapshot, use replay/bisection to isolate the first differing tick; verify both the witness and its membership in the accepted transcript.

## Multi-player interactions

Each global transition must commit to the entire ordered batch and relevant shared world state. It is insufficient to replay only accused Alice's signed move if Alice's legal movement depends on Bob's collision, projectile, ability, or world event. Fraud evidence then contains a minimal authenticated neighborhood of inputs and state or a succinct pinned proof that the correct global transition was not followed. The prototype `examine_single_step` supports only **one signed input and exactly one transition**; no claim of full multi-player fraud support is made.

## Concurrency and causality

A tick is a logical number, not a client OS timestamp. The match defines accepted input window, duplicates, late delivery, deterministic tie-breakers, causally dependent actions, rollback horizon and simultaneous collision resolution. Predicted state may be displayed immediately to maintain responsiveness but is never irrevocably authoritative until certified/finalized. Replay all accepted inputs in a single canonical sequence; forbidding inconsistent reads across asynchronous systems is essential.

## Transcript omissions

A valid membership proof doesn't prove completeness. Detect omitted valid inputs by collecting signed acceptance receipts and including admission receipts (or their digest/root) into the ordered log; define expiration for tardy inputs. Equivocation about input ordering is separately punishable with contradictory signed QCs or proposals under consensus rules. If the complete witness is unavailable, classify as availability fault and run the agreed timeout/forfeit policy instead of fabricating a successful replay.

## r3 signed event batching / independent 1v1 evidence

A replay verifier may decode a signed held-control stream into individual tick controls; it must bind the **complete accepted input set** and previous checkpoint, not invent omitted input messages. Single batch signatures authenticate every derived tick state under pinned codec v1, but the batch does **not itself** prove timely admission, physics validity, or signed output ownership. See [r3 batching](22-INPUT-PACKING-AND-DECENTRALIZED-1V1.md).

## Native edge demonstration

See [23](23-EDGE-P2P-PROOF-OF-CONCEPT.md) for a two-player canonical loop where signed `GVEC` batches are sorted by authenticated player ID, expanded per tick, independently replayed by both clients, added to a SHA-256 Merkle log, and committed with *two* identical ML-DSA-65-signed checkpoints. Certified receipts are exportable. This is a bounded 1v1 public-state PoC, not the full generalized game ordering or durable streaming log.
