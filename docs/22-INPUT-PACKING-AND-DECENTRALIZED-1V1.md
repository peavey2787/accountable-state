# 22 — Event-packed inputs, generic chunking and size accounting, decentralized 1v1 disputes

**Status:** implemented in `crates/codec` (`GVEC`, `GVAG`, `GVKC`); no network, wallet or blockchain dependency. Chunking and size accounting are generic: the caller supplies the size budget of whatever carrier it uses (a file, an object store, a message queue, a settlement system).

## Inline when small, hash-only when not

No technique guarantees that hours of arbitrary control or aim data fit in a few records. Digital, event-driven controls are small; high-frequency analog input is not. The SDK therefore:

1. Canonically encodes and *authenticates* each player's input stream; one signature authenticates a bounded batch, not every tick.
2. Optionally groups several signed streams and matches into a canonical aggregate (`GVAG`) and keeps the original player signatures.
3. Measures the **actual** encoded bytes and plans against the caller's limits (`gv_codec::chunks::plan`). If the aggregate fits within `max_chunks` chunks of `payload_ceiling - application_headroom`, the result is `Chunked`; otherwise `HashOnly` (carry only the aggregate hash; the bytes need independent custody and retrieval).
4. Never silently truncates, discards or lossy-compresses signed input to get under a cap. A game may explicitly quantize analog input *before signing* as part of its immutable rules.

The defaults (`24 KiB` ceiling, `256 B` headroom, 4 chunks) are illustrative only. Chunking provides no ordering, timestamping or availability guarantee; the aggregate digest authenticates the reassembled whole, and a chunk set that does not reassemble to the expected digest is rejected.

## Worked size examples (payload-only lower bounds)

Assume 2 control changes per player per second at 3 bytes per change:

| Activity | Event data only |
|---|---:|
| 1v1 × 10 minutes | `2 * 600 * 2 * 3 = 7,200 B` |
| 1v1 × 1 hour | `2 * 3600 * 2 * 3 = 43,200 B` |
| 16 players × 10 minutes | `16 * 600 * 2 * 3 = 57,600 B` |
| 1v1 × 1 hour × 60 Hz × 4 B analog | `2 * 3600 * 60 * 4 = 1,728,000 B` |

Sizes are derived from real encoded records with ML-DSA-65 signatures (3309 B each). `crates/codec` test `packing_size_vectors` encodes the scenarios and checks them against `tests/interoperability/packing_sizes_v1.json`; `scripts/bench-packing.mjs` independently recomputes the same numbers from the wire layout and asserts equality. Bytes only; nothing here models any carrier's fees or acceptance rules.

| Scenario (per-player aggregates, <= 4096 records each) | Records | Aggregates | Bytes |
|---|---|---|---|
| 1v1, 10 min, 2 changes/s, one record per player | 2 | 2 | 11,664 |
| 1v1, 1 h, 2 changes/s, one record per player | 2 | 2 | 35,666 |
| 16 players, 10 min, 2 changes/s, one record per player | 16 | 16 | 93,312 |
| 1v1, 1 h, 8-bit state changing every tick (60 Hz worst case) | 2 | 2 | 870,868 |
| 1v1, 10 min, 2 changes/s, live 20-tick epochs | 3,600 | 2 | 12,339,614 |
| 1v1, 1 h, 2 changes/s, live 20-tick epochs | 21,600 | 6 | 74,037,642 |

The last two rows are what the live game's per-epoch signing costs if every signed batch is archived verbatim (about 165 kbit/s averaged for two players, dominated by one 3309 B signature per 20 ticks). Batching more ticks per signature (the first rows) is roughly 100x smaller; the live epoch length trades signature cost against accountability latency. Earlier revisions of this document quoted figures computed with 64 B signatures; those were wrong for ML-DSA-65 and have been removed.

## Codec v1 (`crates/codec`)

Versioned `PackedControls` stores **digital button-state changes**, not raw XYZ. It is a *state-stream codec*, not a replacement for the canonical game rule that transforms controls into state. Fields, in exact byte order:

```text
GVEC (4 ASCII bytes)
version: u8 = 1
control_bytes: u8 = 1 or 2
match_id: bytes32
player_id: bytes32 = SHA-256("gv/player-id/v1\0" || alg || ML-DSA-65 verifying key)
previous_batch_hash: bytes32
start_tick: u64 LE
tick_count: u32 LE (>0, <=5_184_000)
initial_state: u8 or u16 LE based on control_bytes
change_count: minimal unsigned LEB128 u32
repeated change_count times:
    delta_tick_from_prior_change: minimal unsigned LEB128 u32, >0
    new_state: u8 or u16 LE; MUST differ from previous
signature: ML-DSA-65, 3309 bytes (over the envelope digest of the complete encoded GVEC record)
```

- A change at tick offset zero is represented by the `initial_state`; events have offsets strictly increasing within `[1, tick_count - 1]`. No gaps are encoded into the button-state timeline: current state holds until the next event.
- Signature message is `"gv/packed-controls-signed/v1\\0" || GVEC_BYTES` (the `\\0` denotes one actual NUL byte). Verify ML-DSA-65 against the key registered for `player_id`; distinct keys for wallets and game identities.
- The hash binding `previous_batch_hash` is `SHA256("gv/packed-controls-hash/v1\\0" || GVEC_BYTES || player_signature)`. First batch must reference the match-authorized genesis stream commitment; this codec alone cannot authenticate that genesis.
- Maximum encoded record 8 MiB, 1,000,000 change events; decoder rejects unknown versions, nonminimal integers, truncated records, trailing bytes, overflow, impossible ticks, redundant states and bad signatures.
- `GVAG` v1 aggregate is `magic(4) || version(u8) || record_count(minimal ULEB128) || (signed_record_len(minimal ULEB128) || signed_record)*`. Max 4096 records / 32 MiB. Records strictly sorted by `(match_id, player_id, start_tick)`. Consecutive batches for one player must have contiguous time ranges and reference the prior signed digest; first batches remain subject to a separate authenticated match/genesis manifest.
- Aggregate hash: `SHA256("gv/packed-aggregate-hash/v1\\0" || GVAG_BYTES)`. No cryptographic privacy is provided by bit packing; it must not be posted before any required secrecy period ends.

`gv-codec` is **not an entropy compressor**, does not store analog values, does not define network tick deadlines, does not promise cross-platform physics determinism, and does not independently prove correct playback of a match. Those require later game adapters, end-to-end vectors and replay tests.

## Generic chunk envelope (`gv_codec::chunks`)

- Input: a validated, signed `GVAG` aggregate and `Limits { payload_ceiling, application_headroom, max_chunks }`.
- Output: `Chunked { chunks, aggregate_hash }` or `HashOnly { aggregate_hash, bytes, required_chunks }`; failure on a zero or impossible budget, overflow or an oversized aggregate.
- `GVKC` v1 chunk: `magic(4) || version(1) || GVAG_digest(32) || chunk_index(u32 LE) || total_chunks(u32 LE) || chunk_len(u32 LE) || content`. The 49-byte header counts inside `payload_ceiling`. Reassembly requires contiguous indices from zero, matching totals, exact lengths and a digest that matches the expected one, and the result must decode as a valid aggregate.
- An adversary may offer different sets of individually valid chunks; the match must agree on the expected aggregate digest before chunks are admissible. The envelope has no authentication of its own beyond that digest.
- The live witness protocol uses its own bounded chunking for large evidence packages ([36](36-CHALLENGES-WITNESSES-EVIDENCE.md)) because the real transport caps a message at 512 KiB.

## Decentralized 1v1: proof of fraud is NOT two-node consensus

A single honest player may expose an authenticated *safety violation* and convince any independent verifier without votes, once the previous accepted state, player attribution, ruleset and admissible input history are established.

A separate question arises when the two parties disagree on whether an input was timely received, or one refuses to cooperate. Under arbitrary asynchrony and one Byzantine player, two-party communication alone cannot guarantee both agreement and progress. A cryptographic proof cannot invent a missing message. Options, chosen per game:

1. **Bilateral signed admission (optimistic 1v1):** both acknowledge accepted input sets or periodic roots. Valid bilateral certificates are immutable evidence; a withholding party may force a timeout, a stalemate or a predefined forfeit; there is no unilateral finality for new conflicting sets. This is what the SDK implements.
2. **Independent witnesses:** enrolled third parties relay and independently verify evidence ([36](36-CHALLENGES-WITNESSES-EVIDENCE.md)). They are never gameplay authorities and never vote on objective validity.
3. **An agreed external ordering service:** a game may choose one for admission deadlines; it is outside this SDK.
4. **Referee:** a host or server supplies admission and finality if the game opts in. A separate profile, not the decentralized default.

A deterministic `tick,player,sequence` sort only orders the same *known set*; if the admitted sets differ, sorting does not create consensus.

## One valid proof, objective disputes, deterministic resolution

- Anybody may submit an evidence object. Submission requires no validator quorum.
- Each verifier authenticates the match genesis, canonical admitted input set / prior checkpoint, claimed state signed by the alleged author, Merkle/chain/inclusion evidence, canonical ruleset, and a complete witness. The verifier independently returns `PROVEN_RULE_VIOLATION`, `PROVEN_EQUIVOCATION`, `NOT_PROVEN`, or `UNAVAILABLE/PROTOCOL_TIMEOUT`.
- **No majority vote on the truth of a proof**. A challenger can disprove a false accusation by pointing out an invalid signature, a wrong state anchor, a malformed inclusion proof, a missing dependency, a wrong ruleset, or by reproducing the *legal* transition. All observers compute the same verifier output on the same authenticated facts.
- Distinguish player-originated invalid signed state claims from validator/sequencer fabrication. Never punish a player for a claim someone else forged, or a mere failed delivery as a physics cheat.
- Counterproof threads must not become a path to permanent unfinalizability. Each distinct cryptographic claim is independently checked with a bounded witness, verifier version, challenge-ID, memory/CPU budget and precommitted deadline. A wrong allegation is `NOT_PROVEN`; repeated duplicates do not delay finality. Late evidence is preserved for appeals and reputation adjustments under a published governance policy.
- A *fraud proof* is not necessarily a zero-knowledge proof. A record that does not carry all witness bytes is only a commitment unless a verifier actually checks a pinned succinct predicate; a Merkle root or allegation hash posted alone proves nothing.

## Privacy, withholding and retention

Publishing raw input batches anywhere public reveals strategy, aim and timing; do it only after the allowed disclosure ([38](38-EVIDENCE-EXPORT.md) has an explicit disclosure policy). If gameplay needs hidden enemy positions or unrevealed cards, prefer private P2P streams, encrypted custody and selective disclosure. Retain the full signed inputs and state openings until fraud windows and appeals have elapsed; availability cannot be inferred from a root.
