# Wire formats (all V1)

Integers are little-endian. Every decoder checks lengths before allocating, rejects trailing
bytes and non-canonical encodings, and bounds counts.

## Accountability objects

| Object | Magic / label | Layout |
|---|---|---|
| Log entry | – | `kind u8 ‖ len u32 ‖ payload` (payload <= 64 KiB) |
| Chain head | `gv/audit/chain/v1\0` | `head_n = H(domain ‖ match ‖ owner ‖ seq ‖ head_{n-1} ‖ kind ‖ H(payload))`; genesis `H("gv/audit/genesis/v1\0" ‖ match ‖ owner)` |
| Authenticator | `gv/audit/authenticator/v1` | `match ‖ ruleset ‖ owner ‖ seq u64 ‖ head ‖ ML-DSA sig` (3445 B) |
| Segment | – | `match ‖ owner ‖ start_seq ‖ prev_head ‖ count ‖ entries` (<= 4096 entries) |
| Log snapshot | `GV-AUDIT-LOG/V1\0` | magic ‖ segment; heads are recomputed on load |
| Challenge | `gv/audit/challenge/v1` | signed: match, challenger, target, nonce u64, kind, issued_tick, deadline_tick |
| Response | `gv/audit/response/v1` | signed: challenge id, responder, payload (<= 1 MiB) |
| Evidence | `GV-ACCOUNTABILITY-EVIDENCE/V1\0` | magic ‖ tag u8 ‖ length-prefixed parts (<= 1 MiB total) |
| Evidence id | `gv/audit/evidence-id/v1\0` | hash over the tag and the sorted parts (fork keeps its order), so either discovery order gives one id |
| Record file | – | `[u32 len][8-byte SHA-256 prefix][payload]`, longest valid prefix kept (<= 256 MiB) |

Evidence tags: 1 conflicting authenticators, 2 fork (earlier + later authenticator + segment
starting at `earlier.seq`), 3 conflicting batches, 4 conflicting checkpoints.
Challenge kinds: `MissingBatch`, `Ack`, `LogSegment`, `MerkleWitness`, `HiddenReveal`, `Replay`.

## Gameplay objects

| Object | Label / magic |
|---|---|
| Packed controls (`GVEC`) | `gv/packed-controls-signed/v1`, hash domain `gv/packed-controls-hash/v1` |
| Aggregate (`GVAG`), chunk (`GVKC`) | `gv/packed-aggregate-hash/v1` |
| Checkpoint | signed claim binding match, ruleset, epoch start/length, previous checkpoint and state, input root, next state |
| Blinded batch commitment | `gv/admission/blinded-batch/v1` (see [33](33-HYDRA-MLDSA-INTEGRATION.md)) |
| Live pipe messages | gameplay and hide messages use tags below 7; 7 `Auth`, 8 `Challenge`, 9 `Response`, 10 `Evidence` |
| Certified match archive | `GV-CERTIFIED-MATCH/V1\0` |

Golden vectors: `tests/interoperability/`. Earlier prose specs (docs 06, 22, 24) describe the
same objects in more detail; where they differ on signature algorithm or length, this
document wins.

## Sizes (ML-DSA-65)

A signed object is its body plus 3309 B. Authenticator 3445 B; checkpoint and batch about
3.5 KB each. At 3 epochs/s per peer that is about 10 KB/s of signed traffic.
