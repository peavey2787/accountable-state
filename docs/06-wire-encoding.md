> **Note.** Player/accountability signatures are ML-DSA-65 over a SHA-512 envelope digest; the authoritative byte layouts are in [docs/34](34-WIRE-FORMATS.md).

# 06 — Canonical wire/signing formats and version negotiation

**Implemented subset:** v1 exact signed-input preimage, Merkle-leaf hashing, checkpoint signature preimage, state commitments. A complete external wire framing and cross-language vector suite are still future acceptance requirements. This document specifies the intended production format; unspecified types MUST NOT be silently decoded as if already standardized.

## Envelope v1 — proposed framing

```text
magic[4] = ASCII "GV01"
protocol_version: u16 LE
record_type: u16 LE
flags: u16 LE (reserved bits MUST be zero)
match_id: [u8;32]
epoch: u64 LE
sequence: u64 LE
payload_length: u32 LE
payload: [u8;payload_length]
authenticator: record-specific, exactly bounded
```

All fields are fixed-width unsigned integers unless described otherwise. Lengths MUST be checked prior to allocation. No trailing bytes, alternate representations, noncanonical varints, implicit JSON maps, duplicate keys, float encodings or unchecked UTF-8 conversion. Network message framing is **not** the ML-DSA-65 input signing preimage; both have separately versioned domains. Implementations MUST NOT sign a parsed abstract object and verify a different serialization.

## Proposed record types

| Type | Body and security meaning |
|---|---|
| 1 MATCH_MANIFEST | Version, identities, game code/ruleset hash, genesis, validator roster, policy hashes |
| 2 PLAYER_INPUT | Current implemented `SignedInput` signing payload + signature |
| 3 INPUT_BATCH | Canonical ordered list of authenticated inputs, tick range, root |
| 4 CHECKPOINT | Signed checkpoint header fields + QCs |
| 5 AVAILABILITY | Chunk root, blob length, custody duration, signer, signature |
| 6 CHALLENGE | Accepted checkpoint, accused claim, challenge type, evidence hash, bond |
| 7 REVEAL | Committed data, nonce/opening, authorization scope, deadline reference |
| 8 FRAUD_EVIDENCE | Signed attribution, Merkle path, prior state witness, invalid transition witness |
| 9 VERDICT | Exact verifier version, statement/reason, evidence digest, quorum signatures |
| 10 FINALITY | Certified checkpoint and passed challenge deadline |
| 11 EQUIVOCATION | Two conflicting signatures for same exclusive slot |
| 12 ZK_CLAIM | Public statement, circuit/image ID, proof-system tag, proof blob bounds |

Unknown mandatory types or versions MUST fail closed. Unknown *optional* extensions MAY be ignored only if explicitly allowed by a negotiated extensibility profile and not referenced by signed consensus semantics.

## Checkpoint signing payload v1 (implemented)

The existing `CheckpointHeader::signing_bytes()` forms:

```text
"gv/checkpoint/v1\\0" || match_id32 || epoch_u64 || round_u64 ||
tick_u64 || ruleset32 || previous_state32 || input_root32 ||
next_state32 || parent_checkpoint32
```

The signed player **state-output claim** (now also in the prototype) has preimage
`"gv/state-claim/v1\0" || match_id32 || player_pubkey32 || tick_u64_le || previous_state32 || proposed_next_state32 || input_root32 || ruleset32`.
This distinguishes a player's claim of a false result from a situation where a validator fabricated the result despite receiving a valid input.

The validator set is determined by an independently authenticated match manifest (and epoch transitions); it is not chosen by the sender of a checkpoint. Signatures over these bytes are ML-DSA-65; no quorum certificate exists in the SDK.

## Canonical ordering policy

Each input must have `(tick, player_key, per_player_sequence)` and a signed acceptance receipt or a canonical ordering decision. Ordering **must** be determined before replay, with conflict/dedup handling. For simultaneous actions, the game manifest must specify deterministic tie-breakers or globally ordered sequence decisions. Sorting merely by client timestamps is forbidden. For cross-player shared state the input batch must bind all inputs used in the transition, not just one selected signature. In the prototype fraud verifier only single-input/single-step checkpoints are admissible; multi-input claims are rejected.

## Transcript archive and hashing

Archive the exact signed bytes, batch membership paths, manifest, validator epoch keys, QC and checkpoint chain, reveal witness with nonce, reference game build and evidence/verdict artifacts. A `sha256sum` over a ZIP is only a package integrity check and must not be interpreted as the canonical Merkle root. Byte-level conformance will require golden vectors created independently by Rust + JS + C and rejection tests for overlong/unknown/truncated forms.

## Codec security checklist

Bound vectors and nested arrays, reject integer overflow on `length * element_size`, cap proof depth, avoid any panic on network bytes, reject mismatched content hashes and duplicate keys, verify signers after cheap framing checks but before expensive replay, avoid unsafe deserialization, validate every public key/circuit input, reject stale epoch/time windows, and enforce per-peer budgets.

## r3 signed event batching / independent 1v1 evidence

A new **separate codec family** exists: `GVEC` v1 signed event streams, `GVAG` v1 multi-player/multi-match aggregate, `GVKC` v1 generic chunk envelope. These do not silently change older single-tick signed input bytes. Minimal unsigned LEB128, fixed LE fields, strict signatures, ordering, predecessor-chain continuity and byte caps are mandatory. Exact byte schema in [r3 spec](22-INPUT-PACKING-AND-DECENTRALIZED-1V1.md).
