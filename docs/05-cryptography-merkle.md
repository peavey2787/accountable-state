# 05 — Cryptographic profile and Merkle log v1

## Cryptography choices

Reference Rust prototype uses **SHA-256** for hashes and **ML-DSA-65** (FIPS 204, via Hydra) for every gameplay and accountability signature; see [33](33-HYDRA-MLDSA-INTEGRATION.md). The SHA-256 choice enables wide native/browser compatibility and easier independent verification. Games may use another algorithm only under a new committed protocol/circuit/hash profile; silently swapping hash algorithms is forbidden. Signature keys are per-match or explicitly bound with signed enrollment; never confuse any external wallet/account identity with a game signing identity. Hashes and signatures alone do not establish valid game outcomes.

Use a secure OS CSPRNG for signing keys and 32-byte state-commitment nonces. The deterministic toy sample uses fixed nonces **only for reproducible demonstration** and MUST NOT be copied to production. Commitments are computationally binding assuming collision-resistant hashing. Hiding for low-entropy private input depends on sufficiently random secret nonces; unblinded hashes of coordinates, card IDs, or actions may be brute-forced.

## All byte strings are exact; ASCII prefixes include terminating `00`

Hash inputs are concatenated in the given order. Lengths are unsigned little-endian; `u64` eight bytes, `u32` four bytes, no UTF-8 normalization of opaque state bytes.

| Function | Bytes hashed with SHA-256 |
|---|---|
| `H_input(data)` | `"gv/input/v1\\0" || u64(len(data)) || data` |
| `H_state(nonce, state)` | `"gv/state/v1\\0" || nonce32 || u64(len(state)) || state` |
| `H_secret(label,nonce,secret)` | `"gv/secret/v1\\0" || u32(len(label)) || label || nonce32 || u64(len(secret)) || secret` |
| `H_leaf(data)` | `"gv/leaf/v1\\0" || u64(len(data)) || data` |
| `H_node(L,R)` | `"gv/node/v1\\0" || L32 || R32` |
| `H_empty` | SHA-256(`"gv/empty/v1\\0"`) |
| `H_root(n,top)` | SHA-256(`"gv/root/v1\\0" || u64(n) || top32`) |

The displayed `\\0` notation means one zero byte, not a literal slash and digit. SHA-256 output is a raw 32-byte value; only human UIs may render lowercase hexadecimal. Production implementations MUST cap sizes before casting to integer widths.

## Ordered Merkle log

Append canonical leaf bytes; leaf position starts at zero. Internal levels hash adjacent pairs in order; if the level has odd width, duplicate its last hash as the right child. Repeat until a single top hash. Public root is `H_root(number_of_leaves, top)`, with `top = H_empty` for zero leaves. The count commitment prevents ambiguous padding and is verified against the membership path. A path carries `(index: u64, leaf_count: u64, siblings from bottom up)`; a missing odd partner uses the current hash itself, which MUST be validated by the verifier. The proof MUST consume exactly the number of siblings implied by the leaf count; truncation and excess siblings are invalid.

**Important:** this is an ordered tree over the current list of leaves. By itself it does not implement a cryptographically efficient append-only consistency proof between successive roots. The protocol must separately bind signed/checkpointed predecessor roots and/or add a formally specified history-consistency structure. No tree root automatically proves availability, global order, valid rules or author consent. The reference in-memory Merkle log rejects appends above 1,048,576 leaves and leaf records above 128 KiB; verifier rejects counts above that, leaf records over 128 KiB and sibling paths over 20 elements. Production long-running games require a separately specified storage-backed incremental tree, NOT silent removal of the bound.

## Signature payload v1 (implemented)

Sign exact bytes: `"gv/signed-input/v1\\0" || match_id32 || player_pubkey32 || tick_u64_le || player_sequence_u64_le || payload_len_u32_le || payload`. ML-DSA-65 signs the 64-byte SHA-512 envelope digest of the message (see [34](34-WIRE-FORMATS.md)); the signature is 3309 bytes. The Merkle leaf is those signing bytes concatenated with the 3309-byte signature; it commits to identity, input and signature. A signed input is not a globally accepted input until sequenced into the certified checkpoint's root.

## Known distinctions and future hardening

The code's `commit_secret` is a generic preimage commitment; low-entropy secrecy comes from unpredictable nonce. SHA-256 is not designed as a drop-in SNARK-friendly field hash; a ZK integration may use an authenticated binding gadget or an explicitly versioned circuit-friendly commitment profile. Cross-language vectors and incremental consistency proofs remain planned. Independent Node ML-DSA-65 signing and Merkle leaf vectors are in `tests/interoperability/signed_mldsa65_v1.json` and `merkle_sha256_v1.json`.

## r3 signed event batching / independent 1v1 evidence

For event-packed batches, the authenticated leaf can be the entire versioned `GVEC + ML-DSA-65 signature` record, or its domain-separated digest, with explicit domain and leaf semantics. Do not Merkle-hash unsigned input bytes and assume an actor signed them. See [r3 format](22-INPUT-PACKING-AND-DECENTRALIZED-1V1.md).
