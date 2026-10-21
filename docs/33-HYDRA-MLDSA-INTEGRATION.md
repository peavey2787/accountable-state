# Hydra ML-DSA-65 integration

Every signature on a gameplay or accountability message is a real **ML-DSA-65** (FIPS 204)
signature made with Hydra's `hydra-crypto` through the `gv-sig` crate. There is one format
version (V1). Nothing older is read, written or migrated.

## `gv-sig`

| Item | Value |
|---|---|
| Key | `MlDsaKeyPair::from_seed(seed32)`; verifying key 1952 B |
| Signature | 3309 B; signing is hedged (randomised), so two signatures over one message differ |
| Signed bytes | exactly 64: the SHA-512 *envelope digest* (below) |
| `PlayerId` | `SHA-256("gv/player-id/v1\0" ‖ alg(1) ‖ verifying key)` (32 B) |
| Key registry | verifying keys are interned by `PlayerId` (max 4096); `verify` of an unknown id fails |
| Key files | `GV-PUBKEY/V1` (`encode_public_key_file` / `decode_public_key_file`) |

```
envelope_digest = SHA-512( "gv/sig-envelope\0" ‖ [SIG_VERSION=1, ALG=1]
                           ‖ u16le len(label) ‖ label ‖ signer(32) ‖ u64le len(body) ‖ body )
```

The label is the message's domain (for example `gv/audit/authenticator/v1`,
`gv/packed-controls-signed/v1`, `gv/audit/challenge/v1`). A signature therefore binds the
format version, the domain, the signer and the body; a signature for one message type can
never verify as another, and cannot be replayed under a different signer.
Every body additionally binds match id, ruleset hash, type-specific sequence numbers and
predecessor hashes (see [34](34-WIRE-FORMATS.md)).

Verification is strict: fixed lengths, registered key, exact digest. There is no fallback verifier.

Because the digest is standard, **any** FIPS 204 implementation can verify a signature:
`scripts/verify-vectors.mjs` recomputes the envelope in Node and verifies the Rust signature
with the system OpenSSL (>= 3.5), and rejects tampered messages, signatures and keys.
`crates/sig/tests/committed_vector.rs` checks the same committed file in Rust.

## Signing budget (what is *not* signed)

The sim runs at 60 Hz and never signs per tick. Signed objects: one input batch per epoch,
one checkpoint per epoch, one log authenticator per epoch, plus rare challenges and responses.
Measured on this machine with `cargo run --release -p gv-sig --example bench`:

| Scheme | sign | verify | signature | key |
|---|---|---|---|---|
| ML-DSA-65 (now) | 539 µs | 54 µs | 3309 B | 1952 B |

Signing happens on the pipeline task, never on the 60 Hz sim path.

## License note

`hydra-msg` / `hydra-crypto` are GPL-2.0-or-later. The workspace is MIT, but `gv-sig` is declared
`GPL-2.0-or-later` and every binary that links it (including `gv-edge` and `accountable-state`)
is therefore distributed under GPL-2.0-or-later terms. Source-only use of the MIT crates that
do not link `gv-sig` is unaffected. The `p2p-net` and Hydra git dependencies are pinned by
`Cargo.lock`; check their licenses before redistributing binaries.

## Hide commitment blinding

`blinded_batch_hash = SHA-256("gv/admission/blinded-batch/v1\0" ‖ blind(32) ‖ batch digest)`.
The blind comes from the OS CSPRNG and is revealed only inside the `Opening`, so a commitment
reveals nothing about a low-entropy hidden batch before the reveal.
