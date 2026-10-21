# 38 — Chain-agnostic evidence export

One interface exports, imports, independently verifies and streams evidence. It lives in `gv_edge::export`, is reached through `AccountableState::export` and `Verifier::verify_package`, and has **no** network, wallet or blockchain dependency. A package is plain bytes: store it in a file, an object store, a message queue or any settlement system.

> **Publishing a hash is not fraud verification.** A `Commitment` proves only that someone published 32 bytes. Fraud is established solely by running `verify_package` on the package itself with the pinned match id, ruleset and roster. Every commitment carries a `publication_only` byte that decoders require to be set.

## Artifacts

| Function | Package kind | What it carries |
|---|---|---|
| `export_match` | `MatchArchive` | A complete certified match (`CertifiedMatch`): everything needed to replay it from the pinned genesis |
| `export_fraud` | `FraudWitness` | The smallest sufficient witness: `FalseCheckpoint` (`FraudBundle`), `IllegalInput` (`CheckpointEvidence`) or `Equivocation` (`audit::Evidence`) |
| `export_audit` | `Audit` | Signed authenticators, log segments, challenges, responses and evidence for audit; every record is re-verified on import |
| `Package::commitment` | `Commitment` | Compact 32-byte id plus kind, fraud kind, match id and ruleset; `Commitment::WIRE_SIZE` bytes |
| `AccountableState::subscribe` | event feed | Signed, numbered, durable `ExportEvent::{Evidence, Audit, Checkpoint}` |

## Encoding

* `GV-EVIDENCE-PACKAGE/V1\0` envelope: kind, fraud kind, match id, ruleset hash, sorted roster (two ML-DSA-65 verifying keys, 1952 B each), a flag saying whether player inputs are disclosed, the payload length, the payload and its payload hash. Exactly one version exists; unknown versions, trailing bytes, non-canonical lengths and unknown kinds are rejected.
* **Deterministic ids:** `id = SHA-256("gv/export/commitment/v1\0" || alg || kind || fraud kind || inputs-disclosed flag || match id || ruleset || roster[0] || roster[1] || payload_hash)` with `payload_hash = SHA-256("gv/export/payload/v1\0" || payload)`. The same evidence always has the same id, whoever exports it. Two domain-separated hashes keep package ids, payload digests and every signature domain disjoint.
* **Resource limits:** `MAX_PACKAGE_BYTES` 512 MiB, audit exports at most `MAX_AUDIT_ITEMS` (256) records per list and `MAX_AUDIT_BYTES` (64 MiB). Every length is checked before allocation.
* **No secrets:** a package contains verifying keys, signatures, hash chains, signed inputs and public state only. It never contains signing keys, Hydra identities, session state, passwords, peer addresses or logs of other sessions. The tests assert that a package decodes into exactly the declared structures.
* A package has no signature of its own. Authenticity comes from the signatures inside the payload, which are verified against the pinned roster, so a verifier needs no trust in the exporter.

## Disclosure policy

`DisclosurePolicy` has no `Default`; the caller states what may leave the process.

* `inputs_releasable`: signed input batches (and so every player's controls) may be released.
* `permanently_secret_state`: the game promises that some state stays secret after play. Match archives and any witness that contains input history are then refused with `ExportError::DisclosureForbidden`.
* `DisclosurePolicy::PUBLIC` is for public-state games (such as the anti-cheat arena). Equivocation evidence made of signed heads alone does not disclose inputs and exports under any policy; evidence made of conflicting signed input batches does.

## Verification

```rust
let verifier = Verifier::new(TrustAnchor { match_id, ruleset: rules.ruleset_hash(), roster });
match verifier.verify_package(&bytes, &rules) {
    VerificationResult::ProvenViolation(proof) => { /* proof.kind, proof.accused */ }
    VerificationResult::Valid(record) => { /* a match archive or a clean audit record */ }
    VerificationResult::Inconclusive(reason) => { /* proves nothing either way */ }
}
```

`Inconclusive` carries the reason: `WrongContext` (other match, ruleset or roster), `Malformed`, `TooLarge`, `Invalid` (a signature, chain or replay failed) or `NotAViolation` (well formed, but it proves nothing: a valid claim, an honest extension, a lawful input). A signature that verifies is never enough on its own; the semantic check (replay, conflict, rule violation) must also hold. An audit record carrying verified equivocation is a `ProvenViolation`.

A runnable command-line verifier for the arena ruleset lives in [anti-cheat](https://github.com/peavey2787/anti-cheat).

## Event feed

`AccountableState::subscribe(cursor, limit)` reads the node's durable feed (`<storage>.feed`). Every event is signed by the node, numbered and synced before anyone can read it; ids survive restarts, so a consumer resumes from the last id it saw and never loses an event. Events are notifications; the authoritative record is the package.

## Publishing to any system

Take `package.encode()` and `package.commitment().encode()` and put them wherever you like. A consumer who finds only the commitment can fetch the package by `id` from any source and verify it. Nothing in the SDK requires the publication to succeed, to be ordered, or to be final; none of that changes what `verify_package` returns.

## What this is not

It is not a verdict service, not a majority decision and not on-chain verification. The 32-byte id binds bytes; it does not make them true. Retention, availability and any penalty policy belong to the game.
