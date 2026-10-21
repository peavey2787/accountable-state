# 01 — Non-negotiable protocol invariants

Normative words **MUST**, **MUST NOT**, **SHOULD**, **MAY** describe requirements for a production-conforming implementation; the prototype does not claim compliance with all of them.

## Identity, rules, and domain separation

- G01: All signatures, hashes, proofs, messages, and chain transactions MUST bind a protocol version, specific match ID, ruleset hash, and relevant domain/role; prevent replay across games, players, epochs, networks, and chains.
- G02: An initial state MUST be established by a manifest authorized by the game policy; a player-generated untrusted spawn is never a trusted checkpoint.
- G03: The manifest MUST bind game build/executable or verification program hash, canonical serialization schema version, input schema, fixed tick/time source, RNG mechanism, players, validator keys, and quorum parameters.
- G04: Safety-critical hashes MUST be collision resistant; FNV/CRC/non-cryptographic hashes and hashes padded/repeated to appear longer MUST NOT be used.
- G05: Signatures MUST be verified against authenticated roster keys and canonical exact bytes; a supplied self-declared key MUST NOT become an authority.

## State and transcript continuity

- G06: Each accepted transition MUST have exactly one authorized predecessor (except declared genesis), correct tick/sequence, and canonical input ordering. Same input/nonce under multiple matches must not produce interchangeable claims.
- G07: State changes MUST be governed by the deterministic ruleset, not by client assertions. Client visual/render state MUST be isolated from game-authoritative state.
- G08: Integer overflow, underflow, invalid types, non-finite floats, mixed precision, and nondeterministic iteration MUST have explicit deterministic semantics. Unsafe arithmetic and host wall-clock timings cannot establish canonical movement.
- G09: A Merkle proof MUST include leaf index, tree size, and domain-specific shape/algorithm. It MUST NOT establish full transcript completeness without an authorized checkpoint and availability attestations.
- G10: Records MUST be bounded, schema-validated, and replay-protected before expensive cryptography or allocation.

## Network safety and liveness

- G11: Accepted checkpoints MUST be ordered/finalized under an explicit fault model. Open membership without Sybil protection cannot claim Byzantine quorum safety.
- G12: A validator MUST NOT sign mutually conflicting proposals at the same safety lock. Locking, view change, and safe recovery MUST be durable across crash/restart.
- G13: Transitions within a challenge window remain **provisional**. If the rules allow post-finality reversal it MUST be a separate, documented appeal protocol, not silent rollback.
- G14: A missing message, expired reveal, or failed peer is an availability/protocol fault until a separate rule establishes a forfeit. It is NOT an objective semantic cheat proof.
- G15: Signed equivocation evidence and invalid-transition evidence MUST be independently distinguishable and reproducible by third parties.
- G16: Data availability acknowledgments MUST prove that authentic data was actually retained before they count. Merkle roots alone do not grant availability.

## Privacy and anti-cheat

- G17: Each recipient MUST receive only game-authorized information. No client anti-cheat can retract information already supplied to an adversarial client.
- G18: Encrypted payloads MUST be authenticated, keyed to the correct context, and subject to nonce/sequence rules. Hiding commitments require unpredictable blinding and must bind game/domain metadata.
- G19: Post-match reveals MUST specify what becomes public and what is protected forever. Evidence publication MUST minimize personal data and reveal only data necessary to check the claim.
- G20: Fraud submissions MUST be publicly verifiable or explicitly labelled attestations/allegations; a blockchain transaction or accusation signature is not by itself a cheat proof.
- G21: Optional ZK MUST bind exact public inputs, verifier/circuit/image ID, accepted prior/next commitments, ruleset and match; generic verification of an unrelated statement is invalid.

## Governance

- G22: Fraud-punishment policy, bonds, challenge periods, validator membership, tie-breakers, and appeal processes MUST be fixed before match start, not decided by the accuser.
- G23: Protocol upgrades MUST change a version/hash; no reinterpretation of existing transcripts under new rules.
- G24: Witness loss and application bugs MUST produce explicitly classified **inconclusive** outcomes rather than fabricated convictions.
- G25: Publishing a hash or evidence to any external storage or settlement system MUST preserve the distinction between a published commitment, a signature attestation, and an actually verified fraud statement. Publication alone is never fraud verification.

The acceptance matrix in [14](14-qa-acceptance.md) covers each invariant; proof-of-concept features remain non-conformant until those gates pass.

## r3 signed event batching / independent 1v1 evidence

Invariant: one authenticated witness of a deterministic rule violation suffices for every honest verifier to reject it, independent of quorum voting; this does **not** authorize unilateral creation of a disputed input order. Inline chain batches must pass network mass/fee checks; off-chain roots require data availability. See [r3 profile](22-INPUT-PACKING-AND-DECENTRALIZED-1V1.md).
