# Game Verification Protocol — normative specification index

**Protocol target:** GVP/1 (design; production conformance not claimed). **Implementation:** foundation v0.1.0. This index is the entry point for implementers, validators and game integrators. The numbered documents are authoritative for their respective responsibilities; this index is not an alternative shorter protocol.

## Specification hierarchy

1. [Protocol invariants](01-invariants.md) — global MUST/MUST NOT rules and invariant IDs G01–G25.
2. [Cryptography and Merkle exact byte format](05-cryptography-merkle.md), [wire encoding](06-wire-encoding.md) — exact implemented preimages and proposed external wire envelope. No unversioned serialization.
3. [Game integration requirements](04-game-integration.md) and [replay](07-transcripts-replay.md) — canonical rules and official state transitions.
4. [Consensus and finality](08-p2p-consensus.md), [data availability](09-data-availability.md), [state machines](19-state-machines.md) — peer authority and evidence custody.
5. [Fraud/evidence](10-fraud-disputes.md), [privacy](11-privacy-visibility.md) — what a valid conviction requires, what must never be disclosed.
6. [Evidence export](38-EVIDENCE-EXPORT.md) and [ZK](13-zk.md) — chain-agnostic evidence packages versus optional succinct proofs.
7. [Threat model](02-threat-model.md), [QA](14-qa-acceptance.md), [operations](16-operations-governance.md), [performance](17-performance.md), [formal model](41-FORMAL-MODEL.md) and [remaining gaps](42-REMAINING-GAPS.md) — risk and implementation acceptance.

## Separation of normativity from implementation

Four kinds of statement are kept apart everywhere ([41](41-FORMAL-MODEL.md)): **cryptographic assumptions** (unforgeable signatures, collision-resistant hashing), **model-checked behavior** (bounded TLC runs, never an unbounded proof), **executable tests** (unit, real-filesystem, native multi-process and hostile-network runs), and **unverified deployment assumptions**. `Designed` text in the older numbered documents is intended behavior unless one of the documents above says it is implemented and tested.

**Security red line:** accepting a fraud proof requires independently authenticated canonical accepted state and official rules. Valid signature/inclusion alone ≠ semantic violation. A published hash of anything ≠ verified fraud. A QC signature ≠ application finality without safe protocol state. Withheld reveal ≠ proven illegal movement.

## Game developer deliverables

See [integration contract](04-game-integration.md) for the full list. The irreducible three inputs are legal genesis, pure canonical `F(S,I)` including map/world input, and an explicit information-flow policy. The developer must also choose input acceptance order, time authority, roster/fault model, challenge window, data custody, side effects, terminal conditions, and the policy enforcing penalties; these are part of safe integration, not optional assumptions inferred by the SDK.

## Signed event batching and size accounting

[22 — Signed event packing, generic chunking and size accounting, decentralized 1v1](22-INPUT-PACKING-AND-DECENTRALIZED-1V1.md) defines the `GVEC`/`GVAG`/`GVKC` codec family; it is carrier-agnostic.

## Edge-executed engine and accountability

The real-time engine is in [32](32-REALTIME-60HZ-ENGINE.md); signatures in [33](33-HYDRA-MLDSA-INTEGRATION.md) and [34](34-WIRE-FORMATS.md); accountability in [35](35-ACCOUNTABILITY-GUARANTEES.md) and [36](36-CHALLENGES-WITNESSES-EVIDENCE.md); export, recovery, witness network and formal model in [38](38-EVIDENCE-EXPORT.md)–[41](41-FORMAL-MODEL.md). The optional native transport uses the default Git branches of `p2p-net` and `hydra-msg`.
