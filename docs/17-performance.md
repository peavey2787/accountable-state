# 17 — Performance, sizing and resource constraints

## Fast path vs slow path

The fast path must stay cheap: bounded canonical input parsing, signature verification, hash and Merkle append, a small custody receipt, occasional checkpoint QC. Replay of contested transitions or full matches is the slow path. Optional ZK proving is a **rare** or batched off-path operation unless real-world benchmarks demonstrate affordable proving. No assumptions of fixed 60Hz ZK proofs or 500ms blockchain writes are built into the core.

## Design variables

Let P=players, T=ticks, I=average signed input bytes, C=checkpoint interval, V=independent verifiers, R=replication factor, f=Byzantine budget. Storage is approximately `O(P*T*I*R + snapshots)` without pruning; Merkle proof length is `O(log(T))`; a naive full replay is `O(T * rule_cost)` and bounded snapshot replay about `O(C * rule_cost)` if trustworthy. Quorum communication can be substantial and must be measured under actual P2P latency, partitions and churn. ZK proving scales with guest execution and compression pipeline; benchmark independently.

## Required configurable limits

- Max input/payload/state bytes per match and per tick.
- Max total transcript bytes, proof depth, proof receipts, Merkle path and witness size.
- Max CPU/instruction steps for canonical transition replay; deterministic out-of-gas result where game-defined.
- Max simultaneous challenges per peer, time spent validating invalid ones, signature/hash/certificate budget.
- Max custody replica and erasure-coded chunk count, cache size, retention time and archive bandwidth.
- Max P2P payload/frame, backlog, queue depth, retransmission and duplicate filtering.

All oversized inputs must be rejected before expensive processing. Public verification endpoints should prioritize low-cost syntactic prefiltering, memoize already checked canonical proofs and apply per-identity/per-IP quotas without asserting IP identity proves uniqueness.

## Benchmark plan

1. Measure single input sign/verify/hash on low-end mobile, midrange desktop and browser WASM.
2. Measure 1k/10k/100k input Merkle append, proof generation and verification.
3. Measure fixture replay on faithful actual game physics for 1/10/60/600 ticks.
4. Measure 4-validator P2P consensus latency and recovery under 0–500ms RTT and drops.
5. Measure encrypted data availability with corruption, disk restart and retrieval timeout.
6. Measure proof generation/compression/verification on commodity devicescosts before committing to any ZK default.
7. Preserve reproducible benchmark inputs and versioned JSON reports; compare correctness before speed.

## Prototype limitations

`MerkleLog::root()` builds a tree from stored leaves and is O(N) each call; this is intentionally easy to audit, but **not appropriate for every-frame production root generation**. Use a documented incremental Merkle frontier/tree with consistency proof and independently derived test vectors before deployment. The `Vec` allocations and signature checks are not hardened for hostile unbounded inputs beyond the specified per-record cap. The core prototype contains no P2P, runtime disk storage or benchmark implementation.

## r3 signed event batching / independent 1v1 evidence

Add the event-rate variable `E` (actual control changes per second). For 8-bit digital controls with frequent <128-tick gaps, event records are often **2 bytes per change**, plus per-stream headers and a 64-byte signature; 16-bit digital state is often 3 bytes/change. Analog/high-entropy streams are not guaranteed to compress. Benchmark both 24-KiB-style transaction payload planning and full wallet transaction mass. See [r3 estimates](22-INPUT-PACKING-AND-DECENTRALIZED-1V1.md).
