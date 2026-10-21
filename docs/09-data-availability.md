# 09 — Data availability, withholding, retention, recovery

**A commitment to a transcript does not prove that anyone can retrieve its contents.** Optimistic fraud detection is only sound when an honest challenger can obtain the required authenticated input and state witness before its challenge deadline.

## Custody protocol — proposed

1. Producer splits exact authenticated archive into bounded chunks, with `(match, epoch, checkpoint, kind, chunk_index, chunk_count, original_length, chunk_hash)` and a domain-separated full-blob Merkle root. No ambiguity in duplicate chunk last/empty sizes.
2. Custodians receive encrypted or public chunks, validate hash and expected custody metadata, save durably, fsync according to configured durability guarantees, and sign a receipt containing the root, byte count, expiry and availability window.
3. Producer must gather an **availability quorum**, specified independently from consensus quorum, *before* a checkpoint is accepted; enforce distinct authenticated custody operators rather than IP addresses. For `n=3f+1` shared validator/custodians with up to `f` Byzantine, custody receipts from `2f+1` nodes imply at least `f+1` honest custody acknowledgments **only if signers really retained complete retrievable data**.
4. During a challenge, any observer retrieves data by root from independent custodians; each chunk must be re-hashed and authenticated. Prefer complete archive plus Merkle inclusion path; optionally use erasure codes with a documented reconstruction threshold.
5. On miss: query alternative replicas, perform bounded repair from peer custody, recover via archive/indexer, and record signed requests/failed responses for governance. If all retrieval fails, mark **Unavailable** and invoke the precommitted forfeit/abstain policy.

## Retention and expiry

Hold data until max of: application finality time + audit/appeal grace, economic settlement challenge deadline, chain reorganization margin when chain settlement applies, and mandated archive period. Never garbage-collect after merely receiving a quorum vote; persistent retained state is needed to replay later fraud evidence. Private game secrets may require protected storage until reveal; raw keys marked never-reveal should not become public just to satisfy a challenge.

## Omission and non-disclosure

A malicious peer might refuse to reveal a committed secret. If post-match reveal was a contractually required move, inability to reveal after an authenticated fair deadline may trigger a predefined **forfeit**, but not automatically a cryptographic proof of bad physics or intent. A signed receipt of the disclosure duty plus independently authenticated deadline and failed reveal shows a *protocol violation*; network delay or key loss remains a possible cause. Offer explicit disconnection/rejoin policy and appeal.

## Adversarial conditions

- Storage node says 'stored' but discards bytes: periodic random chunk challenges, proof-of-custody where suitable, bonded receipts and retrieval tests; no unproven claim of cryptographic proof of continuous storage.
- Custodians collude to withhold: choose independent operators, monitor quorum health, repair replicas, pause acceptance when availability below target.
- Archive is encrypted: ciphertext availability proves only ciphertext persistence. A legitimate decryption key or ZK/private attestation may still be unavailable; separately commit and guarantee access to key material under the visibility policy.
- Very large evidence: range queries and bounded bisection using certified state snapshots; do not let a challenger dictate unbounded replay.
- Crashes/corrupt disks: durable WAL, checksums, replicated manifest/catalog, idempotent restores, periodic restore tests.
- Malicious flooding: quotas per match/operator, signed transport identities, challenge bonds/rate limits, bounded cache and bounded decompression ratio.

## Service-level policy template

Sample (NOT a universal secure default): 1 MiB chunks, 3 replicas managed by independent peers, 24-hour dispute window after match completion and 48-hour retention buffer. **These values are placeholders only**, unsuitable for high-stakes games without calibrated bandwidth/disk, recovery and dispute-latency measurements. The manifest must store the actual policy and explicit deadline unit.

## Required records

`CustodyReceipt`, `DataManifest`, `ChunkProof`, `FetchRequestReceipt`, `DisclosureObligation`, `RevealReceipt`, `RetentionReleaseCertificate`. All have match/epoch/checkpoint domain binding, canonical signatures, explicit expiry and version. The skeleton currently implements none of the custody service, only basic Merkle input membership.

## r3 signed event batching / independent 1v1 evidence

If all signed inputs are fully published in an external store, peers can recover them subject to that store's retention. If only a 32-byte commitment is published, the original authenticated data MUST have independent custody/retrieval arrangements (witness inventories and retrieval, [36](36-CHALLENGES-WITNESSES-EVIDENCE.md)). Never assume an external system retains application payloads permanently. See [r3](22-INPUT-PACKING-AND-DECENTRALIZED-1V1.md).
