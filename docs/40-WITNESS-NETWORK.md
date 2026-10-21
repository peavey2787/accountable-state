# Witness network

Third-party witnesses relay and independently verify accountability evidence over the real
`p2p-net` + `hydra-msg` transport (protocol magic `GV-WITNESS/V1\0`, `crates/edge/src/witness.rs`,
runner `examples/edge-p2p/src/witness_net.rs`). Witnesses are never gameplay authorities: they
see no inputs, sign no state, and 1v1 works without them.

## Protocol
* Topology: one link per (player, witness); supervised re-dial; 10 s silence recycles a link.
* Admission: Hello/Admit signed (ML-DSA-65) over a per-link nonce; unknown keys are refused.
* Messages: Auth (signed authenticators), Inventory (<=64 ids), Want (<=16), Evidence,
  Package, Chunk, Challenge, Response. Large packages are chunked (16 KiB chunks, inline
  <=24 KiB, item <=4 MiB, message <=4 MiB; transport cap 512 KiB).
* Anti-entropy: inventory every 1000 ms; missing items fetched with Want.

## Bounds
1024 items, 256 authenticators per owner, 64 msgs/s/link token bucket, 8 strikes block a
link. Invalid or duplicate evidence is rejected and counted as a strike. Verification runs
off the 60 Hz simulation thread.

## Fraud validity
Every item is verified independently from signatures and rules (`verify_package`). A witness
cannot forge a verdict: a forged or altered item fails verification; witness agreement is
never consulted for objective validity. A timeout yields SUSPECTED/UNAVAILABLE, never PROVEN_FRAUD.

## Real-process results (loopback; 2 players + 3 honest + 1 malicious witness)
`scripts/witness-network-linux.sh` (optional `FAULTS=...`, `WITNESS_PARTITION=1`):

| Scenario | Result |
|---|---|
| Baseline | PASS; 12 items verified; first fraud verified ~14.7 s, equivocation ~21.3 s after witness start |
| loss 20 % / dup 20 % / delay 40 ms / jitter 250 ms + 25 s SIGSTOP partition of one witness | PASS; 11 items; the partitioned witness caught up via anti-entropy at ~50–60 s |
| kill -9 of a witness + loss 10 % / dup 10 % / delay 20 ms / jitter 100 ms | PASS; 12 items; restarted witness re-verified persisted evidence and converged |
| Headless 1v1, no witnesses (Hide + withheld reveal, false accusation, illegal input, false checkpoint, equivocation) | PASS; 6 evidence files verified offline |

Fault injection (`GV_FAULTS`) is applied above the encrypted transport in the runner, not by
an OS packet shaper. The malicious witness sends oversized (300 kB) and malformed messages
and forged evidence; all were rejected. Failures copy data to `target/failure-artifacts/`.

## Assumptions / not covered
Convergence assumes eventual connectivity between at least one honest witness and the
accused's counterparties. Loopback only: no real WAN. No multi-hour soak was run; the longest
runs are minutes. Eclipse of all witnesses blocks propagation (not local verification).
