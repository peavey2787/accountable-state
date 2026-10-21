## Real-time 60 Hz engine with PeerReview-style accountability (current)

The arena runs a **60 Hz deterministic simulation decoupled from P2P consensus**: local input
advances the provisional Rust state immediately, inputs stream continuously, and both clients
replay with bounded prediction and rollback. Signed epoch batches, Merkle commitments,
checkpoint co-signatures, fraud proofs and the accountability log run in a separate pipeline
every ~333 ms without blocking gameplay; commit-lock-reveal is kept only for the **Hide 5 s**
action (with a random blind in every commitment).

* **Signatures:** every gameplay and accountability message is signed with Hydra's real
  **ML-DSA-65**, domain-separated and bound to version, match, signer and ruleset
  ([docs/33](docs/33-HYDRA-MLDSA-INTEGRATION.md)). Only one format version exists.
* **Accountability:** hash-chained logs with signed authenticators, equivocation and fork
  proofs, challenge/response where a timeout is only ever *suspicion*, counterproofs and
  offline-verifiable evidence ([guarantees](docs/35-ACCOUNTABILITY-GUARANTEES.md),
  [challenges and evidence](docs/36-CHALLENGES-WITNESSES-EVIDENCE.md),
  [wire formats](docs/34-WIRE-FORMATS.md)).
* **Measured** (two native processes, encrypted P2P): 60.0 Hz, input-to-screen ~12.6 ms,
  finality p50 17 / p95 20 ms, ~14 % of a core, ~250 kbps signed traffic per direction
  (3.3 KB per ML-DSA signature). Before/after table: [docs/37](docs/37-OPERATIONS-AND-PERFORMANCE.md);
  engine details: [docs/32](docs/32-REALTIME-60HZ-ENGINE.md).

```bash
./scripts/play-arena-linux.sh              # two browser windows: http://127.0.0.1:9001 and :9002
./scripts/smoke-arena-linux.sh             # fail-closed two-process test incl. a commit-reveal hide
./scripts/headless-arena-linux.sh          # scripted match, then offline verification of all proofs
./scripts/bench-realtime-linux.sh          # tick rate, latency, finality, bandwidth, CPU
./scripts/witness-network-linux.sh         # 2 players + 3 honest + 1 malicious witness on real p2p-net/Hydra links
FAULTS='loss=0.2,dup=0.2,delay=40,jitter=250' ./scripts/witness-network-linux.sh   # same, hostile network
./scripts/model-check.sh                   # TLC over spec/Accountability.tla (bounded; needs Java, fetched once)
cargo run -p gv-edge --example verify_package -- PACKAGE MATCH_ID_HEX a.pub b.pub   # independent verifier
```

# game-verification

**Decentralized, independently verifiable multiplayer gameplay at the edge.** Clients execute deterministic game rules and independently verify the same signed input history. A demonstrably invalid signed player action or state claim can be proved to any independent verifier without a trusted host, server, blockchain transaction, gas fee or invasive OS monitoring. This project uses Rust and an optional `p2p-net`/`hydra-msg` native transport. The core SDK has no blockchain, wallet or external-service requirement.

> **STATUS: experimental edge PoC, not retail-ready anti-cheat and not externally audited.** What is executed, what is model-checked, what is only assumed and what remains open are kept apart in [docs/41](docs/41-FORMAL-MODEL.md) and [docs/42](docs/42-REMAINING-GAPS.md). Not done: fuzzing, a security audit, real WAN measurements, Windows/macOS runs.

## What the PoC implements in source

| Component | Capabilities and status |
|---|---|
| `crates/edge` | Two-player canonical event-batch admission, deterministic replay, Merkle input roots, signed mutual checkpoints, bounded portable certified archives, crash recovery from authenticated genesis, one-witness fraud proofs |
| `crates/edge::BilateralAdmission` | Signed commit -> both signed input-set locks -> authenticated reveal; phase checks, roster binding, conflicting commitments/equivocation check |
| `crates/edge::ArenaRules` | Deterministic small public-state two-player 2D arena (grid movement, walls, collision, hitpoints, line-of-sight attacks, cooldown, guard, victory). **A protocol demonstration, not a complete retail game.** |
| `crates/edge::FraudBundle` | Verifiable false signed state claims from *any certified epoch*, with the complete preceding independently checkable history |
| `crates/edge::InputViolationBundle` | Verifiable illegal signed player inputs even when no checkpoint could be accepted, requiring both signed epoch locks and both revealed signed batches |
| `crates/edge::CertifiedMatch` | Persisted bounded sequence of two-player certified epochs, replayed from pinned genesis before recovery/resumption |
| `crates/codec` | Bit-/event-packed 8/16-bit controls with canonical varints, ML-DSA-65 batch signatures, prior-stream digest chaining, aggregation |
| `crates/commitments`, `crates/transcript`, `crates/replay` | SHA-256 domain-separated ordered Merkle logs, signed input transcripts, pure replay and typed rule errors |
| `adapters/p2p` (feature `native`) | Real upstream `p2p-net` + `hydra-msg` sessions: non-blocking reliable and lossy channels, 4 KiB packets, bundling, windowed retransmission, HYDRA history pruning |
| `crates/edge::live` | 60 Hz `Timeline` (prediction + rollback), loss-tolerant input `StreamSender`, asynchronous checkpoint `Pipeline` (activity-gated epochs, shortest-prefix agreement, fraud/illegal-input evidence) and the commit-lock-reveal **hidden window** |
| `examples/edge-p2p` | Two-process real-time arena (headless scripted or local graphical UI): 60 Hz sim task + pipeline task, Hide action, false-checkpoint/illegal-input test modes, append-only receipts, `--resume`, offline `verify`, `bench-hydra` |
| `crates/edge::export` | Chain-agnostic evidence export: compact commitment, full match archive, fraud evidence, audit export, bounded non-blocking evidence feed; independent `verify_package` ([docs/38](docs/38-EVIDENCE-EXPORT.md)) |
| `crates/edge::audit` | Hash-chained logs, signed authenticators, equivocation/fork proofs, challenges, ledger, anchored crash recovery ([docs/35](docs/35-ACCOUNTABILITY-GUARANTEES.md), [docs/39](docs/39-ANCHORED-RECOVERY.md)) |
| `crates/edge::witness` | Third-party witness protocol `GV-WITNESS/V1`: authenticated admission, signed authenticator distribution, inventories, retrieval, bounded anti-entropy, independent verification ([docs/40](docs/40-WITNESS-NETWORK.md)) |
| `spec/` | TLA+ model of the accountability protocol with TLC configurations ([docs/41](docs/41-FORMAL-MODEL.md)) |
| `crates/zk`, `adapters/wasm` | Partial skeleton components. **Not a working ZK backend or a retail web app.** |

## Play the graphical 1v1 arena (experimental)

Run `./scripts/play-arena-linux.sh` on Linux and open `http://127.0.0.1:9001/` (Alice) and `http://127.0.0.1:9002/` (Bob). WASD/arrows tap-to-step or hold-to-repeat, Space attacks, Shift guards, **H or the Hide button hides your location for 5 s** (commit-lock-reveal; the opponent sees only a fog marker and is rolled back to the truth at the reveal). Your fighter moves on the live 60 Hz state; a dashed ring marks the last position both players certified. Telemetry shows the real tick rate, jitter, finality latency, rollbacks and input-stream bandwidth. The violation indicator is separate from the verification chip, latches red, and counts every proven cheat. **Send cheat move** signs a false checkpoint and **Send invalid signed input** signs an illegal control word; the other peer proves both. `GV_ARENA_EPOCH_TICKS` sets the checkpoint cadence. A P2P error keeps the local page alive with a diagnostic instead of silently exiting.

Before launching, use `./scripts/format-all.sh` and `./run-all-linux.sh` on a machine with Rust 1.98+.



## Getting started

Requires **Rust 1.98+** for the native imported projects (core crates target Rust 1.85+), Cargo, Clippy, rustfmt; Node.js is optional for independent cryptographic vector scripts.

```bash
./run-all-linux.sh
cargo test -p gv-edge --all-targets
```

Windows: `run-all-windows.cmd`. The scripts **fail** on warnings/errors and never silently change source. Run `scripts/format-all.sh` (or `.cmd`) first.

For **two independent peers** with their own long-term private keys and Hydra identities, read [the complete setup and commands](docs/23-EDGE-P2P-PROOF-OF-CONCEPT.md). The example includes separate P2P listen-port/identity config files under `examples/edge-p2p/configs/`. It accepts `--ui-port=P`, `--epochs=N` (headless), `--epoch-ticks=N`, `--hide-at=T`, `--cheat-at=T`, `--illegal-at=T`, `--equivocate-at=T`, `--withhold-at=T`, `--accuse-falsely-at=T`, `--resume=ARCHIVE`; the offline `verify` command demands an explicitly pinned match ID and both player public keys, never self-authorized evidence.

## Required game integration

A game must provide **(1)** an independently authenticated match invitation and canonical initial state, including roster, ruleset identity, tick policy and timeout/finality model; **(2)** a pure deterministic state transition implementation and exact canonical inputs/state encoding; **(3)** a strict policy for which state each recipient may access or reveal. This prototype deliberately uses public state. Sending hidden enemy data to a client still permits wallhacks; cryptographic replay also does not distinguish a human player from an aimbot producing legal inputs. See [integration contract](docs/04-game-integration.md) and [complete bilateral protocol](docs/24-BILATERAL-ADMISSION-AND-EDGE-RECOVERY.md).

## Trust model and limitations

An **authenticated, reproducible fraud witness from one person is enough** to demonstrate a violation. A majority vote cannot override mathematics. **A single witness cannot force an opponent to send, reveal or co-sign inputs**, nor establish timestamps that have not been authenticated. In 1v1 this implementation preserves safety through bilateral locking and co-signed checkpoints but can stall under a malicious opponent; timeouts are *unproven disconnects/forfeits*, never automatically proven gameplay cheating. Additional BFT members or independently sequenced transactions are separate opt-in approaches to make progress against a faulty participant.

**No blockchain is required or assumed.** Clients keep their own evidence and may publish an exported package or its 32-byte commitment to any storage or settlement system. Publishing a commitment proves publication, not guilt; only `verify_package` on the package itself establishes fraud ([docs/38](docs/38-EVIDENCE-EXPORT.md)). There is no central referee and no majority vote on whether evidence is valid: witnesses relay and independently verify, and a witness can never forge a verdict.

**Dependency licensing:** binaries linking `gv-sig` (Hydra's ML-DSA, GPL-2.0-or-later) are distributed under GPL-2.0-or-later ([docs/33](docs/33-HYDRA-MLDSA-INTEGRATION.md)). ML-DSA-65 is the only signature algorithm in the project; SHA-256 is used for hashes and the Merkle trees.

**Dependency licensing (details):** The supplied `p2p-net` source currently declares BUSL-1.1, and its maintainer has stated a plan to change it to GPL-2.0; that planned change is **not assumed to have occurred**. `hydra-msg` declares GPL-2.0-or-later. SDK-owned code is MIT, but a combined native distribution must comply with actual dependency licenses. Updating the Git default branches changes resolved revisions only when the Cargo lockfile is updated; run `scripts/update-upstreams.sh` or `.cmd`, inspect the changes, then retest.

## Documentation

- [Overview and specification index](docs/SPEC.md)
- [Game integration requirements](docs/04-game-integration.md)
- [Wire, replay, signed input history and Merkle specification](docs/06-wire-encoding.md)
- [P2P finality and threat models](docs/08-p2p-consensus.md)
- [Fraud proof security model](docs/10-fraud-disputes.md)
- [Native edge P2P setup](docs/23-EDGE-P2P-PROOF-OF-CONCEPT.md)
- [Bilateral protocol, fraud proof formats, recovery and limitations](docs/24-BILATERAL-ADMISSION-AND-EDGE-RECOVERY.md)
- [Graphical arena testing and controls](docs/26-GRAPHICAL-ARENA.md)
- [Real-time 60 Hz engine](docs/32-REALTIME-60HZ-ENGINE.md)
- [Hydra ML-DSA-65 integration and licensing](docs/33-HYDRA-MLDSA-INTEGRATION.md)
- [Wire formats (V1)](docs/34-WIRE-FORMATS.md)
- [Accountability: threat model, guarantees, limits](docs/35-ACCOUNTABILITY-GUARANTEES.md)
- [Challenges, evidence, witnesses, privacy](docs/36-CHALLENGES-WITNESSES-EVIDENCE.md)
- [Operations, validation and performance](docs/37-OPERATIONS-AND-PERFORMANCE.md)
- [Chain-agnostic evidence export](docs/38-EVIDENCE-EXPORT.md)
- [Anchored crash recovery and rollback protection](docs/39-ANCHORED-RECOVERY.md)
- [Witness network and hostile-network testing](docs/40-WITNESS-NETWORK.md)
- [Formal model: assumptions, model-checked properties, tests, unverified](docs/41-FORMAL-MODEL.md)
- [Remaining gaps and their security implications](docs/42-REMAINING-GAPS.md)

## Provenance

The Merkle commitments are SHA-256 with domain separation and ordered leaves. The native Git dependencies are not vendored into this ZIP and are obtained by Cargo from their upstream default branches.
