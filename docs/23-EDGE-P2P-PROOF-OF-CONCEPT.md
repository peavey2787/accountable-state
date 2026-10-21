# Running the encrypted two-process edge verification PoC

No mandatory blockchain, server, kernel driver or smart contract. See [the exact protocol and threat model](24-BILATERAL-ADMISSION-AND-EDGE-RECOVERY.md) and [validation](37-OPERATIONS-AND-PERFORMANCE.md).

## Requirements

- Rust toolchain 1.98 or newer for the native Git dependencies; Cargo, rustfmt and Clippy.
- Upstream Git default branches from `https://github.com/peavey2787/p2p-net` and `https://github.com/peavey2787/hydra-msg`. Cargo.lock, when generated, pins concrete commits; use `scripts/update-upstreams.sh`/`.cmd` to request updates and retest.
- Two separate credentials/identity directories, two different ML-DSA-65 player keys and a 32-byte shared random match ID.
- Trusted exchange of BOTH Hydra contact cards and BOTH ML-DSA-65 public-key files (`GV-PUBKEY/V1`) via an authenticated channel; optional pinned p2p-net peer IDs/multiaddrs.

The uploaded source snapshot of p2p-net says BUSL-1.1, with GPL-2.0 planned by its owner; Hydra is GPL-2.0-or-later. Check actual upstream license before distributing a combined native executable; this SDK's own MIT license does not override dependency terms.

## Setup

Run `./run-all-linux.sh` (Linux/macOS) or `run-all-windows.cmd` (Windows). Both scripts fail on Rust formatter/Clippy/test errors and do not silently repair files.

On Alice and Bob separately, with unique secret values each:

```bash
export GV_HYDRA_PASSWORD='unique-strong-local-password'
export GV_PLAYER_SEED_HEX="$(openssl rand -hex 32)"
cargo run -p gv-edge-p2p-demo -- init ./my-hydra-identity ./my-card.bin
```

Use distinct identity folders, and **retain each person's private seed securely** between `init`, `run` and `--resume`; environment variables are a convenience for development, not hardened consumer key storage. Record the printed public keys and independently exchange the contact cards; create a match ID with `openssl rand -hex 32`, shared by both.

The repository supplies `examples/edge-p2p/configs/alice.json` and `bob.json` for loopback experiments. They use different listen ports and P2P identities, but the same app namespace and network ID. These examples intentionally generate local identity secrets at runtime; do not commit the generated files. For remote networks replace loopback addresses and configure verified bootstrap peers, NAT/relay and discovery following p2p-net's instructions.

Two terminals (each exporting its own password and ML-DSA-65 signing seed):

```bash
cargo run -p gv-edge-p2p-demo -- run alice examples/edge-p2p/configs/alice.json ./alice-hydra ./bob-card.bin MATCH_ID_HEX BOB_PUBLIC_HEX ./alice.receipt.bin --epochs=8
cargo run -p gv-edge-p2p-demo -- run bob examples/edge-p2p/configs/bob.json ./bob-hydra ./alice-card.bin MATCH_ID_HEX ALICE_PUBLIC_HEX ./bob.receipt.bin --epochs=8
```

The peers must actually discover/connect using the p2p-net network (the demo fails closed if ambiguous), or pin `GV_REMOTE_PEER_ID` plus `GV_REMOTE_MULTIADDR` to a trusted peer/dial address. Both processes should generate matching signed checkpoints and save replayable, co-signed `GV-CERTIFIED-MATCH/V1` binary archives after each epoch. For real multi-host tests, use different network configurations and an accessible address; the loopback configs only work on the same machine.

Verify independently on a third machine, using the TRUSTED invitation context (never derive it solely from the alleged evidence):

```bash
cargo run -p gv-edge-p2p-demo -- verify ./alice.receipt.bin MATCH_ID_HEX ALICE_PUBLIC_HEX BOB_PUBLIC_HEX
cargo run -p gv-edge-p2p-demo -- verify ./bob.receipt.bin MATCH_ID_HEX ALICE_PUBLIC_HEX BOB_PUBLIC_HEX
```

### Deliberate fraud cases

To produce a signed false state claim, add `--cheat-at=TICK` to **only one** client's `run` command (the live engine, see [docs/32](32-REALTIME-60HZ-ENGINE.md)). The other client must independently reject it and export `GV-FRAUD-BUNDLE/V1` with a chain of previously accepted receipts; pass that file to the same offline `verify` command. To produce a signed illegal input, use `--illegal-at=TICK` instead; in the live engine the illegal word is neutralized in replay and exported as `GV-EVIDENCE/V1`, which `verify` checks (the older `GV-INPUT-VIOLATION/V1` path remains for the bilateral protocol). Altering any byte in a signed receipt/proof should make verification fail.

For a crash/restart, stop both peers at a certified epoch and pass `--resume=./alice.receipt.bin` / `--resume=./bob.receipt.bin` respectively to `run` (and choose how many **new** epochs to play with `--epochs=N`). Each party independently replays the archive from genesis before accepting fresh inputs; a corrupt or forked archive is rejected. A restart is not an automatic transport reconnect: contact cards, P2P peer identities, the match invitation and upstream connection must still be established.

## Timeouts, finality, limitations

Peer receive timeout is currently 45 seconds. In 1v1 there is no mathematically correct way to turn non-delivery into proof that someone cheated at the game. Lock/reveal withholding must be treated as unproven abort/disconnect/forfeit according to a signed prior match policy. No referee or vote is required to verify genuine signed impossible gameplay. This experiment does not resist wallhacks when clients receive secret state or aimbots that emit valid player inputs.

Remaining gaps before production are listed in [42](42-REMAINING-GAPS.md).
