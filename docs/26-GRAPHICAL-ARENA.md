# Browser arena: playable two-peer edge-verification demo

## What this is

This is a **local graphical frontend for each real Rust peer**, not a centralized web service or a second Javascript simulation. Each Rust executable binds a loopback-only HTTP listener. The browsers submit signed-control requests to their respective local peer; the actual game rules, event-packed input signatures, bilateral commit/lock/reveal, Merkle root, deterministic state transitions, signed checkpoint, and evidence verification remain in Rust. The browser never computes authoritative movement or adjudicates fraud.

The UI displays a 17×17 public grid, obstacles at `(0,0)` and `(0,1)`, two fighters, movement, guarding, health, and attack cooldowns. Ordinary movement into walls, bounds, or opponents is a no-op; holding attack during a cooldown does not bypass it. These playable semantics are identified by the arena ruleset hash, which every signed message binds.

## Local Linux launch

Requires Rust 1.98+, `cargo`, `openssl`, a current browser, and the Git-sourced `p2p-net` and `hydra-msg` dependencies. From the extracted repository root:

```sh
./scripts/format-all.sh
./run-all-linux.sh
./scripts/play-arena-linux.sh
```

The launcher creates **two separate processes**, identities and Hydra profiles under `.arena-local/`, then opens:

- Alice: `http://127.0.0.1:9001/`
- Bob: `http://127.0.0.1:9002/`

If the peer discovery namespace is not working in your environment, inspect `.arena-local/alice.log` and `.arena-local/bob.log`. `p2p-net` still needs viable local discovery or explicit peer ID/dial addresses. Do not assume both nodes are connected merely because their browser pages load.

**Security:** `.arena-local/` contains test secrets; keep it private, never check it into Git, and delete it after testing. This launcher is for local development, not an identity-management design for real users. It uses an ephemeral match ID on each run and reuses demo Hydra identities only within the same local directory.

## Controls

- WASD / arrows: move one grid cell per accepted tick; hit a wall or opponent to stop.
- Space: attack if cooldown allows and opponent is in the same row/column within two unobstructed cells.
- Shift: guard; reduces incoming damage.
- **No Enter / Send input / Auto-step**: held keyboard/touch controls are sent immediately to the local Rust peer when they change. Each peer automatically captures controls on the next verification tick, subject to P2P commit/lock/reveal/checkpoint latency. The browser interpolates only between already verified positions.
- **Send cheat move**: signs a false next-state commitment. The honest opponent must reject it and export a portable fraud witness; it is not applied to the game.
- **Send invalid signed input**: emits control bit 0x80, which is not allowed by the arena rules, after mutually locking that commitment. The honest opponent can independently prove the invalid authenticated input.

The panel shows input-to-checkpoint verification latency, actual accepted ticks per second, independently accepted/rejected counts and green/red validity. It does not claim to measure raw network ping.

After a provable violation, gameplay stops and the local HTTP server stays up so the result and evidence path can be inspected. Ctrl+C stops the Rust processes.

## Evidence verification

Each successful epoch saves an independently replayable, signed receipt in `.arena-local/{alice,bob}-proof-or-receipt.bin` (files are overwritten by the next accepted epoch). When Bob catches a fraudulent Alice claim, the Bob artifact contains a fraud bundle instead. Verify it from a *separate* process with the **trusted** match ID and the two player public keys:

```sh
cargo run -p gv-edge-p2p-demo -- verify \
  .arena-local/bob-proof-or-receipt.bin MATCH_ID_HEX ALICE_PUBLIC_KEY BOB_PUBLIC_KEY
```

The match ID is `.arena-local/match-id`; public keys are printed by `cargo run -p gv-edge-p2p-demo -- init ...` with the matching player's secret seed. The evidence file is never a proof without validating those trusted match parameters and the exact ruleset.

## Trust model and limitations

The local browser interface is not a secure anti-tamper boundary. The client can always be modified; the **other** peer verifies its signed claims. The HTTP server binds only to `127.0.0.1` and checks Host/Origin for control requests, but is only a development UI. No anti-bot/aimbot or private-state wallhack protection is claimed. A malicious opponent may disconnect or refuse to sign; 1v1 liveness is not guaranteed. P2P discovery, manual contact-card trust, and actual Rust compilation must be tested on supported targets. The new GUI is not yet a production-real-time rendering/networking stack.

See [32](32-REALTIME-60HZ-ENGINE.md) for the input path, telemetry and security boundaries.
