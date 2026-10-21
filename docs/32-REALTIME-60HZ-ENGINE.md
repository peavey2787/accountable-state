# 32 · Real-time 60 Hz engine with asynchronous cryptographic finality

**Goal:** 60 Hz gameplay with sub-second cryptographic finality, *not* 200–500 ms gameplay.
The simulation never waits for the network or for cryptography; signed inputs, replay,
Merkle commitments, checkpoint co-signing and fraud proofs run in a separate pipeline a
fraction of a second behind it. This supersedes the four-phase-per-epoch flow described
in docs 28–31, which could not exceed a few ticks per second.

## Measured result (two real native processes, Linux, debug build of this workspace)

Sustained, randomized two-player button mashing for 40 s per run, plus a hidden window.
Reproduce with `./scripts/bench-realtime-linux.sh` (see [Benchmarking](#benchmarking)).

| checkpoint every | simulation | input → screen | **finality** (tick played → both signatures agree) | CPU / process | input stream | hide catch-up |
|---|---|---|---|---|---|---|
| 10 ticks (167 ms) | 60.0 Hz, jitter ≤ 0.7 ms | p50 12.6 / p95 13.6 ms | **p50 13 / p95 16–18 / max 20–22 ms** | ~15 % of a core | 2.5 kbps tx | 275 ms |
| **20 ticks (333 ms, default)** | 60.0 Hz, jitter ≤ 0.7 ms | p50 12.5 / p95 14.0 ms | **p50 13 / p95 16–17 / max 19–23 ms** | ~10 % of a core | 2.5 kbps tx | 127 ms |
| 30 ticks (500 ms) | 60.0 Hz, jitter ≤ 0.7 ms | p50 12.6 / p95 14.1 ms | **p50 13 / p95 16 / max 18 ms** | ~8 % of a core | 2.5 kbps tx | 106 ms |

* Input → screen is measured through the same HTTP endpoints a browser uses (POST, next
  60 Hz tick, next poll). It is dominated by the tick period, not by networking.
* Finality is measured from the moment a tick was played to the moment both players'
  signatures on its checkpoint agreed. It is **not** network ping. Zero epochs exceeded
  100 ms; zero HYDRA calls exceeded 100 ms; zero retransmits, bad frames or send errors.
* Over a 150 s continuous run (450 epochs) finality stayed flat (p50 12–13 ms, p95 16–19 ms)
  and process memory flattened (48 → 54 MB).
* An idle match sends and verifies **nothing** (0 epochs in 3 s; ~0.2–0.5 kbps keep-alive).
* Cold start (process launch → both peers live): 4.4–4.8 s (7.1 s for the first run, which
  included a build); 12 of 12 consecutive runs passed `scripts/smoke-arena-linux.sh` (first
  certified epoch 0.7 s after going live, a complete hide cycle in 6–9 s).

These are loopback numbers on one machine. They show the *local* pipeline cost and that
the protocol does not add latency of its own; real WAN latency adds one round trip to
finality (and does not touch the 60 Hz loop), and loss behaviour on a real network has
not been measured.

## Architecture

```text
 browser ──/controls──▶ ┌─────────────── sim loop (60 Hz, one task) ───────────────┐
 (local HTTP only)      │ sample input → Timeline.advance (real rules, prediction) │
 ◀──/state (poll)────── │ StreamSender ─ run-length input frames ─▶ P2P (lossy)    │
                        │ apply: RemoteInputs → rollback · Finalized → rebase       │
                        └────────────▲──────────────────────────┬──────────────────┘
                                     │ events                    │ own control per tick
                        ┌────────────┴──────────────────────────▼──────────────────┐
                        │ pipeline task (never on the 60 Hz path)                   │
                        │ sign epoch batch · replay · Merkle root · co-sign         │
                        │ checkpoint · fraud / illegal-input evidence · hide        │
                        │ (commit → lock → reveal) · receipt archive                │
                        └────────────────────────────┬──────────────────────────────┘
                                                     │ reliable, ordered messages
              P2P session actor: Hydra (4 KiB Lite packets) + p2p-net, bundling,
              windowed retransmission, lossy stream channel, silence back-off
```

| piece | where | role |
|---|---|---|
| `Timeline` | `crates/edge/src/live/timeline.rs` | provisional 60 Hz simulation with the **real** rules engine; predicts the opponent by holding their last control; rolls back and re-simulates when authoritative input disagrees; bounded prediction (180 ticks) and stall; `rebase` onto each certified state |
| `StreamFrame` / `StreamSender` | `live/stream.rs` | run-length input changes with cumulative acks; redundant, idempotent, loss- and reorder-tolerant; silent when idle; never describes a hidden tick |
| `Pipeline` | `live/pipeline.rs` | epoch agreement, signing, replay, co-signing, evidence, hide protocol |
| `LiveSession` + `Reliable` | `adapters/p2p/src/{native,reliable}.rs` | non-blocking reliable and lossy channels over one Hydra session |
| `game.rs`, `ui.rs`, `arena.html` | `examples/edge-p2p` | orchestration, local HTTP bridge, page |

### Determinism and the 60 Hz rules

Time never enters the rules, only the tick index. `ArenaRules` (ruleset
`gv/example-arena/public-deterministic/v1`) applies one step per player per tick, so
time-based mechanics are in ticks: a held direction repeats every 8 ticks (7.5 squares/s;
a tap moves exactly once), attack cooldown is 30 ticks. State is 30 bytes. There is a single
format and ruleset version; no older formats are read or migrated.

An illegal control word (outside the legal set, or contradictory movement) no longer makes
an epoch uncertifiable. Every honest replay and every independent verifier **neutralizes**
it (replays it as control 0) and the signed batch becomes portable proof (`apply_tick`,
`MatchReplica::live`, `verify_checkpoint_evidence_with(.., sanitize = true)`, archive magic
`GV-CERTIFIED-MATCH/V1`). A cheater therefore cannot stall the match, only get caught.

### Input streaming vs. signed batches

* **Stream frames are hints**, not evidence: session-authenticated but unsigned, sent only
  when a control changed, repeated until acknowledged, silent when idle (a keep-alive per
  second). They give the opponent low-latency prediction and rollback.
* **Signed epoch batches are the record.** At each epoch each player signs the exact
  controls they played (`SignedPackedControls`, chained to their previous batch). The
  opponent's timeline is corrected to the signed inputs the moment they arrive.
* **Public play uses no commit-reveal.** Inputs are not secret, so a commitment round trip
  per epoch would add latency for nothing. Commit-lock-reveal is used only for the hidden
  window below.

### Epochs and finality (no negotiation rounds)

* Only a player with something to certify opens an epoch (any non-neutral input, a pending
  test injection, or a forced idle cut every 3,600 ticks). The other answers with the same
  end. Idle matches therefore exchange nothing.
* If both open different epochs, **the shorter end wins**; the longer proposer answers with
  the identical-prefix batch. Nobody signs a longer end after a shorter one, so both sides
  always pair on the same end (tested under 0–25 ticks of delay and 0–9 ticks of clock skew).
* Epochs are certified strictly in order: both sign batches → each replays independently →
  both co-sign the checkpoint → `finalize`. Disagreement yields evidence (below) and the
  honest replay becomes the chain head (`finalize_disputed`).
* A disputed epoch has no dual signature, so it cannot be exported as a receipt: the
  exportable archive ends there while play and verification continue.

## Hide (commit-reveal, exercised by the **Hide 5 s** button / `H`)

`SignedHide` announces a 5 s (300-tick) window starting on an epoch edge ≥ 30 ticks ahead,
with a 10 s cooldown after it. During the window:

1. The hider **stops streaming** and sends no batch. The observer predicts them standing
   still and shows a fog marker at the last provable position. Nothing about their location
   is in the observer's memory or on the wire.
2. At every epoch edge (always, even when idle, so activity does not leak) each player
   signs a batch and exchanges a **signed `BatchCommitment`** (a blinded hash of the signed batch: `H(blind || batch digest)` with a fresh random 32-byte
   blind revealed only in the opening), then **signed locks**
   over both commitments. Cells chain through `previous_batch_hash`, and the commitment
   anchor is the checkpoint before the window, so each cell is bound as it happens.
3. The observer's inputs were never secret and are opened right after the locks. The hider
   opens **after the window closes** (`Reveal`). Each reveal must hash to its commitment.
4. The observer replays the revealed cells in order, rolls its provisional state back, and
   both co-sign the hidden epochs (catch-up ≈ 17 ms per epoch).

Faults: a reveal that does not match its commitment → `BadReveal` evidence; a lock with no
reveal for 20 s after the window → `WithheldReveal` (attributable, reported, and the
certified chain stalls until it opens). Hiding is never a violation by itself.

## Violations and evidence (`gv-edge`, offline-verifiable)

| violation | proven by | exported as |
|---|---|---|
| false signed checkpoint | independent replay of both signed batches ≠ the signed claim | `GV-FRAUD-BUNDLE/V1` (self-contained; `verify` → `ProvenInvalidState`) |
| illegal signed input | replay shows the accused's signed control rejected by the rules | `GV-EVIDENCE/V1` (`verify` lists player, word, tick) |
| bad reveal / equivocation / withheld reveal | commitment vs reveal; two signed batches for one range; lock without reveal | evidence bytes (`.violation-N-kind.bin`) |

`scripts/headless-arena-linux.sh` runs two scripted peers (hide, an illegal word, a false
checkpoint), then verifies every saved artifact with the offline `verify` command.

## Transport engineering (what made 60 Hz practical)

Each item below was found by measurement; the first three were behind the "first-commit
timeout" and the finality blow-ups seen earlier.

1. **HYDRA is a messenger**, and `send`/`receive` store every message in a per-contact
   history (hard limit 10,000) and rewrite the whole encrypted state on every call. Cost
   grew from ~2 ms to ~9 ms per message (spikes of 180–260 ms) and a match would have died
   after ~3 minutes. The session now **prunes history every 16 operations** and, by default
   in the scripts, keeps the match's throwaway session state on RAM-backed storage
   (`GV_HYDRA_RAM=1`; identity is only copied). Result: flat 0.5 ms send / 5.6 ms receive.
2. **Bundling.** One HYDRA message costs a fixed ~2 ms/~5 ms regardless of size, so
   everything due in one flush (stream frames, reliable frames, acks) is packed into as few
   4 KiB Lite packets as fit.
3. **Retransmission.** Only the head-of-line frame is retransmitted (the receiver buffers
   early frames), with a 150 ms floor, exponential backoff and fast retransmit on duplicate
   acks. The first version retransmitted whole windows under a 40 ms timer and flooded itself
   (63 messages queued, 286 transmitted).
4. **Lite packets.** `Hydra::set_packet_size(4096)` instead of the default 32 KiB class
   (~170 KB on the wire per message through p2p-net's JSON fragmenting).
5. **Fan-out lag is not fatal.** p2p-net hands messages to the app through a bounded
   broadcast channel; `Lagged` is one lost packet, which both layers already tolerate.
6. **One connection per peer, QUIC.** Parallel TCP+QUIC+public-IP connections stranded queued
   Gossipsub messages for seconds. The demo configs use a single loopback QUIC listener.
7. **No public bootstrap in the demo.** With the default config p2p-net resolved public
   libp2p bootstrap/relay lists (6–19 s of DNS-over-HTTPS) and announced the private match
   topic to public nodes. The demo configs empty those lists; Alice dials Bob directly.
8. **Pipeline bookkeeping must be O(1) per epoch.** Re-encoding and rewriting the whole
   receipt archive per epoch made finality grow ~0.14 ms per epoch; it is now append-only
   (`ArchiveBuilder`, byte-identical to a full encode) with writes at most once a second.
9. **Pairing deadlock** (fixed, with a regression test): a responder whose clock lagged
   recorded the opponent's batch as "owed" and never re-checked for a pair after answering.

## Benchmarking

```bash
./scripts/bench-realtime-linux.sh                          # 20-tick epochs
GV_ARENA_EPOCH_TICKS=10 BENCH_SECONDS=60 ./scripts/bench-realtime-linux.sh results.json
./target/debug/gv-edge-p2p-demo bench-hydra prune          # crypto cost in isolation
./scripts/smoke-arena-linux.sh                             # cold start + hide cycle, fail-closed
./scripts/headless-arena-linux.sh                          # scripted match + offline verification
```

The benchmark reports tick rate and jitter, input→screen latency, finality distribution,
bandwidth, CPU, rollbacks, HYDRA worst-case call time, retransmits and the hide catch-up,
and exits non-zero unless both peers agree on the final checkpoint with zero violations.

## Knobs

| setting | meaning |
|---|---|
| `GV_ARENA_EPOCH_TICKS` / `--epoch-ticks` | checkpoint cadence (6–120, must divide 300) |
| `GV_HYDRA_RAM=1` | session state on `/dev/shm` (set by the scripts; needs Linux tmpfs) |
| `--hide-at=T` `--cheat-at=T` `--illegal-at=T` | scripted hide / false checkpoint / illegal word |
| `--epochs=N` | headless: stop after N certified epochs |
| `GV_REMOTE_PEER_ID` + `GV_REMOTE_MULTIADDR` | dial directly instead of waiting for discovery |
| `max_predict` (180 ticks), `STREAM_*`, `PipelineConfig` | code constants in `game.rs` / `live/pipeline.rs` |

## Limits and honest caveats

* **Input look-ahead.** Public inputs are streamed in the clear and signed afterwards. A
  player who delays their own stream can see the opponent's inputs first and adapt; that is
  indistinguishable from network delay and is **not** detected. (Per-tick delivery deadlines
  or a commit-reveal for hidden-information actions are the usual mitigations.) Signed
  batches do stop anyone rewriting what they already played.
* A cheater who streams one thing and signs another only causes bounded provisional
  rollback on the opponent (stream frames are unsigned hints, so this is not provable fraud).
* Hide gives the hider an information advantage by design (they see the opponent during
  the window), and attacks made while hidden resolve retroactively at the reveal. Each
  20-tick cell is committed as it ends, so earlier cells cannot be rewritten in hindsight.
* Two players only; no Byzantine liveness. A peer that stops sending stalls the simulation
  at the prediction limit; one that never reveals stalls the certified chain.
* Clock alignment is a one-shot half-round-trip estimate; drift is bounded by the stall
  rule and only affects how far ahead one side predicts.
* The HYDRA history pruning and RAM store are application-side workarounds. The clean fix
  is upstream: a no-history/ephemeral mode and compact state writes in `hydra-msg`.
* Linux only (`/dev/shm`, bash scripts). No fuzzing, long-run soak beyond minutes, external
  audit, or real WAN/loss testing has been done.
