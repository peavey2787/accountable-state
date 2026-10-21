# 04 — What a game must provide: integration contract

The minimal three inputs from the developer are **(1) canonical initial state, (2) deterministic state transition, (3) authorized information disclosure policy**. Production hostile-multiplayer integration requires several additional commitments specified below.

## Required A: canonical match manifest and initial state

Before accepting any player input, generate a signed/approved immutable `MatchManifest` specifying:

| Field | Required meaning |
|---|---|
| `match_id` | Fresh unpredictable 32-byte match instance identifier, not a reusable lobby name |
| `protocol_version` | Exactly defined wire/crypto rules, hashes and edge cases |
| `game_id`, `ruleset_hash`, `vm_image_id` | Identity of canonical game rules, physics, collision map, asset versions and optional proof program |
| `genesis_commitment` | Root commitment to legal initial player/world state; opening or trusted generation procedure documented |
| `participants` | Bound authenticated signing keys, roles, join/leave policy and reconnect identities |
| `validators` | Fixed admission policy, epoch, public keys, Byzantine fault bound and quorum |
| `tick_policy` | Logical tick duration, input deadline, grace/lag compensation, scheduling, simultaneous-action resolution |
| `randomness` | Public seed beacon, verifiable reveal/VRF, bias resistance, replay transcript, anti-withholding procedures |
| `privacy_policy` | Classification of every state field and per-observer viewing/disclosure rules |
| `dispute_policy` | Challenge window, retention, proof limits, response deadlines, fees/bonds, appeals and default action |
| `resource_policy` | Max state/input bytes, allowed batch length, proof/witness limits, peer bandwidth and CPU budgets |
| `end_policy` | Match terminal conditions, results, award distribution, settlement and archive rules |

No field may be changed mid-match unless a versioned, quorum-authorized reconfiguration is explicitly part of the manifest; old checkpoints remain under old rules. The prototype `MatchManifest` contains only initial core fields; this table is the full production contract, not a claim about current code.

## Required B: deterministic canonical transition

Recommended Rust-facing shape:

```rust
pub trait GameRules {
    fn ruleset_hash(&self) -> [u8; 32];
    fn apply(&self, old: &[u8], input: &[u8]) -> Result<Vec<u8>, String>;
}
```

This is the current *minimal* SDK trait. Mature API should add `validate_input`, `advance_tick`, `validate_cross_player_interaction`, `reason_code`, and bounded execution instrumentation. The transition MUST use canonical serialization and agreed input ordering. It must reject invalid inputs and perform checked integer arithmetic; for deterministic movement use signed fixed-point coordinates (e.g., millimeters in i64) and fixed tick duration. No `Date.now()`, OS RNG, nondeterministic hash map iteration, unseeded random scheduling, or renderer-dependent physics may influence canonical outcomes.

Example movement invariants: displacement/velocity, acceleration, jump arc, grounded state, stamina, obstruction, teleports authorized by spells, boosts and mounts, map bounds, friction, collision order, root motion/animation effects, and max tick budget. Merely checking global speed incorrectly flags legitimate jumps, knockbacks and speed buffs; titles must express their real rules.

For legacy/PS2-accurate games, preserve the original reverse-engineered gameplay decisions, collision boundaries, packet encodings, and timing semantics using deterministic reference fixtures. Do **not** simplify physics solely to make it easy to verify; model authentic behavior or isolate trusted non-deterministic effects.

## Required C: authorized visibility

Provide a view projection per observer identity and role. Decisions are evaluated *before* sending content and again before honoring retrieval requests:

- Public: safe for all peers including spectators.
- Owner-only: private to owning player and authorized verifier; not sent to opponents.
- Team-scoped: visible only to team members with valid membership for that tick.
- Hidden-until-reveal: encrypted/stored and automatically disclosed under agreed deadlines.
- Never-reveal: no raw state is published even after the game; verification requires trusted referee or ZK for rules that rely on it.

A commitment is not a visibility policy. A server/peer that transmits hidden enemy coordinates has already lost confidentiality—even if the resulting movement is later proven legal. See [11](11-privacy-visibility.md).

## Additional required multiplayer decisions

1. **Global ordering** of cross-player inputs and conflict resolution: who decides two shots/exchanges/loots that occur during the same tick?
2. **Inter-player authorization:** what state does a hit, trade, or spell need; how is reachability proven without leaking unseen actors?
3. **Time authority:** input receipt deadlines and lag compensation must use agreed logical/timestamp policy, not player clock.
4. **Custody:** which actors retain input and state openings? Are reveals post-game? How do they prove honest storage?
5. **Fault model:** who decides a dispute if two peers disagree, and who enforces a forfeit?
6. **Run-time budget:** deterministic maximum steps, storage, memory, event depth, and evidence size.
7. **Privacy-lifecycle:** when are keys erased and who can still obtain plaintext after retirement?
8. **Gameplay exploits vs technical cheating:** inputs legal under the rules may still be unintended; policy changes require new ruleset version and cannot retroactively change past verdicts.

## Developer checklist

- [ ] Record and pin official replay engine binary/source revision.
- [ ] Supply canonical sample game genesis and signing keys for tests only (no production secrets).
- [ ] Supply valid and invalid transition fixtures at every gameplay mode change.
- [ ] Supply state visibility tests (enemy hidden, owner visible, team changes, post-match disclosure).
- [ ] Define player roster, validators, sequencing, challenge deadlines, forfeit conditions.
- [ ] Set hard byte/CPU limits and reproducible cross-platform tests.
- [ ] Test replay of every supported version, including from checkpoints and after crash recovery.
- [ ] Define how legitimate client predictions are reconciled to accepted state.

## Minimal toy example

`examples/movement/src/main.rs` implements a signed single-coordinate toy transition, with domain-separated state commitments and an inclusion path. It is a local demonstration, not multiplayer acceptance or physical anti-cheat. `crates/sdk` exposes an early `GameAdapter` trait with `initial_state`, `view_for`, and `validate_manifest`; additional methods above are planned.

## r3 signed event batching / independent 1v1 evidence

The game also selects a **canonical input codec** (event-packed 8/16-bit digital controls v1, or a game-specific analog/other version), a maximum batch size and update rate, a chain-inline budget policy, and a first-batch/genesis predecessor hash. It defines how input-only streams deterministically reconstruct XYZ. A match may span multiple signed batches; no implicit lossy quantization is allowed. See [r3 format](22-INPUT-PACKING-AND-DECENTRALIZED-1V1.md).
