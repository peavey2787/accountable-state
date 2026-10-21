# Encrypted edge-to-edge anti-cheat: executable protocol v1

**Status: SOURCE IMPLEMENTED / RUST NOT COMPILE-VERIFIED / LAN NOT TESTED.** This is a precise description of the r5 implementation, not a third-party audit. It does not claim general permissionless BFT, fairness under a network partition, or that a malicious 1v1 participant can be forced to finish a match.

## Product boundary

Neither p2p-net nor Hydra nor any external store is a source of game authority. Peers execute a pinned deterministic ruleset locally, exchange authenticated control records over end-to-end encrypted P2P messages, and independently check identical state. Any party can publish a portable, objectively reproducible contradiction. External reputation enforcement remains a consumer-game policy. Users can retain/export their evidence and choose independent storage or anchoring.

## Game developer integration requirements

1. **Trusted match invitation**, exchanged over an authentic channel: random `match_id` (32 bytes); canonical roster of exactly two distinct ML-DSA-65 player keys for this implementation; verified Hydra contact cards; verified p2p-net peer identity/multiaddr; protocol and ruleset version; exact input codec/tick rules; accepted genesis. A mere discovered P2P address is not authorization.
2. **Pure deterministic rules** implementing `StateMachine`: `ruleset_hash()` pinned to the exact ruleset version; `genesis(roster)` canonical byte serialization; `apply(previous_state, input)` either canonical next bytes, `RuleError::InvalidAction(ViolationCode)` for provable rule violations, or `RuleError::ExecutionFailure` for indeterminate verifier faults. Runtime replays in ascending tick and ascending player-key order.
3. **Disclosure policy**: this v1 PoC uses full PUBLIC world state. It is unsuitable for secrets such as unseen enemy positions or undealt cards without information filtering, delayed reveal, or a private/ZK execution integration. Encrypting transport does not prevent a cheating recipient from inspecting data it receives.
4. **Crash/timeout policy**: bilateral 1v1 needs *both* signatures to accept any new checkpoint. A stalled or disconnected opponent causes a timeout/abort or game-defined forfeit, not an invented fraudulent-gameplay verdict. Objective proofs remain valid without the opponent's permission.
5. **Resource limits**: authenticated batch `GVEC`; max epoch 4096 ticks; public state <=65536 bytes; bounded witness/archive formats; no untrusted all-memory network allocations.

## Protocol state machine (one epoch)

```text
TRUSTED MANIFEST + ACCEPTED PREVIOUS CHECKPOINT
             |
    (1) COMMIT signed full-batch digest
             |
    (2) RECEIVE BOTH SIGNED COMMITS
             |
    (3) BOTH SIGN SAME COMMIT-SET ROOT (LOCK)
             |
    (4) RECEIVE BOTH LOCK SIGNATURES
             |
    (5) REVEAL COMPLETE SIGNED INPUT BATCHES
             |
    (6) VERIFY COMMIT MATCH + PREV BATCH HASHES
             |
    (7) EACH CLIENT EXECUTES EXACT SAME RULES
             |
         +---+-------------------------+
         |                             |
   INVALID ACTION                VALID CANDIDATE
         |                             |
  PROVE WITH BOTH LOCKS      BOTH SIGN STATE CHECKPOINT
         |                             |
   REJECT GAME STATE         APPEND DURABLE CERTIFIED EPOCH
```

**Signed commit record** (`gv/admission/commit/v1\\0`): version u8; `match_id[32]`, `ruleset[32]`, `previous_checkpoint[32]`, `player[32]`, `start_tick` u64 LE, `tick_count` u32 LE, `signed_batch_hash[32]`; ML-DSA-65 signature appended. `signed_batch_hash = SHA256("gv/packed-controls-hash/v1\\0" || full signed GVEC bytes)`.

**Lock root:** `SHA256("gv/admission/root/v1\\0" || hash(signed-commit[lower player key]) || hash(signed-commit[higher player key]))`, where `hash(signed-commit) = SHA256("gv/admission/commit/v1\\0" || signed-commit bytes)`. Lock signer signs `"gv/admission/lock/v1\\0" || lock_root || player_key`. All messages are domain separated and ML-DSA-65 verified. A reveal is admissible only after *both* valid signed locks, and must hash exactly to its prior authenticated commitment.

Input admission rejects duplicate player slots, invalid signatures, changed committed bytes, mismatched epoch/previous checkpoint, noncanonical encodings, early reveals and locking a different commitment set. A player cannot adopt a different batch after inspecting an opponent's revealed inputs without detection. However, the protocol **cannot** prevent a player from refusing to lock or reveal. Signed commitment equivocation is independently demonstrable via two signed contradictory commitments for the same player/epoch; this is a protocol offense, distinct from illegal physics.

Once revealed, both peers build an ordered Merkle tree of the *signed* batch bytes, replay `(tick,player)` deterministic steps, and sign the same canonical `Checkpoint` binding match/ruleset/prior hash/prior state/input root/new state. It advances only after two matching player signatures. The P2P transport is Hydra-encrypted over p2p-net; no part of it decides game truth.

## One-witness fraud adjudication without a vote

There are TWO independent fraud-witness types:

1. **`GV-FRAUD-BUNDLE/V1`**: prior `CertifiedMatch` receipts from known genesis + public prior state + admitted signed inputs + the ACCUSED PLAYER'S signed false next-state checkpoint. The verifier replays every prior certificate from the externally pinned match/roster/ruleset, recomputes the disputed transition and confirms `ProvenInvalidState`. A forged claim/signature, wrong parent, unknown roster or wrong game code yields *inconclusive*, not guilt.
2. **`GV-INPUT-VIOLATION/V1`**: prior verified receipts + BOTH signed commitments + BOTH matching signed lock records + BOTH revealed signed player batches + accused player identity. The verifier replays from authenticated genesis through the first invalid action and returns `ProvenInvalidAction(accused_player)` only if that action was unambiguously rejected by the canonical rules and signed by the accused. No checkpoint needs to have been accepted for this offense. An engine crash, different earlier offender or invalid lock yields *inconclusive*.

Both are portable, self-contained relative to a **trusted external match invitation**. An evidence file may never invent its own match ID, roster, rule code or trusted genesis for the verifier. `Verifier::new(TrustAnchor { match_id, ruleset, roster })` supplies the pinned identity context. Developer tooling should further sign a manifest binding ruleset binary hash and invited identities.

A third party can independently verify a proof offline using its local deterministic rules. No vote or peer acknowledgments can convert an invalid proof into a valid one, nor a valid proof into an invalid one. Independent clients need the same authenticated ruleset and previous history. This does not equate timeout or disconnect with cheating.

## Example rulesets

`gv_edge::testkit::GridRules` (feature `testkit`) is the minimal ruleset the protocol tests run on. The [anti-cheat](https://github.com/peavey2787/anti-cheat) repository holds a complete small arena. Changing any rule requires changing the ruleset identity and compatibility tests.

One action per player per canonical simulation tick is applied in sorted player-key order. At a tick, player #2 can observe the resulting state after player #1's action only through deterministic simulation; a later input cannot be crafted after reveal because its batch was already locked. The signed tick serves as a simulation index, **not a cryptographic network timestamp**.

## Crash recovery and state continuity

`CertifiedEpoch` captures two checkpoint signatures, both signed input streams, prior full state and trusted predecessor roots. `GV-CERTIFIED-MATCH/V1` stores a versioned bounded sequence. On restart `CertifiedMatch::restore` starts at canonical genesis, verifies every prior epoch's signatures, ruleset, roster, input root, state, and player-batch hash links, and replays each checkpoint before advancing. Corrupted, missing, reordered or conflicting receipts abort recovery. `AccountableState` atomically replaces its accepted-epoch archive (at most once a second) and resumes from `Config::resume`; recovery never trusts persisted next-state bytes on their own.

If an application requires secret states, encrypted persistent records and appropriate selective evidence are separate features; the public zero-nonce state commitment is **not hiding**.

## Transport, timeouts and network attacks

The example uses real upstream Git dependencies, pinning an out-of-band contact card and validating ML-DSA-65 player signatures separately from P2P/Hydra. Sender identity at the P2P layer is not a replacement for match authorization. The transport waits up to 45 seconds for a message; timeout is a local abort/unknown status, **not** a cryptographically proven offense. Duplicate, delayed, reordered, cross-match, conflicting-lock, corrupted or wrong-signer records are rejected by the signed admission/state validation. A partition can stop finality. A malicious client may always send no data.

A real product additionally needs durable receive/retransmit receipts, rehandshake/resync negotiation, authenticated deadlines, replay windows, reconnection UX, resource/CPU hardening, fuzzing and multi-OS tests, suitable anti-Sybil/BFT policies for >2 mutually distrustful players, and a privacy information-flow design.

## Limitations before treating as production

1. **Rust toolchain unavailable while building r5**; no native Rust compile/test/fmt/Clippy run and no live two-process LAN run is claimed.
2. Uploaded `p2p-net` snapshot declares BUSL-1.1 and `hydra-msg` GPL-2.0-or-later. The owner intends to relicense p2p-net to GPL-2.0, but that upstream change is **not represented as completed**; distributors must examine actual upstream terms and downstream combined-binary obligations.
3. Publishing evidence to an external store is an application concern ([38](38-EVIDENCE-EXPORT.md)). Publishing a hash does not certify alleged cheating. There is no mandatory wallet or fee.
4. Neither edge execution nor replay detects bots/aimbots that produce legal inputs, nor wallhacks if secret enemy state was delivered. The sample only demonstrates public-state physics and authenticated input offenses.
