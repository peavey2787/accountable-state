> Accountability-layer threat model, assumptions and guarantees: [docs/35](35-ACCOUNTABILITY-GUARANTEES.md).

# 02 — Threat model and security properties

## Trust assumptions

Trusted: a published canonical verifier/ruleset with pinned hash; collision-resistant hashing; unforgeable signatures; approved game genesis and match invitation; retrievable evidence within retention period; all-party agreement on protocol versions. Not trusted: game client, host OS, graphics process, modded binaries, client timestamps, network delivery/ordering, remote RPC, unverified external storage, opponent-provided keys, gossip endorsements, or unauthenticated published payloads.

## Attacks and required countermeasures

| Attack | Why signatures/roots alone fail | Protocol control | Residual limitation |
|---|---|---|---|
| Teleport / speed | Client signs a false state | Authenticated predecessor + deterministic physics replay | Needs correct collision/rules and authoritative time |
| Spawn spoof | Illegal prior state may still produce a legal step | Match manifest authorizes genesis; chain anchors | Initial trusted configuration could itself be compromised |
| Replay/out-of-order | Valid signed input reused in new context | Match ID, tick, sequence, player and epoch binding | Requires reliable canonical ordering |
| Equivocation | Player signs two incompatible proposals | Keep both signed artifacts; compare same slot/domain | Proof of misbehavior, not necessarily a physics violation |
| Withheld reveal | Root does not expose preimage | Data custody, deadlines, predictable forfeit | Data loss does not necessarily mean intentional cheating |
| Withheld P2P traffic | Peer can selectively isolate verifiers | Replication, quorum, timeout, view change, reconnect/recovery | Partial synchrony cannot guarantee availability during full partition |
| Sybil validators | Many fake node IDs manufacture votes | Fixed roster / stake / game-authorized admission | Corrupt majority can violate protocol assumptions |
| Colluding validators | Majority certifies bad state | Independent replay + challenge window; external observers | Cannot rely on colluders to honor dispute or penalty policy |
| Wallhack | A legal action was influenced by leaked hidden state | Never send unobservable state; per-recipient views; delayed disclosure | If data reaches client, cryptography cannot erase it |
| Aimbot/bots | Machine chooses fully legal input faster than a human | Game-designed rate limits, interaction policy, server-side visibility; heuristics explicitly outside proof | No cryptographic proof of human agency |
| Input timing abuse | Timestamp comes from attacker-controlled clock | Accepted authoritative tick and deterministic scheduling | Latency compensation must itself be deterministic |
| Nondeterminism | Honest peers reach different results | Fixed-point math, canonical RNG, cross-platform vectors | Some legacy physics may require measured compatibility layers |
| Malformed proofs | Resource exhaustion or decoder confusion | Strict canonical encodings, size caps, parsing limits, budget | Parser bugs remain possible |
| Malicious fraud claim | Griefing and slander | Exact evidence verification, refundable challenge bond, cheap prefilter | Punishment must not follow a submitted hash alone |
| Signature/key theft | Attacker controls account signing key | Rotation, rekeying and revocation before acceptance, account recovery | Cannot tell stolen signature from legitimate signature on its own |
| Validator restart | Re-signing conflicting height after crash | Persist signed-lock and QC state to durable WAL before voting | Requires durable storage configuration and operational checks |
| History tamper | Delete early input, preserve later roots | Chain of previous checkpoints + non-equivocation | Availability receipts still necessary |
| External record loss | A published commitment is removed or reordered by the external system | Evidence is self-verifying; republish from the local archive | Publication never guarantees correct gameplay |

## Four classes of finding

1. **Semantic invalidity:** independently replayed accepted transition deviates from official rules. Evidence requires trusted predecessor, accepted claim, authenticated inputs, and deterministic witness (or pinned ZK verification).
2. **Equivocation:** same admitted identity cryptographically signed inconsistent mutually exclusive artifacts for same slot. May be provable using only two signatures, even without replay.
3. **Protocol fault:** missing reveal, invalid availability receipt, missed deadline, inactivity, refusal to vote, or delayed packet. Can justify forfeit/disqualification under preset policy but does NOT prove semantic cheating.
4. **Suspicion/inconclusive:** statistical anomalies, inaccessible evidence, bot-like actions, graphics telemetry, malformed accusation, or undefined physics. Never promote to cryptographic conviction.

## Game categories

Turn-based deterministic card/board games can often disclose all committed inputs afterward, but hidden deck order must be verifiably generated and preserved. Racing and strategy benefit from batched replay with periodic state roots. Shooters/MMORPGs require careful line-of-sight and selective server/arbiter disclosure because a client cannot be allowed to learn all positions. Physics-heavy games require cross-platform deterministic fixtures. Competitive rewards with financial stakes require independent safety/finality and an appeal/governance plan.

## Out of scope

Prevention of all cheating, trustless proof of human input, physical peripheral attestation, arbitrary real-world input authenticity, bandwidth/censorship protection under total outage, retroactive secrecy after reveal, and automatic global bans. Anti-cheat outcomes are scoped to their match/ruleset and explicitly identified verifier model.

## r3 signed event batching / independent 1v1 evidence

New attack surface: compressed event streams with redundant states/nonminimal varints, withheld signed batches, chain transaction censorship, unrelated matches mixed into aggregates, premature publication of secret moves, fake consensus from a block-hash reference. Require canonical rejection, authenticated chain/genesis admission, on-time receipts or actual on-chain inclusion, and bounded witnesses. A solitary mathematical witness proves a **violation of authenticated rules**, not completeness of an unknown input set. See [r3 profile](22-INPUT-PACKING-AND-DECENTRALIZED-1V1.md).
