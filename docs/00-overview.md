# 00 — Product overview and scope

**Status:** Architecture specification v0.1.0. What is implemented, model-checked, tested and still open is in [41](41-FORMAL-MODEL.md) and [42](42-REMAINING-GAPS.md).

## Purpose

Allow honest participants, referees, or spectators to independently establish whether claimed gameplay state transitions complied with a committed and immutable ruleset. Make most verification optimistic: record tamper-evident evidence up front, perform inexpensive checks and event-driven audits, and produce a small, independently checkable witness only when something is disputed. Support post-match commit/reveal when the title can tolerate delayed results. Avoid kernel hooks, binary attestation, surveillance of user devices, compulsory cryptocurrency, and heavyweight continuous ZK proving.

## The four fundamentally different claims

1. **Attribution:** participant P signed these canonical bytes. Authentication only; not whether its contents are true.
2. **Inclusion:** committed transcript root R contains a specified record at position i. Merkle proof; not completeness, freshness or availability by itself.
3. **Semantic validity:** canonical ruleset F maps independently authenticated prior state S plus ordered inputs I to claimed next state S'. Deterministic replay or a proof pinned to F and public commitments.
4. **Network acceptance:** under an explicitly identified agreement protocol, checkpoint C was the canonical accepted checkpoint for the match. This requires fault assumptions, validator roster, finality and deadlines; mere P2P gossip is insufficient.

No component may silently substitute one claim for another.

## Modes

| Mode | Input disclosure | Response to invalid transition | Finality |
|---|---|---|---|
| Real-time | Inputs necessary to verify each tick immediately available to authorized verifiers | Reject before applying or hold provisional | Small windows, if network supports it |
| Optimistic | Signed inputs and checkpoints immediate; encrypted/sealed witnesses retained | Challenge during fixed fraud window; rollback provisional state | After quorum certification + end of challenge window |
| Post-match | Commit to inputs/state early; reveal agreed secrets at match end | Replay and submit bounded fraud evidence | After authenticated reveal and challenge closure |
| Private/ZK optional | Reveal only public statement; prove private witness | Reject invalid proof or accept valid pinned claim | Same network ordering/finality requirements |

**Post-match privacy is temporary.** Do not promise perpetual secrecy where plaintext is required for replay. Real-time private visibility requires information minimization and/or selective proof, not end-game replay alone.

## Example: movement

The match agrees on spawn/initial state, tick cadence, fixed-point position, and legal speed/collision rules. Every input is signed and sequenced, and the checkpoint is committed by the validator roster. A third-party verifier replays from a trusted anchor to the challenged tick. A teleport is proved only if the claimed accepted transition cannot be produced by the legal rules. If no one can obtain the relevant authenticated input or state opening, the proper classification is **unavailable/inconclusive**, not automatically proven cheating. Non-disclosure may trigger an agreed forfeit separately.

## Deployment separation

`core`/`commitments`/`transcript`/`replay` must remain usable in local, LAN, centralized, and decentralized environments. `edge` provides the real-time engine, accountability and witness protocol. `p2p` distributes authenticated bytes. `zk` adds pinned computation proofs only for rules that cannot be made publicly replayable. There is no blockchain requirement anywhere in the core.

## Security and compliance boundaries

The SDK doesn't prevent humanly implausible but legal actions, botting, aimbot input choices, wallhack exploitation of data already disclosed, endpoint key theft, unavailable data, DoS, or colluding majorities. Some can be made harder by game design, information isolation and policy, but a valid replay alone cannot detect them. No global cheating reputation should be assigned on unverifiable allegations.

## r3 signed event batching / independent 1v1 evidence

Input transport now also supports **signed event-driven button-state batches**. For matches where measured, wallet-preflighted serialized data fits the transaction budget, publish the complete authenticated input batches on-chain; otherwise use off-chain DA plus Merkle commitments. See [r3 input compression/1v1 specification](22-INPUT-PACKING-AND-DECENTRALIZED-1V1.md).
