# 08 — P2P ordering, validator quorums, and finality

**Core warning:** P2P gossip isn't consensus. Replaying correctly doesn't force a malicious player to acknowledge a result. Safety, availability and finality require an explicit fault model and agreed authority.

## Three supported trust profiles (design)

| Profile | Authority | Guarantees and limitation |
|---|---|---|
| Central referee | Dedicated authorized server with signed checks | Efficient authoritative ordering; single trusted failure/censorship point |
| Fixed BFT validator roster | `n >= 3f + 1` identities, tolerate up to `f` Byzantine members | Safety under signatures, correct locking and partial synchrony; live only after network stabilizes with adequate responsive validators |
| Bilateral/optimistic | Players publish contradictory claims to neutral observers or witnesses | Public evidence may be indisputable, **but no objective unilateral match finality** unless an arbiter/referee/contract rule is agreed beforehand |

**Default design for adversarial prize/ranked games:** an independently enrolled BFT roster (not a player-generated fake roster). A 2-player match with no trusted third party cannot guarantee honest consensus against one malicious player. Signer count is not Sybil resistance; membership and authority must be cryptographically pinned in the genesis manifest.

## Static BFT quorum calculations

For `n=3f+1`, commit certificate quorum `q=2f+1`. Two quorums intersect in at least `f+1` validators, so with at most `f` Byzantine validators, at least one honest validator participates in the intersection. **This safety argument only holds if honest validators never sign conflicting locked checkpoints.** For `n > 3f+1` (currently rejected by the prototype config), choose a quorum satisfying `2q - n > f`, not blindly `2f+1` (e.g., `q = floor((n+f)/2)+1` if appropriate for liveness); require `q <= n-f` for liveness under f failures. The prototype config currently enforces only `n >= 3f+1` and `q = 2f+1`; therefore **do not use roster sizes greater than `3f+1` for BFT safety** until the configuration and certificate verifier are upgraded. For exact 3f+1 rosters, signatures alone still require a safe multi-round protocol.

## Proposed consensus protocol, not yet implemented

1. **Manifest:** pin validator roster, epoch, initial state, ruleset hash, tick/round schedule, max `f`, signature scheme and challenge window.
2. **Propose:** authorized leader proposes `(epoch, height/tick, round, parent QC, prior state root, ordered input root, claimed next state root, DA receipts)`.
3. **Validate/lock:** validator checks authorization, parent lock, availability, ordering and (optionally) cheap replay before signing a unique vote. Persist vote/lock in write-ahead log *before* sending signature.
4. **Prepare/commit:** collect authenticated phase certificates according to a reviewed BFT protocol (e.g. HotStuff-style chained finality). A standalone signature collection is not enough; formal voting and lock rules are required.
5. **View change:** on timeout, broadcast signed highest safe QC/lock to next leader; new leader extends a safe ancestor. Monotonic round/epoch and fencing tokens prevent rollback/double signing.
6. **Provisional application:** allow local prediction/fast feedback; do not distribute irreversible prizes until challenge window closure and settlement policy.
7. **Fraud dispute:** freeze affected provisional descendants, validate independently, propose canonical correction under the same BFT rules, retain both original and corrective artifacts.
8. **Finalize:** after safe consensus commitment **and** challenge deadline, mark a checkpoint application-final; any external settlement is a separate, game-chosen policy outside the core SDK.

## Exact risks and fallbacks

- **Byzantine fraction exceeded:** protocol safety cannot be promised; preserve raw signed equivocation and public incident records, pause settlement.
- **Network partition:** permit provisional local simulation only; halt global irreversible finality until a live authorized quorum reconnects.
- **Validator crash/restart:** restore durably signed highest lock, prior QCs, membership epoch, checkpoint history and own vote set before casting votes.
- **View-change failure:** deterministic timeout escalation with view numbers, leader election and a bounded catch-up protocol; do not turn a missing vote into a semantic cheating verdict.
- **Membership rotation:** epoch transition must be authorized by the old roster's approved reconfiguration rule plus new roster acceptance; epoch-specific public keys and historic QCs remain verifiable forever.
- **Conflicting finalized roots:** treat as consensus safety violation, preserve signatures, stop irreversible settlement and activate explicitly documented recovery arbitration.
- **Censorship or omission:** signed acceptance receipts allow accusations, but failure to deliver a move by a deadline may be network fault. Resolve under precommitted input-admission rules.

## Application finality vs consensus finality vs chain inclusion

- **Consensus finality:** protocol-certified canonical order/commit under trust assumptions.
- **Application finality:** challenge window closed and ruleset dispute paths exhausted; result may be released.
- **External publication finality:** a storage- or settlement-system-specific assumption about a published artifact; it does *not* by itself establish either of the above.

## Implementation state

The SDK ships **no** BFT consensus component. Accountability is evidence-based: signed, hash-chained histories, signed conflicts and independently replayable fraud evidence ([35](35-ACCOUNTABILITY-GUARANTEES.md), [36](36-CHALLENGES-WITNESSES-EVIDENCE.md)). A quorum or leader-based sequencer, if a game wants one, is its own component and must itself be model-checked and fault-tested before being relied upon; objective fraud validity is never decided by a vote.

## r3 signed event batching / independent 1v1 evidence

For decentralized **1v1**, quorum-based BFT over only two participants cannot guarantee termination with one Byzantine peer. Choose immutable bilateral acceptance with honest stalemate/forfeit rules, a shared ordering service the game agrees on in advance, or additional independently enrolled witnesses. One valid rule-violation witness still wins without any vote. A reference to an external record is not proof an off-chain input was accepted. Details: [22](22-INPUT-PACKING-AND-DECENTRALIZED-1V1.md).

## r4 bilateral prototype, not BFT

The `gv-edge` 1v1 demonstration uses bilateral signed batch admission and co-signed checkpoints. This guarantees that a single client cannot produce a *mutually certified* next checkpoint without the other signing, but cannot guarantee liveness or timely inclusion against one malicious peer. For 3+ or permissionless participants, the BFT/consensus mechanisms described above remain unimplemented. Details: [23](23-EDGE-P2P-PROOF-OF-CONCEPT.md).
