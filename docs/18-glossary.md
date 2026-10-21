# 18 — Glossary, guarantees, and non-goals

- **Canonical ruleset:** byte-for-byte stable implementation and data defining what transitions are legal.
- **Commitment:** collision-resistant binding to previously chosen data; with randomized nonce, can conceal low-entropy values until opening.
- **Merkle proof:** demonstrates that a specific exact byte string occupies a location in a committed ordered set; does not establish truth, authorization or availability.
- **Input transcript:** authenticated ordered history of candidate or admitted player inputs, with durable signed receipts.
- **Checkpoint:** committed claimed state transition and its ancestry, inputs and participating validator attestations.
- **Quorum certificate (QC):** signatures from enough independently enrolled validator identities on the *same* checkpoint; requires safe lock protocol for true consensus finality.
- **Byzantine fault:** actor can lie, collude, omit, equivocate, deviate arbitrarily, or deliberately crash.
- **Partial synchrony:** after an unknown stabilization point, honest network messages eventually arrive within some bound; necessary for common live BFT assumptions.
- **Data availability:** ability to retrieve authenticated witness bytes within deadline, not merely a hash of bytes that once existed.
- **Provisional acceptance:** state may be used for prediction/interaction but still subject to challenge and rollback.
- **Application finality:** irreversible game/settlement decision per match policy after both consensus and challenge requirements.
- **Fraud proof:** accepted claim + authenticated relevant inputs/state + demonstrable rule violation, or a cryptographically verified proof of that same statement.
- **Protocol fault:** omission or missed deadline with authorized records; may be punishable without proving game-rule cheating.
- **Equivocation:** actor signs conflicting exclusive messages under the same domain/slot.
- **ZK:** optional ability to prove a specific predicate without revealing witness fields; not a replacement for authenticated accepted state.
- **Published commitment:** a hash of an evidence package placed in any external storage or settlement system; it proves publication only, never guilt.
- **Censorship:** authorized or network actor refuses to disseminate or accept a valid input/evidence.
- **Information minimization:** enemy-hidden world state is never transmitted to an unauthorized client's control in the first place.

## Deliberately not guaranteed

There is no cryptographic solution here to detect all aimbots, guarantee genuine human gameplay, recover permanently lost witnesses, force an adversarial peer to honor a verdict without a settlement authority, reveal no information from public timing data, or guarantee a fully asynchronous fair multiplayer consensus. A privately proven legal move may still be strategically unfair if secret information was leaked. Honest-looking signed input history can still omit inputs never admitted into the canonical protocol.

## r3 signed event batching / independent 1v1 evidence

**Signed packed control stream (`GVEC`)**: authenticated event-driven digital control record. **Aggregate (`GVAG`)**: canonically ordered collection of player-signed streams, possibly across games. **Chunk envelope (`GVKC`)**: a medium-agnostic piece of an authenticated aggregate sized to any caller-supplied limit. **One-witness fraud**: objectively invalid accepted transition established by one reproducible witness, unrelated to input-admission quorum.
