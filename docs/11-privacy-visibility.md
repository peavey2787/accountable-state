# 11 — Information flow, fair hidden information, and commit/reveal

## Prevent wallhacks through information minimization

The game must not send every player's world state to every game client and hope that a replay catches wallhacks afterward. If Alice receives Bob's hidden coordinates, Alice can read them from her own process regardless of kernel anti-cheat. A subsequent legal move can have been influenced by that leak and remains replay-valid. **The prevention is to withhold unauthorized data upstream**, not to obfuscate it after delivery.

## Information-flow labels (production target)

| Classification | Intended recipients | Reveal after match? | Typical field |
|---|---|---|---|
| Public | All authorized peers/spectators | Already visible | Score, terrain surface, public combat effects |
| Owned secret | Owner and trusted referee only | Per policy | Private inventory, card hand |
| Opponent-hidden | Authorized referee/visibility verifier | Often no | Fog-of-war enemy coordinates |
| Team-only | Current team members and referee | Game-specific | Team strategy position |
| Reveal-later | Encrypted custodians then agreed parties | Yes, explicit deadline | Commit-before-choice input |
| Never-reveal | Authorized trusted computation or ZK witness only | No | Private strategy, long-term seeds, some unrevealed cards |

Every packet and storage retrieval method must enforce disclosure based on `(observer_id, observer_role, match, tick, game policy)` before returning plaintext or decryptable ciphertext. Commitments, hashes and small-domain plaintext may leak via dictionary attacks if insufficiently blinded.

## Real-time spatial games

- Interest management and authoritative visibility decisions are computed outside opponents' machines. Transmit only visible actors, public effects or policy-approved low-resolution/lagged data.
- A referee may need full state for hit validation or collisions; if no trusted referee exists, a pinned ZK computation or distributed private computation may be necessary, with performance and trusted setup tradeoffs.
- A client must not derive hidden enemy position from precise sound/event timestamps, deterministic particle effects, network ordering, bounding boxes, object IDs, fine-grained interest updates, or the existence of encrypted packets. Design side-channel mitigations, including padding, batching and delayed metadata when needed.
- Client prediction and interpolation operate only on authorized view. Don't accidentally send private state in physics/debug channels, telemetry, spectators, minimaps, replay thumbnails, or crash logs.

## Commit/reveal protocol

1. Before opponent choice becomes observable, player samples a 32-byte unpredictable nonce and commits to `domain || match || round || player || choice || nonce` using a versioned hash formula.
2. Authorized participants/validators acknowledge committed root and deadline, preserving order. Cannot reveal a different choice without changing commitment (collision resistance assumed).
3. After all required commitments lock, players reveal exact canonical choices and nonces to designated verifiers. Verifiers check commitments, decision ordering, admissibility, and deterministic round outcomes.
4. Missing reveal runs fixed protocol fault/forfeit policy, NOT an assertion that a physically illegal move was executed.
5. If the match rules allow post-match publication, selectively release minimal reveal material. For permanently hidden strategy, use ZK or a trusted referee; don't force disclosure.

For randomness derived from multiple player seeds, avoid last-revealer manipulation. Commit with strict timeout, combine only authorized participant contributions per a predeclared algorithm, use an independently unpredictable beacon where appropriate, and predetermine what happens when someone withholds their reveal. VRF alone does not guarantee unbiased output if the source can choose whether/when to publish it.

## Encrypted custody

Use an audited authenticated cipher (e.g., XChaCha20-Poly1305) with separate keys per match/purpose/recipient, explicit AAD `(match, epoch, tick, record type, recipient, commitment root)`, unique nonces, sequence/replay protection, forward-secure key agreement when required, and bounded ciphertext. Never invent encryption. Custodians can verify ciphertext hash and receipt even if they cannot read plaintext; *plaintext availability* also requires eligible parties' key material at challenge time.

## Privacy-preserving fraud evidence

Minimize the witness to the challenged step and relevant dependencies. Redact unrelated player data only if the verifier relation remains complete and auditable. Use a ZK proof for sensitive fields that must remain secret forever; a public full replay of those fields would violate the game's privacy contract. Third-party observers get `public claim + pinned proof`, or authorized referees review private evidence and publish a **labelled trusted attestation**, never interchangeable with a mathematical proof.

## Privacy lifecycle

Define disclosure deadlines, key rotation, player opt-out where permissible, retention after appeals, immutable public chain metadata, and whether evidence could identify players via match participation. A public on-chain hash is not plaintext but still a permanent correlation point. Avoid publishing personal identifiers, IP addresses, chat logs, or full hidden-game state as fraud evidence.

## r3 signed event batching / independent 1v1 evidence

Packing does **not** preserve secrecy: publishing signed raw digital inputs to any public store exposes strategy/aim/timing indefinitely. Only publish full batches after the game authorizes reveal; otherwise retain encrypted off-chain custody, selective openings, hidden state visibility filtering and optionally ZK. See [r3 confidentiality notes](22-INPUT-PACKING-AND-DECENTRALIZED-1V1.md).
