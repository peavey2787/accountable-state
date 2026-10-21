# 16 — Operations, trusted policy, reputation and penalties

## Match governance is explicit

A mathematically valid fraud relation can be verified by anyone, but consequences are a separate game-specific rule. At match genesis publish: game/ruleset ID; allowed players and validator roster; evidence types; requirements for conviction; reveal and challenge deadlines; admission/custody fees; refund rules; permitted penalties; finality and appeals; retention; and which external registries/chain are authoritative for stakes.

## Decision outcomes

- **Confirmed semantic invalidity:** independent execution or pinned ZK proves an accepted claim invalid. Apply precommitted rollback, invalidation or financial settlement according to policy. Attribution to a particular player still requires that player authorized the false state claim; a dishonest validator might instead have forged the accepted result.
- **Confirmed equivocation:** same key produced conflicting exclusive signed claims. Punish the accountable key/validator as defined, not an unrelated participant.
- **Failure to reveal/custody:** record noncompliance and apply precommitted timeout/forfeit, with network-delay and recovery exceptions.
- **Unresolved:** freeze provisional awards or refund according to match rules; do not synthesize a conviction.
- **Refuted accusation:** reject challenge, potentially penalize provably malicious spam while preserving honest reporting incentives.

## Appeals

Appeal policy must be finite and unambiguous: filing window, scope (e.g., alleged witness corruption or incorrect verifier build), independent reviewers, evidentiary standard, maximum extensions, and which original verdict remains visible. Changes to verifier rules do not retroactively reinterpret older transcripts. High-stakes irreversible settlement should wait until appeal policy closes.

## Filters / reputation

Games may consume an externally published or P2P-published verification feed and choose filters: ignore, warn, hide match with unavailability, restrict verified equivocation, reject verified semantic-fraud actors, or route to manual appeal. Do not treat a self-signed claim, transaction hash, trust-list entry, or unverified ZK receipt as objective cheating. Include explicit `verification_class`, `accused_actor`, `accepted_claim_author`, `rule_id`, `ruleset_hash`, `proof_digest`, `match_id`, `witness_location`, `finality`, and `revocation/appeal status` in each feed entry.

## On-chain finances

For prize pools and slashing, only a covenant-reproducible proof predicate or carefully scoped trusted referee policy should authorize irreversible spend. A default-on bond or payment mechanism is inappropriate for games with no financial stakes. Never automatically publish full hidden-state witness or PII to a permanent blockchain; hash and bounded proof/public statement are preferred.

## Operational incident response

If a majority of validators colludes, signatures compromise, published verifier is found wrong, chain reorg exceeds budget, or state availability collapses: stop finalizing/paying, preserve all signed evidence, publish a security incident ID, rebuild from last unquestionably trusted checkpoint, and coordinate an announced manifest/version transition. 'Continue with whichever peer responds first' is not a safe fault recovery algorithm.

## r3 signed event batching / independent 1v1 evidence

Apps MUST distinguish `PROVEN_RULE_VIOLATION` from `NOT_PROVEN`, `UNAVAILABLE` and chain hash-anchored allegations. Endless reciprocal complaints cannot hold finality open by themselves: each proof is deterministic, bounded, deduplicated and scoped to a publicly committed appeal window. 1v1 where opponent refuses to finalize needs a precommitted neutral settlement or timeout policy. See [r3](22-INPUT-PACKING-AND-DECENTRALIZED-1V1.md).
