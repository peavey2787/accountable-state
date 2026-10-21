# 10 — Fraud proofs, challenges, disputes, and verdicts

## Fundamental rule

**No accused player may be labelled a proven cheater merely because a third party posts a signature, a hash, a Merkle path, an anchor transaction, or an unverified verdict.** A proof must establish the falsity of a *previously accepted specific claim* under the *pinned official rules*, while binding accepted identity/sequence/chain state. Honest inability to reveal is categorized separately.

## Canonical challenge classes

| Class | Evidence | Cryptographic adjudication |
|---|---|---|
| `INVALID_TRANSITION` | Authoritative accepted checkpoint, accepted input batch, state openings and replay witness; or pinned ZK proof | Independent canonical verifier demonstrates `F(S,I) != claimed_S'`, or deterministic prohibited action under precise accepted rules |
| `EQUIVOCATION` | Two distinct signed exclusive votes/inputs/proposals for same authorized signer/slot | Verify both signatures/contexts, distinct conflicting commitments and exclusivity rule |
| `INVALID_AUTHORIZATION` | Accepted state depends on unauthorized key/action and canonical permissions | Check authenticated roster, signature, authority policy, state trace |
| `INVALID_RANDOMNESS` | Committed randomness protocol transcript and revealed VRF/seed evidence | Independently verify randomness and its mandated use in replay |
| `WITHHELD_REVEAL` | Signed obligation/acceptance, canonical deadline/receipt and absence under authenticated timeout policy | Policy-based forfeit or invalid match; **not physics cheating** |
| `UNAVAILABLE_DATA` | Signed custody and retrieval attempts | Unavailability/failure classification, may suspend settlement |
| `CONFLICTING_FINALITY` | Two certified mutually exclusive checkpoint histories | BFT safety incident; stop settlement, forensic audit |

## Proof object — production target

```text
FraudProofV1 {
  version, match_id, protocol_hash, ruleset_hash, game_verifier_id,
  proof_type, accused_identity, challenged_checkpoint_id,
  accepted_checkpoint_cert_chain_or_trusted_ref,
  trusted_validator_epoch_and_membership_ref,
  authenticated_signed_input_records_or_batch_root,
  player_signed_state_output_claim_or_validator_responsibility_binding,
  merkle_membership_and_consistency_paths,
  previous_state_commitment_and_opening_or_zk_witness,
  claimed_state_commitment_and_opening_or_zk_witness,
  minimal_dependent_world_state_and_rng_witness,
  claimed_rule_violation_code,
  expected_result_digest,
  content_digest_and_evidence_retrieval_locations,
  optional_pinned_zk_receipt,
}
```

A proof may be compressed but MUST still bind the complete proposition that a third party independently verifies. Mere `violation_type: "speed"` without accepted authenticated inputs and replay cannot suffice. `evidence_hash` without witness availability is an allegation pointer, not proof.

## Submit/verify lifecycle

1. **Observe:** participant or watcher selects a certified provisional checkpoint; obtains signed/custodied bytes from independent storage.
2. **Preflight:** check match, epoch, accused identity, ruleset hash, accepted checkpoint, canonical size and challenge deadline. Reject stale, unknown, malformed, duplicate or unauthenticated claims without heavy replay.
3. **Prepare evidence:** find earliest challenged invalid tick, include only necessary state/input openings, signed inclusion paths and side-effect/RNG/collision dependencies. Preserve evidence of how the checkpoint was accepted, not just proposed.
4. **Submit:** sign challenge envelope. Allocate a unique challenge ID and store immutable evidence; require optional refundable bond/rate cap. Publish to dispute committee and independent watchers, not just the accused.
5. **Reproduce:** independent verifiers re-hash the exact bytes, verify signatures, match/validator set, inclusion, ordering, predecessor and canonical rules. Execute deterministic replay or verify precisely pinned ZK proof; return typed error/fraud verdict.
6. **Respond:** accused may supply missing, authenticated clarifying evidence before a precommitted deadline. No unilateral extension; preserve each response. Invalid partial evidence cannot retroactively rewrite accepted history.
7. **Vote:** authorized dispute validators sign the **exact same** evidence digest and deterministic verdict code, with a domain-separated vote; collect quorum when policy uses a committee. The independent proof remains publicly checkable.
8. **Resolve:** if proven, reject/rollback *provisional* descendants and process preagreed penalties; if valid, reject challenge; if unavailable, invoke availability/forfeit policy; if evaluator divergence, halt/quarantine pending resolution.
9. **Finalize:** after terminal QC + challenge/appeal deadline, emit immutable `VerdictCertificate`. If on-chain settlement is enabled, post only the agreed bounded proof or a scoped attestation with proper semantics.
10. **Archive:** retain evidence, verifier identity, roster epoch, verdict code, and appeal trail; avoid leaking unrelated private data.

## Distinguish three validations

- **Evidence well-formed:** signature and Merkle path validate, committed state openings match, evidence size is bounded. This doesn't prove a violation.
- **Demonstrated rule violation:** independently replayed accepted input conflicts with claimed accepted output. This proves a deterministic inconsistency under the pinned game.
- **Agreed punishment:** actual validator/governance policy chooses disqualification, rating update, forfeiture or stake slashing; a valid fraud proof cannot force all decentralized apps to adopt one social policy.

## Special care for missing state / negative claims

An invalid transition may require a complete world snapshot (including map collision, buffs, enemy interference). A challenger cannot simply omit inconvenient valid inputs and get a 'fraud' result. Sound verification MUST authenticate the complete relevant input batch and predecessor state. In resource-heavy games, a ZK proof of rule violation or an interactive fraud game can minimize on-network evidence, but the contract must pin the exact verifier/circuit and accepted commitments. If the verifier cannot reproduce outcome, the only safe verdict is `Inconclusive`.

## Prototype implementation

`gv_edge::fraud_bundle` (`GV-FRAUD-BUNDLE/V1`) verifies a self-contained single-step fraud package against a trusted match invitation: authenticated certified history, a signed input, both state openings and a separately player-signed state-output claim, plus a `StateMachine::apply` result. It returns a proven-invalid-transition result for a mismatch. The caller MUST separately trust the match invitation and ruleset. The signed state claim is verified against the player identity, so an attributable false output is distinguishable from a false checkpoint by someone else. The result must not directly trigger financial punishment or bans without a game-defined policy.

## Explicit protection against malicious accusations

Anyone may submit a candidate, but a public fraud registry MUST separate `verified_onchain_zk`, `verified_offchain_replay`, `quorum_attested`, `alleged`, `unavailable`, and `refuted`; the same word *proven* must not span these classes. Apps should default to using only independently verifiable scoped outcomes; no blanket accusations or unverifiable player-level labels.

## r3 signed event batching / independent 1v1 evidence

No adversarial majority can vote to validate a mathematically false accepted transition: one complete authenticated and reproducible witness establishes the invalidity for all honest verifiers. Counterclaims are resolved by deterministic verification of the same pinned evidence and rules; do not allow unlimited duplicate counterclaims to block finality indefinitely. Attribution needs the accused party’s *signed output/state claim*, not merely their input signature. See [r3 1v1](22-INPUT-PACKING-AND-DECENTRALIZED-1V1.md).
