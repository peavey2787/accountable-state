# Accountability: threat model, guarantees, limits

This layer follows the *PeerReview* idea (tamper-evident logs, signed authenticators,
challenge/response, transferable evidence) without Byzantine agreement. Players keep playing
in real time; accountability runs beside the game and never blocks it.

## Threat model

* Two players, each holding an ML-DSA-65 key; the roster is fixed by a trusted invitation.
  Optional untrusted witnesses may relay and store evidence.
* A participant may be arbitrarily malicious: send invalid inputs, sign a false checkpoint,
  sign two histories (equivocate), withhold data or answers, lie in an accusation, flood, or
  replay old messages. The network may delay, drop, duplicate and reorder.
* Not defended: breaking ML-DSA-65/SHA-2, a compromised signing key, a malicious *both*
  players (nobody left to accuse), an opponent that simply stops playing (indistinguishable
  from a crash; only SUSPECTED), side channels, and traffic analysis beyond what Hydra gives.

## Assumptions

1. ML-DSA-65 is existentially unforgeable and SHA-256/SHA-512 are collision resistant.
2. Keys and the roster were exchanged over an authentic channel before the match.
3. The ruleset code is deterministic and identical on every verifier.
4. A correct node's clock is only used to set *local* deadlines; no verdict depends on
   synchrony. Timeouts produce suspicion, never proof.
5. At least one correct, connected observer exists to hold the evidence. (For 1v1 this is the
   opponent; a witness only adds redundancy.)

## Statuses

| Status | Meaning | Is a cheating verdict? |
|---|---|---|
| `PROVEN_FRAUD` | signed false state or illegal signed input, shown by replay | yes |
| `PROVEN_EQUIVOCATION` | two validly signed contradictory statements | yes |
| `CLEARED` | a valid answer or counterproof arrived (even late) | no, exoneration |
| `SUSPECTED_NONCOOPERATION` | challenge unanswered past its deadline | **no** |
| `UNAVAILABLE` | still unanswered after slow retries | **no** |
| `INCONCLUSIVE` | evidence could not be decided (e.g. wrong premise) | **no** |
| `PENDING` | challenge open | no |

The red *Cheat / invalid move detected* indicator is driven only by the two proven statuses.

## Accuracy and completeness

* **Accuracy.** A correct participant is never given a proven status by any verifier that
  runs the code in this repo. Evidence is self-contained: it carries the signatures and the
  premise it depends on, so a verifier needs to trust nothing but the roster and ruleset.
* **Completeness (bounded).** If a participant signs an invalid input, a false checkpoint, two
  conflicting heads, or conflicting batches/checkpoints, and a correct node sees both sides,
  that node can produce proof. If a participant merely withholds, the best outcome is
  `SUSPECTED`/`UNAVAILABLE`; this is deliberate, not a gap.

## The 12 properties

Label key: **proven** = follows from the construction and an argument given here (assumption 1);
**tested** = covered by automated tests in this repo; **specified** = documented behaviour
without a dedicated test. "proven" means an argument, not a mechanised proof. Separately, a bounded TLC model
checks the protocol-level safety properties for small configurations; see
[41](41-FORMAL-MODEL.md) for exactly what was and was not checked.

| # | Property | Label | Where |
|---|---|---|---|
| 1 | Authenticity: every signed message verifies under a registered roster key, domain, version and signer | proven + tested | `gv-sig` tests, committed vector |
| 2 | Domain separation: a signature never validates under another label, signer or body | proven + tested | `gv-sig`, `committed_vector.rs` |
| 3 | Log tamper-evidence: changing, dropping or reordering an entry changes every later head | proven + tested | `log_chain_authenticators_and_segments` |
| 4 | Equivocation detection: two signed heads at one seq, or a fork shown by a segment, are proof | proven + tested | `conflicting_authenticators_and_forks_are_proven` |
| 5 | No framing: no evidence verifies against a node that did not sign both conflicting statements; a false premise yields INCONCLUSIVE | proven + tested | `conflicting_checkpoints_and_framing_resistance`, `a_false_accusation_and_forged_evidence_prove_nothing` |
| 6 | Timeouts are never proof | proven + tested | `challenge_timeout_is_suspicion_never_proof_and_late_answer_clears`, `withholding_is_only_suspicion_and_a_late_answer_clears_it` |
| 7 | A late valid answer clears suspicion | tested | same |
| 8 | Provable innocence: a dual-signed certified epoch is a counterproof and is final (no ping-pong) | tested | ledger `counterproof`, headless demo |
| 9 | Canonical, deduplicating evidence ids (order independent) | proven + tested | `ledger_dedupes_orders_and_bounds` |
| 10 | Offline verifiability: evidence verifies with only the roster and ruleset | tested | headless script verifies six files offline |
| 11 | Bounded resources: evidence 1 MiB, ledger 1024 / 64 per accused, 64 open challenges / 8 per target, flood limits, segment 4096 entries, store 256 MiB | tested | `challenges_are_bounded_and_flood_limited`, `audit_traffic_is_bounded_and_flooding_is_dropped`, oversize test |
| 12 | Gameplay never waits: the sim, input and rollback paths do not block on finality, audit traffic or signing | specified + benchmarked | [37](37-OPERATIONS-AND-PERFORMANCE.md) |

Also tested: crash/restart recovery (`record_file_recovers_from_torn_and_corrupt_tails`,
`auditor_restart_restores_log_and_reverifies_persisted_evidence`,
`long_session_prune_crash_restart_and_still_proves_fork`), multi-peer propagation by
anti-entropy (`evidence_propagates_to_every_peer_by_anti_entropy`), witness equivocation
(`witness_equivocation_is_proven_against_the_witness_only`), lossy/partitioned networks
(`a_lossy_reordering_network_never_produces_a_cheating_verdict`,
`partition_then_heal_ends_cleared_not_accused`) and real native two-process matches
(`scripts/smoke-arena-linux.sh`, `scripts/headless-arena-linux.sh`).

## Limits

* Detection needs an honest observer to have seen at least one of the two conflicting
  statements and be able to obtain the other (directly or from a witness).
* A partitioned player cannot be proven anything; the system reports suspicion, then heals.
* The audit of the opponent's chain is sampled (every 10th authenticator) to bound CPU;
  evidence of an older fork stays valid indefinitely as long as the signed heads are kept.
* Pruning keeps the newest 8192 log entries; forks older than that are provable only if the
  earlier authenticator and a segment from a peer that kept it are available.
* Hide-window reveal timing is a local deadline; the certified chain stalls on a withheld
  reveal while play continues.
* ML-DSA signatures cost 3309 B each: about 250 kbps per direction for the full signed
  stream at 3 epochs/s ([37](37-OPERATIONS-AND-PERFORMANCE.md)).
