# Formal model (TLA+ / TLC)

`spec/Accountability.tla`, run by `scripts/model-check.sh` (TLC; `--negative` for the
expected-failure configs). Results are bounded model checking only; **nothing here is an
unbounded proof.**

## Results actually obtained
| Config | Participants | Result |
|---|---|---|
| n2 | 2 | PASS, 3,634,806 distinct states |
| n3 | 3 players + 1 witness | PASS, 68,550,454 generated / 1,815,099 distinct, 0 left on queue |
| n2_live | 2 players + 2 witnesses, spec `Fair` | PASS, 43,503,010 generated / 1,155,063 distinct, 0 left; includes `EquivocationConverges` |
| neg_nopin, neg_nowal | negative | fail as expected (violate `NoSelfEquivocation`) |
| n5_exploratory | 3 players + 2 witnesses | **did not complete**: 12.49M distinct states, 4.15M queued at a 2400 s cap, no violation seen; not a result |

## Properties checked
Invariants: TypeOK, NoVerdictAgainstCorrect, EveryProofIsEvidence, TimeoutIsNotProof,
NoConflictingAccepted, InvalidNeverProves, NoSelfEquivocation. Action properties:
AnsweredStaysAnswered, ChallengeOpenedOnce. Liveness: EquivocationConverges.

Model: one contested slot per signer, statements with values 1..3, Byzantine signers and
witnesses, lossy relay, crash/recover, one challenge id. Validity reads signatures only, so
witness votes cannot affect it.

## Liveness assumptions
Weak fairness of Relay and Derive: messages between correct nodes are eventually delivered.

## Implementation correspondence
`NoSelfEquivocation` holds only with both PinCheck and PinsWriteAhead (the negative configs show
the failure without either). The implementation provides both: anchored recovery checks pins
([39](39-ANCHORED-RECOVERY.md)), and nothing signed leaves the process before the write-ahead
store has committed it (`Auditor::make_durable`, exercised at every kill boundary by
`live/writeahead_tests.rs`). This holds only when a `TrustStore` is attached.

## Separation of claims
* Cryptographic assumptions (ML-DSA-65 unforgeability, SHA-256): assumed, not modeled.
* Model-checked: the table above, within its bounds.
* Executable tests: cargo tests, filesystem crash tests, real-process witness runs.
* Unverified deployment assumptions: real WAN, clocks, host integrity.
