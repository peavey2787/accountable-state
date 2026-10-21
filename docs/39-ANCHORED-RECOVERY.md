# 39 — Trusted crash recovery and rollback protection

A log that is self-consistent proves nothing: whoever can write the snapshot can hand back an older or forked but perfectly chained log, and a restarted process would then sign a *different* history under the same sequence numbers, which is equivocation by the honest player. Recovery is therefore **anchored** to signed heads that were authenticated before the crash and are held outside the snapshot.

Code: `crates/edge/src/audit/{trust,durable}.rs`, `live/auditor.rs`; tests `live/recovery_tests.rs` (13 real-filesystem tests).

## Anchors

* **Local pins** (`GV-TRUST-PINS/V1`): the highest few signed `Authenticator`s per owner (at most `MAX_PINS` = 64 in total), for this participant and its opponents. Every pin is signature-verified when added. Two pins by one owner at one sequence with different heads are an equivocation and are reported as such.
* **Peer and witness copies**: the opponent and every witness hold this participant's signed heads. `Auditor::supply_anchor` accepts a head from them after verifying it.
* Pins are saved after each pipeline event in which they changed; the log and open challenges are saved every 5 s.

## Atomic, durable persistence

`write_state` writes a temp file, `fsync`s it, renames it over the target and `fsync`s the directory, so a crash leaves the complete old file or the complete new file. Every file is framed `GV-STATE/V1\0 || length || payload || checksum` (domain-separated SHA-256). `read_state` returns `Missing`, `Corrupt` (torn, truncated, oversized, bit-rotted) or `Ok`; a corrupt file is **never** trusted and never repaired in place. A checksum only detects accident. Against a malicious writer the protection is the anchor check below, not the checksum.

## Recovery outcomes (`check_log` -> `Recovery`)

| Outcome | When | May sign? |
|---|---|---|
| `Fresh` | no log and no pin for this participant | yes |
| `Resumed { len, anchored_at }` | the log contains every pinned head at its pinned position | yes |
| `Unresolved(NoAnchor)` | a log exists but nothing anchors it | **no** |
| `Unresolved(LogLost)` | pins exist but the log is gone or corrupt | **no** |
| `Unresolved(AnchorPruned)` | the only anchors are older than the retained log base | **no** |
| `Refused(Rollback)` | a pinned sequence is beyond the end of the log | **no** |
| `Refused(Fork)` | the log has a different head at a pinned sequence | **no** |
| `Refused(WrongOwnerOrMatch)` | the log belongs to another key or match | **no** |

`Unresolved` is not an accusation: a participant that lost its log with no anchor looks the same as one that never had a log. It suspends signing until `supply_anchor` delivers an authenticated head from a peer or witness, after which the log is re-checked. A forged, foreign or other-match anchor is ignored, never trusted. **Lost evidence is not proof of cheating**; only verified contradictory signatures are.

## Open challenges and pending evidence

`Auditor::restore` reloads the challenge book and `resume_challenges` re-arms each open challenge with its original id, so a restart does not reset or duplicate a challenge and does not turn a timeout into a verdict. A challenge that expires while the process is down ends at `SUSPECTED_NONCOOPERATION`, never `PROVEN_FRAUD`. Witnesses re-verify every persisted evidence record on start (nothing is trusted from disk); a record that no longer verifies is dropped.

## Safe pruning

`AuditLog::prune_to_keep(keep)` never drops entries at or after the lowest *pinned sequence* of the log (open challenges and held anchors pin the sequences they depend on). A request for a pruned range gets **no** answer (never a fabricated one), so the challenger ends at `SUSPECTED`/`UNAVAILABLE` rather than at a proof. `pruning_never_drops_entries_an_open_challenge_depends_on` and `anchor_older_than_a_pruned_log_base_is_unresolved` cover the two edges.

## Authenticating history after reconnect

After a reconnect a verifier asks for the log between a head it already trusts and the newest signed head (a `ChallengeKind::LogSegment { from, to }` challenge, issued by players' auditors and by witnesses). The answering segment must chain, entry by entry, to a head signed by the owner; anything else is dropped as unauthenticated. Witnesses that missed evidence retrieve it with the inventory/want exchange ([40](40-WITNESS-NETWORK.md)).

## Test matrix (all against the real filesystem)

Truncation at **every** length and bit rot, interrupted writes (the old state survives), corrupt snapshot, corrupt pins, a valid-framing snapshot with one substituted entry, rollback to a shorter self-consistent log, forked log of sufficient length, retained-head substitution, forged anchors, lost log with anchors, pruned anchors, pins surviving restart (a later fork by a pinned opponent is detected), an open challenge across a restart, and pruning that preserves challenge dependencies.

## Honest gap

The formal model ([41](41-FORMAL-MODEL.md)) shows `NoSelfEquivocation` holds only if recovery does the pin check **and** the pin is durable *before* the statement is released (`PinsWriteAhead`). The implementation enforces both: `Pipeline::poll_outbox` and `Auditor::poll_witness_response` release nothing until `Auditor::make_durable` has committed the log and every own signed head to the write-ahead `TrustStore`, a failing store withholds all signed output (fail closed), and the auditor's raw outbox is crate-private so a host cannot bypass the barrier. `live/writeahead_tests.rs` kills the participant at every persistence-to-send boundary and checks that a restart never contradicts a head it already sent. A pipeline with no store attached has no durability and therefore no `NoSelfEquivocation` across crashes; hosts must attach one (`examples/edge-p2p` does, and fails closed when it cannot).
