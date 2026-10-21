# Challenges, evidence, witnesses, privacy

## Challenge / response

A challenge is a signed request, bound to match, challenger, target, a fresh nonce and a
deadline in logical ticks. Kinds: `MissingBatch`, `Ack`, `LogSegment`, `MerkleWitness`,
`HiddenReveal`, `Replay`. A response is signed by the target and bound to the challenge id.

Lifecycle (`audit/challenge.rs`): `PENDING` -> answered validly -> `CLEARED`; or the deadline
passes -> up to 3 retransmissions -> `SUSPECTED_NONCOOPERATION` -> slow retries ->
`UNAVAILABLE`. A wrong or off-topic answer is `INCONCLUSIVE`. A valid answer after any of
these always returns to `CLEARED`. **No timeout path ever produces `PROVEN_*`.**

Abuse limits: 8 open challenges per target, 64 in total, a per-peer flood gate, a seen-nonce
window of 4096 for replay rejection, 1 MiB per response. Rejections are counted and dropped
without a verdict (`Reject::{BadSignature, WrongMatch, NotForMe, BadDeadline, Replay, Flood,
Unknown, WrongResponder}`).

## Evidence

Four self-contained kinds ([34](34-WIRE-FORMATS.md)). `Evidence::verify` re-checks every
signature and the violation predicate; nothing is trusted from the sender.

* **Conflicting authenticators** - same owner, match, ruleset and seq, different head.
* **Fork** - an earlier head, a later head, and a segment that starts at the earlier seq,
  chains to the later head, yet whose starting `prev_head` differs from the earlier head.
  An honest extension never satisfies this.
* **Conflicting batches** - overlapping ticks where the held state actually differs. A shorter
  re-signed prefix is legitimate and is *not* equivocation.
* **Conflicting checkpoints** - same slot and predecessor, different claim.

Replay accusations (`Ledger::submit_replay`) are decided by running the ruleset from a trusted
predecessor: invalid state or illegal signed input = `PROVEN_FRAUD`; a valid claim or a wrong
premise = `INCONCLUSIVE` and records nothing. A dual-signed certified epoch matching the
accused claim is a **counterproof** (`Ledger::counterproof`): it exonerates the accusation
id for good, so accusation and defence cannot ping-pong.

Framing resistance: signatures are verified when messages are decoded, and a statement is
only ever paired with one signed by the same key, so an attacker cannot splice a victim's
signature onto a conflicting claim. The demo `--accuse-falsely-at` attempts exactly this and
ends with nothing proven against the victim.

Ids are canonical (order independent) so the same proof found by two peers is one record.
The ledger keeps at most 1024 entries and 64 per accused.

## Propagation and witnesses

The detector announces newly proven evidence once; a receiver verifies it independently,
records it and does **not** re-announce, so there is no gossip storm. `missing_ids`
implements anti-entropy over inventories (at most 64 ids per round) and
`assign_witnesses(match, roster, exclude, k)` picks witnesses deterministically by
`H(match ‖ member)`, never the audited pair.

Witnesses are untrusted: they can only store and relay objects that verify on their own. A
witness that signs two histories is itself provably an equivocator
(`witness_equivocation_is_proven_against_the_witness_only`). The two-player demo has no third
party, so witness assignment and anti-entropy are library primitives exercised by tests
(`evidence_propagates_to_every_peer_by_anti_entropy`), not something the 1v1 demo runs.
Publishing evidence ids to an external system is optional and not required by any check.

## Privacy

Logs and authenticators contain hashes, never raw inputs: batch entries store the batch
digest, checkpoint entries the claim digest. Evidence contains only data the accused already
signed. Hidden positions stay out of the observer's memory and the wire until the opening
reveals the blinded batch; the blind is fresh randomness, so commitments to low-entropy
batches cannot be brute-forced. Evidence files are written locally as
`<artifact>.violation-N-<kind>.bin` and `<artifact>.evidence-ledger`; exporting them discloses
only the signed statements they contain.
