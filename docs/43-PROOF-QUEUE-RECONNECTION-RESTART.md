# Proof queue, reconnection and restart safety

## Durable proof queue (`gv-proof-queue`)
Evidence verification runs off the gameplay path. Jobs are journal-first: a state change is
durable before it is acted on, so a crash replays to the same state. Verifier families:
signed inputs, commitments, recovery certificates, equivocation, transitions. Overload sheds
`Low` priority first; `High` (evidence that can convict or clear) is only refused at the hard
capacity. A timeout is `Expired`, never certification. Backends: `FileJournal` (native),
`MemJournal` (tests), `OutboxJournal` (WASM: the host persists the blobs it takes, a full outbox
makes the queue refuse work). The browser binding is `adapters/wasm` (`ProofQueue`), validated
with `wasm-pack test --node` in both `run-all` scripts.

## Individual-peer reconnection
`PipeMsg` resume (tag 15) with incarnation fencing. Peer events: `Down`, `Resumed`,
`Superseded`, `CaughtUp`, `GraceExpired`. A single peer dropping does not abort the session.
`tests/tcp_processes.rs` runs real OS processes over TCP, including kill and restart.

## Restart safety
A node persists a signing watermark (`.signed-through`) before releasing any batch and resumes
at `max(replica tick, watermark)`, so a restart never signs a second, different batch for a
window it already signed. Equivocation is judged on the signed record: ML-DSA signatures are
randomized, so the signature-inclusive digest of two honest signings differs and must not be
compared.

The pipeline also enforces the floor in memory (`Pipeline::forbid_signing_below`, seeded from the
watermark), starts the close timer from the local clock rather than from a tick number (a
restarted node would otherwise close its epoch alone at once), and drops batches that start
before the window once an epoch finishes, so a late longer batch is never compared with the next
window's batch and misread as equivocation.

## Known limitation: close race
If one node completes an epoch naturally while a coordinator closes the same window over a
smaller batch set, honest nodes on different local clocks can fork that epoch. Safety holds
(nothing finalizes without agreement and nobody is convicted), but the epoch stalls until
resync or restart. Rolling back is unsafe because it would double-sign checkpoints.

## Gates not run in this environment
Miri and ThreadSanitizer require a nightly toolchain; real WAN testing requires geographically
separated hosts. Both are tracked as blocked, not passed.
