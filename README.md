# accountable-state

**An SDK for accountable two-party state machines.** Two participants run the same
deterministic `StateMachine`; every action is signed (ML-DSA-65), replayed by both sides,
committed to a Merkle log and co-certified. Misbehaviour leaves portable evidence
(`GV-EVIDENCE-PACKAGE/V1`) that anyone can verify offline. No server, referee, blockchain or
majority vote is involved.

> **Status: experimental, not externally audited.** What is executed, model-checked, assumed
> and still open is kept apart in [docs/41](docs/41-FORMAL-MODEL.md) and
> [docs/42](docs/42-REMAINING-GAPS.md).

The first application is [anti-cheat](https://github.com/peavey2787/anti-cheat), a real-time
1v1 arena built only on this SDK.

## The API

One trait and six ordinary operations (crate `accountable-state`):

| | |
|---|---|
| `StateMachine` | `ruleset_hash`, `genesis`, `apply(state, input) -> Result<state, RuleError>`, `ordering(action)` |
| `AccountableState::open(machine, Config)` | identity, rules, **durable** storage and crash recovery; fails closed |
| `submit(action)` | a local action for authenticated execution and propagation |
| `state()` | certified state, its checkpoint and the anchor-check status |
| `subscribe(cursor, limit)` | signed, numbered, durable events; resumable across restarts |
| `export(query)` | match archive, fraud witness or audit record, as one package format |
| `Verifier::verify_package(bytes, &machine)` | `Valid`, `ProvenViolation` or `Inconclusive`, without a node |

Two advanced operations move protocol bytes: `receive(peer, bytes)` and `poll(now)`. The
node is sans-IO; the application owns sockets and timers.

`RuleError::InvalidAction(ViolationCode)` is fraud evidence; `RuleError::ExecutionFailure`
never is. An action whose outcome needs a global order
(`ActionOrdering::RequiresExternalOrdering`, e.g. a conflicting transfer) is refused: the
absence of a fraud proof never makes it final.

## Strict defaults

* **Durable storage is mandatory.** Everything signed is journalled before it leaves the
  process ([docs/39](docs/39-ANCHORED-RECOVERY.md)); in-memory mode exists only for tests.
* **Recovery is anchored.** After a restart nothing is signed until the opponent (and, if
  witnesses are pinned, a witness or a bounded wait) has answered with the newest head of ours
  it holds. The trust boundary and its residual risk are in
  [docs/39](docs/39-ANCHORED-RECOVERY.md#trust-boundary).
* **Three separate streams:** the lossy 60 Hz input stream (`realtime`), the reliable signed
  pipeline (`Peer::Opponent`) and the witness channel (`Peer::Witness`, `GV-WITNESS/V1`).
* **ML-DSA-65 only, one evidence format, one event subscription.**

## Validation

```bash
./run-all-linux.sh
```

Windows: `run-all-windows.cmd`. Both run two stages and fail on any warning:

1. **Locked release validation** against the committed `Cargo.lock` (`--locked`): audit,
   format, clippy, tests, independent JS vectors. Reproducible.
2. **Newest-main compatibility** (`scripts/newest-main-compat.*`): the same build and tests
   against the newest `p2p-net` main. `Cargo.lock` is restored afterwards.

To move the release lock forward, run `cargo update -p p2p-net`, review the diff and commit it.

## Layout

| Path | Contents |
|---|---|
| `crates/accountable-state` | the facade: the API above |
| `crates/edge` | pipeline, replica, checkpoints, accountability (`audit`), export, feed, witness protocol |
| `crates/replay` | `StateMachine`, `RuleError`, pure transition verification |
| `crates/codec`, `crates/commitments`, `crates/transcript`, `crates/sig` | packed controls, SHA-256 Merkle logs, signed transcripts, ML-DSA-65 |
| `adapters/p2p` (feature `p2p`) | encrypted native transport over `p2p-net` and `hydra-msg` |
| `spec/` | TLA+ model of the accountability protocol ([docs/41](docs/41-FORMAL-MODEL.md)) |
| `crates/zk`, `crates/privacy`, `adapters/wasm` | partial skeletons, not working backends |

## Trust model

One authenticated, reproducible fraud witness is enough to prove a violation. A witness
cannot force an opponent to send, reveal or co-sign, so a malicious opponent can stall a
match; a timeout is suspicion, never proof. Publishing a package commitment proves
publication, not guilt ([docs/38](docs/38-EVIDENCE-EXPORT.md)).

## Licensing

SDK code is MIT. Binaries linking `gv-sig` (Hydra's ML-DSA, GPL-2.0-or-later) are
distributed under GPL-2.0-or-later ([docs/33](docs/33-HYDRA-MLDSA-INTEGRATION.md)). The
`p2p-net` source declares BUSL-1.1; a planned change to GPL-2.0 is not assumed.

## Documentation

[Specification index](docs/SPEC.md) ·
[Integration](docs/04-game-integration.md) ·
[Wire formats](docs/34-WIRE-FORMATS.md) ·
[Accountability](docs/35-ACCOUNTABILITY-GUARANTEES.md) ·
[Challenges and evidence](docs/36-CHALLENGES-WITNESSES-EVIDENCE.md) ·
[Evidence export](docs/38-EVIDENCE-EXPORT.md) ·
[Anchored recovery](docs/39-ANCHORED-RECOVERY.md) ·
[Witness network](docs/40-WITNESS-NETWORK.md) ·
[Remaining gaps](docs/42-REMAINING-GAPS.md)
