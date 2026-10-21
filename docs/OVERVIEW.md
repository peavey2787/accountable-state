# Overview / orientation

Read [00-overview.md](00-overview.md) for the architectural overview and [SPEC.md](SPEC.md) for the complete implementation contract. All detailed specifications, threat models, and acceptance procedures live under `docs/`; no game engine or blockchain is a mandatory dependency.

The standard path is **sign canonical input → append to committed transcript → replicate evidence → certify provisional checkpoint → challenge/independently replay if needed → finalize after agreed deadline**. Evidence is exported as self-verifying, chain-agnostic packages ([38](38-EVIDENCE-EXPORT.md)); publishing one anywhere is optional and never replaces verifying it. Optional ZK is invoked only when publicly replaying authenticated witnesses would reveal prohibited secrets.

The architectural invariant: execute gameplay immediately at the edge, exchange inputs continuously, verify and audit asynchronously, let any participant produce independently verifiable evidence, and preserve provable innocence without interrupting gameplay.

For current status see [41](41-FORMAL-MODEL.md) and [42](42-REMAINING-GAPS.md). For size accounting and optional chunking of signed input streams see [22](22-INPUT-PACKING-AND-DECENTRALIZED-1V1.md).
