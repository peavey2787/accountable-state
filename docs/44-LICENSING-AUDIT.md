# Licensing audit (accountable-state)

Generated from `cargo deny list` and `cargo deny check advisories` on the committed lockfile.

Owner decision (applied): every repository is GPL-2.0-or-later. This workspace's `license` field and
`LICENSE` file now say so; `gv-sig` and `gv-wasm` already did.

| Component | Declared |
| --- | --- |
| all workspace crates | GPL-2.0-or-later |
| `hydra-core`, `hydra-crypto` (dependencies) | GPL-2.0-or-later |
| third-party | Apache-2.0, MIT, BSD-1/3-Clause, Unicode-3.0, LGPL-2.1-or-later (`r-efi`, Windows/UEFI only, dual-licensed MIT/Apache) — all GPL-2.0-compatible |

Findings
- The earlier MIT label on dependents of `gv-sig` is gone, so declared and effective licenses agree.
- Advisories: none against this lockfile. The `paste` unmaintained advisory (RUSTSEC-2024-0436)
  applies to the anti-cheat dependency graph and is recorded there.
- `p2p-net` (a git dependency) must also be GPL-2.0-or-later before binaries are redistributed; its
  Cargo.toml and LICENSE are updated in that repository.
- BUSL-1.1 components (if any are added downstream) must be listed here before release; none are
  present in this repository.
