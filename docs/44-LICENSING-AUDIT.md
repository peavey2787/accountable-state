# Licensing audit (accountable-state)

Generated from `cargo deny list` and `cargo deny check advisories` on the committed lockfile.

| Component | Declared | Effective |
| --- | --- | --- |
| `gv-sig`, `hydra-core`, `hydra-crypto` | GPL-2.0-or-later | GPL-2.0-or-later |
| `gv-wasm` | GPL-2.0-or-later | GPL-2.0-or-later (links `gv-sig`) |
| `gv-proof-queue` | MIT | **GPL-2.0-or-later when linked**: it depends on `gv-sig` |
| other workspace crates | MIT | GPL-2.0-or-later whenever `gv-sig` is linked |
| third-party | Apache-2.0, MIT, BSD-1/3-Clause, Unicode-3.0, LGPL-2.1-or-later (`r-efi`, Windows/UEFI only, dual-licensed MIT/Apache) | compatible |

Findings
- An MIT label on a crate that links a GPL crate does not change the combined work's license.
  Relicensing `gv-sig`, or relabelling the dependents, is an **owner decision** and has not been made
  or assumed here. Options: keep (document the effective license), obtain permission to relicense
  `gv-sig`, or split the signing backend behind a trait.
- Advisories: none against this lockfile. The `paste` unmaintained advisory (RUSTSEC-2024-0436)
  applies to the anti-cheat dependency graph and is recorded there.
- BUSL-1.1 components (if any are added downstream) must be listed here before release; none are
  present in this repository.
