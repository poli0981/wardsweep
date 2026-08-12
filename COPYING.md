# Licensing

## Application code

`core/`, `cli/`, `ui/`, `tools/` are licensed **GPL-3.0-or-later**.

The full licence text is in [`LICENSE`](LICENSE) at the repository root. This
file is a summary of how the licences are split across the tree and is not a
substitute for it.

## Catalog data

`catalog/` is licensed **CC BY-SA 4.0**.

The anti-cheat catalog is a factual dataset — service names, driver filenames,
install paths, publisher common names. It is deliberately licensed separately so
other uninstaller projects, forum guides and researchers can reuse it without
taking on GPL obligations. Attribution: "WardSweep anti-cheat catalog".

## Documentation

`docs/` is licensed **CC BY-SA 4.0**.

## Third-party notices

Generated into `THIRD-PARTY-NOTICES.md` via `cargo-about` (Rust) and
`dotnet-project-licenses` (C#), and regenerated before every release.

> **Not yet enforced by CI.** No workflow currently checks the committed
> file against a fresh generation, so a stale file will not fail a build.
> Wiring that check up is tracked in `CHANGELOG.md`; until it exists,
> regenerating is a release-checklist item and nothing more.

Anti-cheat product names (Vanguard, Easy Anti-Cheat, BattlEye, ACE, GameGuard,
Xigncode, Denuvo, Ricochet, PunkBuster, and others) are trademarks of their
respective owners. WardSweep is not affiliated with, endorsed by, or derived
from any of them. They are named only to identify the software being uninstalled.
