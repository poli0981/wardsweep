# Licensing

## Application code

`core/`, `cli/`, `ui/`, `tools/` are licensed **GPL-3.0-or-later**.

The full licence text belongs in a file named `COPYING` at the repository root —
copy it verbatim from <https://www.gnu.org/licenses/gpl-3.0.txt>. This file is a
summary and is not a substitute for it.

## Catalog data

`catalog/` is licensed **CC BY-SA 4.0**.

The anti-cheat catalog is a factual dataset — service names, driver filenames,
install paths, publisher common names. It is deliberately licensed separately so
other uninstaller projects, forum guides and researchers can reuse it without
taking on GPL obligations. Attribution: "WardSweep anti-cheat catalog".

## Documentation

`docs/` is licensed **CC BY-SA 4.0**.

## Third-party notices

Generated at build time into `THIRD-PARTY-NOTICES.md` via `cargo-about` (Rust)
and `dotnet-project-licenses` (C#). CI fails if the generated file is stale.

Anti-cheat product names (Vanguard, Easy Anti-Cheat, BattlEye, ACE, GameGuard,
Xigncode, Denuvo, Ricochet, PunkBuster, and others) are trademarks of their
respective owners. WardSweep is not affiliated with, endorsed by, or derived
from any of them. They are named only to identify the software being uninstalled.
