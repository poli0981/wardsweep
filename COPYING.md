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

Listed in `THIRD-PARTY-NOTICES.md`, which points to two generated files:
`licenses/rust.md` (by `cargo-about`, from `Cargo.lock`) and
`licenses/dotnet.md` (from the interface's `packages.lock.json` and the packages
as restored). CI regenerates both and fails when either differs from what is
committed, and every release carries them.

Anti-cheat product names (Vanguard, Easy Anti-Cheat, BattlEye, ACE, GameGuard,
Xigncode, Denuvo, Ricochet, PunkBuster, and others) are trademarks of their
respective owners. WardSweep is not affiliated with, endorsed by, or derived
from any of them. They are named only to identify the software being uninstalled.
