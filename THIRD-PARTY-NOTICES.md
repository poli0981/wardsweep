# Third-Party Notices

WardSweep incorporates third-party software. This document lists those components and
their licences.

> **This file is generated.** The authoritative version is produced at build time by
> `cargo about generate` (Rust) and `dotnet-project-licenses` (C#), then committed. The
> tables below are the maintained template; **regenerate before every release** so they
> reflect the exact versions in `Cargo.lock` and `packages.lock.json`. Do not hand-edit
> the generated sections.
>
> **Staleness is not yet checked by CI.** No workflow compares this file against a
> fresh generation, so nothing will stop an out-of-date version from shipping.
> Regenerating is a release-checklist item until that check exists — see `CHANGELOG.md`.
>
> Licence identifiers use [SPDX](https://spdx.org/licenses/). Full licence texts are
> bundled under `licenses/` and viewable from the About page.

---

## Rust components

| Component | Licence | Purpose |
| --- | --- | --- |
| `windows` (windows-rs) | MIT OR Apache-2.0 | Win32, SCM, registry, Authenticode bindings |
| `aho-corasick` | Unlicense OR MIT | Single-pass multi-pattern matching |
| `rayon` | MIT OR Apache-2.0 | Bounded parallel filesystem walk |
| `ed25519-dalek` | BSD-3-Clause | Catalog signature verification |
| `rusqlite` | MIT | Job history and audit trail |
| `serde` / `serde_json` | MIT OR Apache-2.0 | IPC and manifest serialisation |
| `toml` | MIT OR Apache-2.0 | Catalog parsing |
| `tracing` / `tracing-subscriber` | MIT | Structured logging |
| `sha2` | MIT OR Apache-2.0 | Artifact hashing |
| `clap` | MIT OR Apache-2.0 | CLI argument parsing |

## .NET components

| Component | Licence | Purpose |
| --- | --- | --- |
| WPF-UI (`lepoco/wpfui`) | MIT | Fluent controls, NavigationView, Mica backdrop |
| CommunityToolkit.Mvvm | MIT | MVVM source generators |
| Microsoft.Extensions.Hosting | MIT | Dependency injection, lifetime |
| Serilog + sinks | Apache-2.0 | UI logging |
| Velopack | MIT | Installer and delta updates |

## Build and CI tooling

Not distributed with the application; listed for completeness.

| Component | Licence | Purpose |
| --- | --- | --- |
| `cargo-about` | MIT OR Apache-2.0 | Generates the Rust section above |
| `cargo-deny` | MIT OR Apache-2.0 | Advisory, licence and ban checks |
| `dotnet-project-licenses` | MIT | Generates the .NET section above |
| XamlStyler | MIT | XAML formatting gate |
| Roslynator, Meziantou.Analyzer | Apache-2.0 / MIT | C# analysers |

---

## Trademarks

Anti-cheat and game product names referenced in the catalog and documentation —
including Vanguard, Easy Anti-Cheat, BattlEye, ACE, GameGuard, Xigncode, Denuvo,
Ricochet, PunkBuster, and others — are trademarks of their respective owners.

WardSweep is not affiliated with, endorsed by, sponsored by, or derived from any of
them. These names appear solely to identify the software being uninstalled, which is
nominative use.

Windows, Microsoft Defender and SmartScreen are trademarks of Microsoft Corporation.
Steam is a trademark of Valve Corporation. Other launcher and platform names are
trademarks of their respective owners.

---

## WardSweep's own licensing

| Component | Licence |
| --- | --- |
| Application code (`core/`, `cli/`, `ui/`, `tools/`) | GPL-3.0-or-later |
| Anti-cheat catalog (`catalog/`) | CC BY-SA 4.0 |
| Documentation (`docs/`) | CC BY-SA 4.0 |

See [`COPYING.md`](COPYING.md).
