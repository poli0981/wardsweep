# WardSweep

> Windows-only. Removes anti-cheat-bearing games **together with** their anti-cheat
> software, then sweeps the residue those uninstallers leave behind.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](COPYING)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-0078D4)
![Status](https://img.shields.io/badge/status-pre--alpha-orange)

---

## What it does

Kernel-mode anti-cheat (Vanguard, Easy Anti-Cheat, BattlEye, ACE, nProtect, ...)
installs boot-start drivers, Windows services, scheduled tasks and registry trees.
When you uninstall the game, a surprising amount of that stays behind — sometimes
the driver keeps loading at every boot for a game you deleted two years ago.

WardSweep does three things:

1. **Audit** — read-only scan. Lists every anti-cheat on the machine, which game
   owns it, whether it is still referenced, and what it left in the registry and
   filesystem. Produces an exportable report. **Requires no administrator rights.**
2. **Remove** — uninstall selected games via their official uninstallers first,
   then remove the anti-cheat *only if no remaining game still needs it*, then
   sweep the residue.
3. **Orphan Sweep** — find and remove anti-cheat components whose game is already
   gone. This is the most common real-world case.

## What it explicitly does **not** do

WardSweep is an uninstaller. It is not a cheat tool, and the following are
permanently out of scope — see [`docs/02-SAFETY-GATE.md`](docs/02-SAFETY-GATE.md):

- Removing or disabling anti-cheat while leaving the game playable
- Stopping, unloading or tampering with anti-cheat while a game is running
- Modifying hardware identifiers (MachineGuid, SMBIOS UUID, disk serial, MAC)
- Anything framed as ban evasion, "HWID reset", or "clean trace"

There is no "uninstall anti-cheat only" button and there never will be. An
anti-cheat becomes eligible for removal only as a consequence of removing every
game that references it.

## Safety model

| Guarantee | How |
|---|---|
| Nothing is deleted immediately | Everything moves to a quarantine store first |
| One-click rollback | Per-job manifest restores files, registry keys and service configs |
| Reversible registry edits | Every touched key is exported to `.reg` before modification |
| Official path first | Vendor/launcher uninstaller is always attempted before manual removal |
| Nothing hidden | Full plan is shown and must be approved before any write |
| Save games preserved | Known save paths are excluded by default and always archived |

## Stack

| Layer | Technology |
|---|---|
| Core / broker | Rust (stable), `windows-rs`, elevated, headless |
| UI | C# / .NET 10 LTS, WPF, [WPF-UI 4.3.0](https://wpfui.lepo.co/) |
| IPC | Named pipe, length-prefixed JSON |
| Storage | SQLite via `rusqlite` (job history, quarantine manifests) |
| Catalog | Signed TOML, versioned independently of the binary |
| Packaging | Velopack |
| Logging | `tracing` (Rust) + Serilog (UI), rolling files |

## Documentation

| # | Document | Read it when |
|---|---|---|
| 01 | [Vision & Scope](docs/01-VISION-SCOPE.md) | Starting out |
| 02 | [Safety Gate](docs/02-SAFETY-GATE.md) | **Before writing any code** |
| 03 | [Architecture](docs/03-ARCHITECTURE.md) | Understanding process split |
| 04 | [Catalog Schema](docs/04-CATALOG-SCHEMA.md) | Adding an anti-cheat |
| 05 | [Detection Engine](docs/05-DETECTION-ENGINE.md) | Scan internals |
| 06 | [Removal Pipeline](docs/06-REMOVAL-PIPELINE.md) | The six stages |
| 07 | [Rollback & Quarantine](docs/07-ROLLBACK-QUARANTINE.md) | Undo semantics |
| 08 | [IPC Protocol](docs/08-IPC-PROTOCOL.md) | UI ↔ broker wire format |
| 09 | [UI Specification](docs/09-UI-SPEC.md) | Building screens |
| 10 | [Performance Budget](docs/10-PERF-BUDGET.md) | Optimising |
| 11 | [CLI Reference](docs/11-CLI-REFERENCE.md) | Scripting / testing |
| 12 | [Testing Strategy](docs/12-TESTING-STRATEGY.md) | Writing tests |
| 13 | [P0 Spikes](docs/13-P0-SPIKES.md) | **Before feature work** |
| 14 | [Distribution & Trust](docs/14-DISTRIBUTION-TRUST.md) | Releasing |
| 15 | [Test Machine Protocol](docs/15-TEST-MACHINE-PROTOCOL.md) | **Before touching a real machine** |
| 16 | [Observation Harness](docs/16-OBSERVATION-HARNESS.md) | Building catalog entries |
| 17 | [Internationalisation](docs/17-I18N.md) | Adding strings |
| 18 | [Logging](docs/18-LOGGING.md) | Diagnostics |
| 19 | [Roadmap](docs/19-ROADMAP.md) | Planning |
| 20 | [Glossary](docs/20-GLOSSARY.md) | Terminology |
| — | [Releases & Detections](docs/RELEASES.md) | Hashes, VirusTotal links, FP status |
| — | [Disclaimer](DISCLAIMER.md) | **Before first run** |

## Status

Pre-alpha. **No removal code exists yet.** The seven P0 spikes in
[`docs/13-P0-SPIKES.md`](docs/13-P0-SPIKES.md) are go/no-go gates: three of them
(S1 boot-start driver removal, S2 shared anti-cheat reference counting, S5
rollback fidelity) decide whether the automatic-removal product is viable at all.
If they fail, WardSweep ships as an audit-and-guidance tool instead.

## Security & trust

WardSweep deletes drivers and services. That is behaviourally indistinguishable
from malware, and antivirus engines will say so. Every release ships with a
VirusTotal permalink and false positives are reported to vendors as they appear.
See [`docs/14-DISTRIBUTION-TRUST.md`](docs/14-DISTRIBUTION-TRUST.md) and
[`SECURITY.md`](SECURITY.md).

## Before you run it

Read [`DISCLAIMER.md`](DISCLAIMER.md). It states, in plain language, the specific ways
this program can fail — including that builds are unsigned, that a scan without
administrator rights is a partial scan, and that games removed in Stage 2 cannot be
restored by rollback.

## Licence

GPL-3.0-or-later. See [`COPYING`](COPYING).
The anti-cheat catalog (`catalog/`) is CC BY-SA 4.0 so it can be reused
independently of the application.
