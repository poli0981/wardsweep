# 04 — Catalog Schema

The catalog is the single source of truth for what an anti-cheat looks like on
disk. It ships as `catalog/catalog.toml` with a detached Ed25519 signature and
is versioned independently of the application binary.

> **Everything in the example entries below is illustrative and must be verified
> against a real observation-harness diff before shipping.** Anti-cheat vendors
> change service names, paths and installers frequently. See
> [`16-OBSERVATION-HARNESS.md`](16-OBSERVATION-HARNESS.md).

## Why a separate signed file

- Anti-cheat footprints change faster than release cycles
- Users can inspect exactly what the tool will match — no hidden heuristics
- Community can contribute entries without touching removal code
- CC BY-SA 4.0 licensing lets other projects reuse the data
- Signature verification is the security boundary: an unverified catalog is
  **refused**, never used with a warning

## Top level

```toml
schema_version = 1
catalog_version = "2026.08.12"
minimum_app_version = "0.5.0"
```

The broker refuses a catalog whose `schema_version` it does not implement, and
warns if `minimum_app_version` exceeds its own.

## `[[anticheat]]`

```toml
[[anticheat]]
id           = "eac-eos"                    # stable, kebab-case, never reused
display      = "Easy Anti-Cheat (EOS)"
vendor       = "Epic Games"
kind         = "kernel"                     # kernel | usermode | hybrid
shared       = true                         # true ⇒ refcount is mandatory
risk         = "high"                       # low | medium | high | critical

# --- identity: how we know it is really this, not something wearing the name
authenticode_cn = ["Epic Games, Inc.", "EasyAntiCheat Oy"]
file_hashes     = []                        # optional SHA-256 pins for known builds

# --- footprint
services = ["EasyAntiCheat", "EasyAntiCheatEOS"]
drivers  = ["EasyAntiCheat.sys", "EasyAntiCheatEOS.sys"]

paths = [
  { path = "%ProgramFiles(x86)%\\EasyAntiCheat", class = "install" },
  { path = "%ProgramData%\\EasyAntiCheat",       class = "data" },
]

registry = [
  { key = "HKLM\\SOFTWARE\\EasyAntiCheat",       view = "both", class = "config" },
  { key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat", view = "64", class = "service" },
]

tasks          = []
firewall_rules = ["EasyAntiCheat*"]
event_sources  = ["EasyAntiCheat"]

# --- official removal, always attempted first
[anticheat.official_uninstall]
kind    = "exe"                             # exe | msi | none
command = "%ProgramFiles(x86)%\\EasyAntiCheat\\EasyAntiCheat_Setup.exe"
args    = ["uninstall", "{product_id}"]
timeout_secs = 300
```

### Field notes

| Field | Notes |
|---|---|
| `id` | Permanent. Referenced by games and by job history. Never renamed. |
| `kind` | `kernel` implies a driver and therefore a reboot stage. |
| `shared` | `true` makes refcount enforcement mandatory — see G1. Default `true` when unknown; conservative direction. |
| `risk` | Drives UI colour and whether removal requires typed confirmation. `critical` = boot-start driver. |
| `authenticode_cn` | Primary identity signal. A file at a matching path with the *wrong* publisher is reported as suspicious, never auto-removed. |
| `view` | `32`, `64`, or `both`. `both` is almost always correct — see [`05`](05-DETECTION-ENGINE.md) on WOW64. |
| `class` | `install` \| `data` \| `config` \| `service` \| `cache` \| `log`. Drives default tick state: `cache`/`log` on, `data` off pending review. |

## `[[game]]`

```toml
[[game]]
id            = "example-shooter"
display       = "Example Shooter"
publisher     = "Example Studios"
anticheat     = ["eac-eos"]                 # ids; ordering irrelevant
platforms     = ["steam", "epic"]

steam_appid   = 000000
epic_app_name = "ExampleShooter"

install_hints = [
  { path = "%ProgramFiles(x86)%\\Steam\\steamapps\\common\\Example Shooter", class = "install" },
]

residue = [
  { path = "%LOCALAPPDATA%\\ExampleShooter\\Cache", class = "cache" },
  { path = "%LOCALAPPDATA%\\ExampleShooter\\Logs",  class = "log" },
]

# Never removed by default. Always archived before any removal.
saves = [
  { path = "%LOCALAPPDATA%\\ExampleShooter\\Saved\\SaveGames", class = "save" },
  { path = "%USERPROFILE%\\Documents\\Example Shooter",        class = "save" },
]

registry = [
  { key = "HKCU\\SOFTWARE\\Example Studios\\Example Shooter", view = "both", class = "config" },
]
```

**`saves` is a protection list, not a removal list.** Entries here are excluded
from every removal plan by default, are shown in a separate UI section, and are
zipped into quarantine even when the user explicitly opts to remove them.

## `[[launcher]]`

```toml
[[launcher]]
id      = "steam"
display = "Steam"
detect_registry = "HKLM\\SOFTWARE\\WOW64Node\\Valve\\Steam"
library_index   = "steamapps\\libraryfolders.vdf"
manifest_glob   = "steamapps\\appmanifest_*.acf"
uninstall = { kind = "protocol", command = "steam://uninstall/{appid}", silent = false }
```

Launchers matter for two reasons: they own the authoritative "is this game
installed" answer, and they leave their own residue (the `appmanifest_*.acf`
problem — see [`06`](06-REMOVAL-PIPELINE.md)).

## Path variables

Expanded by the broker, never by the shell:

`%ProgramFiles%` `%ProgramFiles(x86)%` `%ProgramData%` `%LOCALAPPDATA%`
`%APPDATA%` `%USERPROFILE%` `%SystemRoot%` `%PUBLIC%`
`%STEAM_LIBRARY%` `%EPIC_LIBRARY%` (multi-valued; expand to every discovered library)

Per-user variables expand across **all** local user profiles when running
elevated, each expansion tracked separately so a per-user artifact is never
attributed to the wrong account.

## Deny-list interaction

Catalog entries are expanded **before** the deny-list check, never after. A
catalog entry naming `C:\Windows\System32` is rejected at load time and the
whole catalog fails verification. The deny-list is compiled into the binary and
is not catalog-configurable — see [`05`](05-DETECTION-ENGINE.md).

## Signing

```
catalog.toml       the data
catalog.toml.sig   Ed25519 detached signature over the raw bytes
```

Public key is compiled into the broker. Verification is unconditional. A
catalog that fails verification produces a hard error and the broker falls back
to the version compiled in at build time.

Update flow: opt-in only. The user may fetch a new catalog over HTTPS, or import
a `.toml` + `.sig` pair from disk. Both paths run the same verification.

## Anti-cheat coverage — initial target

Vanguard · Easy Anti-Cheat (legacy + EOS) · BattlEye · ACE (Tencent) ·
nProtect GameGuard · Xigncode3 · Denuvo Anti-Cheat · Ricochet · mhyprot ·
PunkBuster · FACEIT AC · Equ8

**VAC is deliberately absent.** It is a component of the Steam client, not a
separately installable product. Removing Steam is a normal application
uninstall.

## Adding an entry

1. Run the observation harness on a clean snapshot (see [`16`](16-OBSERVATION-HARNESS.md))
2. Diff install → uninstall to get the true footprint
3. Verify publisher with `signtool verify /v /pa <file>`
4. Set `shared = true` unless you have positive evidence it is single-title
5. Submit the diff JSON alongside the entry
