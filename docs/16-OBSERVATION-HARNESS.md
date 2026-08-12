# 16 — Observation Harness

## Why

Catalog entries must describe what an anti-cheat *actually* installs, on a real
machine, at a real version. Not what a forum post from 2023 said, not what
another tool's source code implies, and not what anyone remembers.

Wrong catalog data deletes the wrong thing on someone's machine. The harness
exists so every entry is derived from an observed diff.

## Principle

```
snapshot(clean) → install → snapshot(dirty) → diff → catalog draft
              → official uninstall → snapshot(after) → diff → RESIDUE
```

The second diff is the more valuable one. It is the exact set of things the
vendor's own uninstaller leaves behind — which is the entire reason WardSweep
exists.

## Commands

```powershell
wardsweep observe snapshot -o 01-clean.json
# install the game + anti-cheat
wardsweep observe snapshot -o 02-installed.json
# uninstall via the official uninstaller only
wardsweep observe snapshot -o 03-uninstalled.json

wardsweep observe diff --before 01-clean.json --after 02-installed.json -o footprint.json
wardsweep observe diff --before 03-uninstalled.json --after 01-clean.json -o residue.json
wardsweep observe suggest --diff footprint.json --residue residue.json -o draft.toml
```

`suggest` emits a **draft** catalog entry. It is a starting point requiring
human review, never a finished entry — see "Review before submitting" below.

## What a snapshot captures

| Domain | Captured |
|---|---|
| Services | Full `QueryServiceConfigW` + `QueryServiceConfig2W` for every service and driver |
| Registry | `HKLM\SOFTWARE` (both WOW64 views), `HKLM\SYSTEM\CurrentControlSet\Services`, `Run` keys, uninstall keys, `HKCU\SOFTWARE` |
| Filesystem | Path, size, SHA-256, mtime, Authenticode signer for `%ProgramFiles*%`, `%ProgramData%`, `%LOCALAPPDATA%`, `%APPDATA%`, `System32\drivers`, launcher libraries |
| Scheduled tasks | Full XML export of every task |
| Firewall | Every rule via `INetFwPolicy2` |
| Event log sources | Registered sources under `EventLog\Application` |
| Environment | Windows build, locale, installed launchers and versions |

Snapshots are **read-only**. The harness has no removal code path at all — it
ships as `wardsweep-observe.exe`, built from `tools/observe/`, for exactly
this reason. `wardsweep observe …` in [`11`](11-CLI-REFERENCE.md) forwards to
it rather than linking its logic into the broker frontend.

Size: roughly 40–120 MB uncompressed, 5–15 MB compressed. Committed diffs, not
committed snapshots.

## Reducing noise

A snapshot pair taken minutes apart on an idle machine still differs in
thousands of places — Windows Update, Defender definitions, browser caches,
telemetry, MRU lists, prefetch.

The differ applies a noise filter:

- Ignore list of known-volatile paths and keys (shipped, versioned, reviewable)
- Ignore `LastWriteTime`-only registry changes with unchanged values
- Ignore files under `%TEMP%`, `%SystemRoot%\SoftwareDistribution`, Defender
  platform directories, browser profiles
- Collapse per-file changes under a single new directory into one entry
- Group by Authenticode signer, so vendor-signed additions cluster together

**Signer clustering is the single most useful signal.** Everything the anti-cheat
installer dropped shares a publisher, and it separates instantly from Windows
Update noise.

To reduce noise further, before snapshotting:

```powershell
Stop-Service wuauserv
Set-MpPreference -SignatureScheduleDay Never    # test machine only
# close browsers and launchers
```

Take snapshots at a consistent point: freshly booted, idle for two minutes, all
launchers closed.

## Draft entry generation

`observe suggest` produces:

```toml
# DRAFT — generated from footprint.json 2026-08-12
# Windows 11 26100.xxxx · Game vX.Y · Launcher vZ
# REVIEW EVERY FIELD BEFORE SUBMITTING

[[anticheat]]
id      = "REVIEW-me"
display = "REVIEW: from signer CN"
kind    = "kernel"          # inferred: a driver service was created
shared  = true              # DEFAULT — prove otherwise before changing
risk    = "critical"        # inferred: SERVICE_BOOT_START observed

authenticode_cn = ["<observed signer CN>"]
services = [ ... ]
drivers  = [ ... ]
paths    = [ ... ]
registry = [ ... ]
```

Inference rules, all deliberately conservative:

| Observation | Inferred |
|---|---|
| Driver service created | `kind = "kernel"` |
| `SERVICE_BOOT_START` | `risk = "critical"` |
| No driver, only a user-mode service or process | `kind = "usermode"` |
| Anything unknown | The most conservative value |

`shared` always defaults to `true`. It is downgraded only with positive evidence
across multiple observed titles — a wrong `shared = false` is the G1 failure
mode.

## Review before submitting

The generated draft is a hypothesis. Before it becomes a catalog entry:

- [ ] Verify every signer CN with `signtool verify /v /pa <file>` and paste the
      output into the PR
- [ ] Confirm each path is genuinely anti-cheat, not a shared vendor directory
      that other software also uses
- [ ] Classify each path: `install` / `data` / `config` / `cache` / `log`
- [ ] Separate save paths into the game's `saves` list — check both
      `%LOCALAPPDATA%` and `Documents`
- [ ] Confirm `shared` against at least two titles, or leave it `true`
- [ ] Test the `official_uninstall` command manually and record what it does
- [ ] Cross-check the residue diff: what did the official uninstaller leave?
- [ ] Attach the diff JSON to the PR

## Multi-title observation

For a shared anti-cheat, repeat across at least three titles from different
launchers. The intersection of the three footprints is the anti-cheat itself;
the differences are per-title integration.

```powershell
wardsweep observe intersect --diff a.json --diff b.json --diff c.json -o shared.json
```

This is how a `shared = true` entry gets its footprint right, and it directly
feeds spike S2.

## The uninstall-and-reinstall cycle

Games already installed before the harness existed have no clean "before"
state. Recovering it:

1. `wardsweep observe snapshot -o 00-current.json`
2. Uninstall via the **official uninstaller only** — do not use WardSweep
3. `wardsweep observe snapshot -o 01-clean.json`
4. Diff `01-clean` against `00-current` → this is the **residue** the vendor
   left, which is directly valuable
5. Reinstall
6. `wardsweep observe snapshot -o 02-installed.json`
7. Diff → the true footprint

Step 4 alone justifies the cycle. It answers "what does the official uninstaller
miss?" with evidence, which is the founding claim of the whole project.

## Storage

```
observations/
├── 2026-08-12-example-shooter-steam/
│   ├── meta.json            machine, versions, dates
│   ├── footprint.json       install diff
│   ├── residue.json         post-uninstall diff
│   ├── draft.toml           generated entry
│   └── notes.md             anything the tooling could not capture
```

Diffs are committed. Raw snapshots are not — they contain full path listings of
a real machine and are large. If a raw snapshot must be shared for debugging,
run it through `wardsweep observe redact` first, which replaces usernames and
per-user paths with placeholders.
