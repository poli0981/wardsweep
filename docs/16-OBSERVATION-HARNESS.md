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

Size and time, measured rather than estimated. On the development machine —
745 000 files under those roots, of which 124 000 are hashed — a full snapshot
is **156 MB uncompressed** and takes **about three and a half minutes**, with
hashing and the signer lookup running in parallel. The earlier estimate of
40–120 MB was optimistic for a machine with games and toolchains installed.

The resulting diff is small: **0.1 MB and under three seconds**, because
almost nothing changes between two snapshots. That asymmetry is the design
working — the snapshot is machine input and is written compact, the diff is
what a person reads and is written indented.

Committed diffs, not committed snapshots.

### Snapshots taken under different policies are not comparable

A snapshot records the roots it walked, the fragments it excluded, and the hash
policy it applied. `diff` compares them and **says so loudly when they differ**,
because changing the exclusion list moves files in and out of the snapshot
without anything happening on the machine.

This is not hypothetical. Two development snapshots taken either side of one
exclusion-list change produced 109 differences, of which 86 were the list. A
later pair, across a second change, produced 31 579. A diff that cannot notice
that is a diff that invents evidence.

For contrast, the same machine under an **unchanged** policy, five minutes
apart and in use the whole time: **18 file differences**, all of them Electron
application state — a desktop app's `leveldb` and `IndexedDB` directories, and
a vendor tray application's log.

That number is the one to judge a new noise rule against. Eighteen is already
low enough that adding rules to reduce it costs more than it saves: every
exclusion is a directory that is never read again, and the `	emp\` mistake
above shows how that fails. If residual noise ever does need addressing, prefer
a *suppression* rule — which relocates a change and keeps it recoverable — over
an *exclusion*, which does not.

### A snapshot is not an instant

The services are enumerated, then the filesystem is walked, then the registry.
On a developer machine the skew between the first and last domain is around
**five minutes**, so a value that changes during the walk is captured
inconsistently *across domains, within one file*.

Measured: a Riot Vanguard baseline recorded `vgk start_type = system` in the
services domain and `Start = 3` (demand) on that same service's registry key
four minutes later, because the anti-cheat raised its own driver's start type
while its client ran and lowered it again. Both readings were correct. The file
implied they were simultaneous.

Every snapshot therefore records `domain_started_utc` per domain and prints the
span it covered. That does not remove the skew — nothing short of a
transactional capture would, and Windows offers none across these three
domains — but it stops the file making a promise it cannot keep, and it tells a
reviewer which cross-domain comparisons are safe.

## Reducing noise

A snapshot pair taken minutes apart on an idle machine still differs in
thousands of places — Windows Update, Defender definitions, browser caches,
telemetry, MRU lists, prefetch.

The differ applies a noise filter:

- Ignore list of known-volatile paths and keys (shipped, versioned, reviewable).
  Keep the fragments **precise**: an early version excluded a bare `\temp\`,
  which caught the system temp directories as intended and also every
  application that keeps its own `…\SomeGame\Temp\`. An excluded directory is
  never read, so unlike a suppressed change it cannot be recovered from the
  snapshot afterwards — the cost of a rule that is too broad is silent and
  permanent.
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

### Safety Gate G3 constrains what the registry walk may record

`docs/02-SAFETY-GATE.md` G3 forbids reading a hardware identifier **including
for reporting**, and a walk of `HKLM\SOFTWARE` passes straight through
`Microsoft\Cryptography` on its way.

Excluding that key was the obvious first answer and is nowhere near sufficient.
Measured on a development machine, the machine identifier had been copied by
three unrelated applications into their own keys — a Visual Studio installation
key, a developer-tools hardware cache, and a cloud-storage client — all holding
the same value. A separate telemetry cache held the motherboard and CPU model
inside a URL query string, under a value whose name gave no clue. One of those
keys also held a disk serial.

So the refusal matches on the **value name and the value data**, not only on the
key path. The term list is shipped as data
(`tools/observe/src/collect/g3-identity-terms.txt`), refused values are dropped
entirely rather than masked, and each refusal is recorded in `access_denied`
with its key and value name — never its data — so the refusal is auditable.

On that machine the result is 54 values refused out of 217 522 keys, and no
hardware identifier anywhere in the snapshot.

One narrowing is worth knowing about, because it looks like a loophole and is
not: a value whose data begins with `prop:` is a Windows shell *property
schema* — it names properties, it does not hold one — and the data check skips
it. Without that, 184 of 243 refusals were schema lists. The name check still
applies to them.

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

`redact` removes **identity, not secrets**, and says so. Rewriting
`\Users\name\` is not sufficient: on a development machine that left 213
occurrences of the account name behind, in file names and registry keys that
applications had written it into — `…\User Account Pictures\name.dat`,
`…\ConnectedDevicesPlatform\L.name.cdp`. So it learns the account names from
paths **rooted at a drive letter** and replaces them wherever else they appear.

Two consequences worth knowing:

- Names are learned only from a rooted profile path. Learning from any
  `\Users\` segment taught it that `desktop.ini`, `guest` and `*` were people
  — from a container layer, an Android source tree and an ASP.NET sample — and
  it then replaced those tokens across the whole document.
- Replacement is on token boundaries, so an account name inside a longer word
  survives. `redact` counts what remains, reports it, and exits non-zero. It
  does not claim to have produced a clean file, and `docs/16`'s checklist still
  expects a person to read one before it is attached to anything.
