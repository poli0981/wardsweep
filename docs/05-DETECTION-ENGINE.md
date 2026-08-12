# 05 — Detection Engine

## Design goal

One pass over each data source, matching every catalog pattern simultaneously,
with a memory footprint independent of the number of patterns.

## Matching strategy

Detection is a scored, multi-signal decision — never a single filename match.

| Signal | Weight | Notes |
|---|---|---|
| Service name exact match | High | Authoritative; services are namespaced |
| Driver filename + path | High | Combined with publisher, near-certain |
| Authenticode publisher CN | Critical | Presence confirms; **mismatch downgrades to `suspicious`** |
| SHA-256 hash pin | Certain | Only for known builds; absence is not evidence |
| Registry key exact path | High | |
| Install path match | Medium | Paths are user-relocatable |
| Uninstall entry `DisplayName` | Medium | Publisher-controlled, drifts |

**Classification:**

- `confirmed` — high-weight signal **and** publisher match
- `probable` — high-weight signal, publisher unverifiable (file already deleted)
- `suspicious` — path/name matches but publisher is wrong or signature invalid
- `orphan` — confirmed anti-cheat, refcount 0

`suspicious` is **never** auto-selected for removal. Something sitting at the
Easy Anti-Cheat path signed by nobody is exactly what you do not want a tool
silently deleting — it is reported prominently and the user decides.

## Aho–Corasick single pass

All path fragments and registry value patterns across all catalog entries are
compiled into one automaton at startup.

```rust
let ac = AhoCorasickBuilder::new()
    .ascii_case_insensitive(true)     // Windows paths are case-insensitive
    .match_kind(MatchKind::LeftmostLongest)
    .build(&all_patterns)?;
```

Complexity is `O(n + m + z)` — input length, pattern length, matches — and does
**not** degrade as the catalog grows. Adding 200 anti-cheat entries costs
automaton build time (milliseconds, once) and nothing per byte scanned.

Automaton is built once, shared across worker threads by `Arc`.

## Registry scanning

### WOW64 is the number one source of missed artifacts

A 64-bit process reading `HKLM\SOFTWARE` transparently gets the 64-bit view.
32-bit installers — which most game and anti-cheat installers still are — write
to `HKLM\SOFTWARE\WOW6432Node`. Reading only one view misses roughly half of all
uninstall entries.

Every `HKLM\SOFTWARE` open is performed **twice**:

```rust
for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
    RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ | view, &mut hkey)
}
```

Results are tagged with their view. The same logical key discovered in both
views is two distinct artifacts and both must be removed.

### Scope

| Hive | Scanned |
|---|---|
| `HKLM\SOFTWARE` | Both views, catalog keys + uninstall enumeration |
| `HKLM\SYSTEM\CurrentControlSet\Services` | Full enumeration (cheap, ~1500 keys) |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Both views |
| `HKCU\SOFTWARE` | Per-user, catalog keys only |
| `HKU\<SID>\SOFTWARE` | All loaded profiles when elevated |
| `HKLM\SYSTEM\...\Session Manager\AppCertDlls` | Read-only report; never modified |

**Not scanned:** anything under `SECURITY`, `SAM`, or the BAM/DAM execution
history except for a read-only "last executed" timestamp used to age orphans.

### Unloaded user hives

Profiles that are not logged in have their `NTUSER.DAT` unloaded. Elevated
scans load them via `RegLoadKey` into a temporary path and **always** unload in
a guard, including on panic. A leaked hive load prevents the user logging in —
this is tested explicitly.

## Filesystem scanning

### Bounded, not exhaustive

Full-disk walks are wasteful and slow. The walker seeds from:

1. Catalog `paths` (expanded)
2. Discovered Steam/Epic/EA/Ubisoft/Battle.net/Riot library roots
3. `%ProgramFiles%`, `%ProgramFiles(x86)%`, `%ProgramData%` at depth ≤ 4
4. Per-user `%LOCALAPPDATA%`, `%APPDATA%` at depth ≤ 5
5. `%SystemRoot%\System32\drivers` (filename match only, never recursive)

Optional deep scan is opt-in, off by default, and clearly labelled slow.

### Reparse points

```rust
// Junctions and symlinks are enumerated but NEVER traversed.
if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
    record_as_link(&path);   // reported, not followed
    continue;
}
```

`%LOCALAPPDATA%` contains junctions to legacy locations. Following them causes
infinite recursion and, worse, causes deletion to escape the intended tree. This
rule is also enforced at the deletion layer, not only the scan layer.

### Parallelism

`rayon` with a pool sized to *physical* cores. Each worker owns a string arena;
arenas merge at the end. Bloom filter over interesting filename fragments
pre-filters before any hashing or signature check — this drops ≥ 99 % of files
before the expensive work.

## Service and driver enumeration

`EnumServicesStatusExW` with `SERVICE_WIN32 | SERVICE_DRIVER` in one pass.
For each match, `QueryServiceConfigW` + `QueryServiceConfig2W` capture the full
configuration into the artifact record — this is what rollback replays.

Recorded per service: `ServiceType`, `StartType`, `ErrorControl`, `BinaryPathName`,
`LoadOrderGroup`, `Tag`, `Dependencies`, `ServiceStartName`, `DisplayName`,
`Description`, `DelayedAutoStart`, `FailureActions`, `RequiredPrivileges`, SDDL.

`StartType == SERVICE_BOOT_START` sets `risk = critical` and forces the reboot
stage — see [`06`](06-REMOVAL-PIPELINE.md) and [`13`](13-P0-SPIKES.md) S1.

## Authenticode verification

`WinVerifyTrust` with `WTD_UI_NONE`, `WTD_REVOKE_WHOLECHAIN`, then extract the
signer CN via `CryptQueryObject` / `CertGetNameStringW`.

Cached by `(volume_serial, file_id, size, mtime)` for the session — file ID
rather than path, so a file seen through two paths is verified once. See
[`10`](10-PERF-BUDGET.md). Verification is the expensive step, so it runs only
after Bloom + Aho–Corasick have narrowed the set.

> A volume serial number is not a volume GUID and is not a hardware
> fingerprint; it identifies a filesystem, changes on reformat, and never
> leaves the process. G3 is not engaged. Stated here because a reviewer working
> through the [`02`](02-SAFETY-GATE.md) checklist will reasonably ask.

Expired certificates on old anti-cheat builds are **normal** and are not
downgraded — countersigned timestamps are honoured.

## Ownership graph and reference counting

```
Game ──references──▶ AntiCheat
```

Built from catalog `game.anticheat` plus evidence found on disk. A game counts
toward refcount when **any** of:

- Launcher reports it installed (`appmanifest_*.acf`, Epic `.item`, EA/Ubi registry)
- An `install_hints` path exists with a non-trivial file count
- An uninstall registry entry exists for it

Deliberately over-inclusive: a false "installed" leaves an anti-cheat in place
(harmless), a false "not installed" removes an anti-cheat another game needs
(the G1 violation this whole design exists to prevent).

`shared = true` entries with refcount ≥ 1 are rendered in the UI as **blocked**,
with the specific blocking game named. Not greyed out silently — named.

## Deny-list

Compiled in, checked after catalog expansion, on every path and key, at scan
*and* at execute:

```
C:\Windows\**              except explicit driver filenames in System32\drivers
C:\Windows\System32\**     no exceptions beyond the above
C:\Users\**\NTUSER.DAT*
C:\ProgramData\Microsoft\**
HKLM\SYSTEM\CurrentControlSet\Services\*   except catalog-named services
HKLM\SAM\**  HKLM\SECURITY\**  HKLM\BCD*
Any path resolving to a volume root
Any path traversing a reparse point
Any top-level directory targeted as a whole: Windows, Users, ProgramData,
  Program Files, Program Files (x86), $Recycle.Bin, System Volume Information,
  Recovery, Boot, EFI, PerfLogs — on every drive, not only C:
Any path with fewer than 2 components under a drive root
Any 8.3 alias that has not been expanded through the filesystem
Any UNC or device-namespace path
```

> The depth floor was originally written as "fewer than 4 components under a
> drive root". Taken literally that denies `%ProgramData%\EasyAntiCheat` and
> `%ProgramFiles(x86)%\EasyAntiCheat` — almost every path a catalog contains,
> and everything [`02`](02-SAFETY-GATE.md) explicitly permits removing. The
> rule's purpose is to stop a whole top-level directory being targeted, so it
> is implemented as a floor of 2 plus the explicit list above.
> Enforced in `core/src/safety/denylist.rs`.

Deny-list is enforced by a function that takes the *canonicalised* path, after
`GetFinalPathNameByHandleW` resolution. Checking the pre-canonical string is a
bug class, not a shortcut.

## Access-denied handling

An unelevated scan cannot read parts of `HKLM` or other users' profiles. Those
locations are recorded as `access_denied`, **not** as absent, and the report
states plainly that the scan was partial. Reporting "clean" from a blind scan
would be the most damaging possible bug in an audit tool.
