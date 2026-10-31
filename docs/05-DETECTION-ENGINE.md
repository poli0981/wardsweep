# 05 — Detection Engine

> **What exists (2026-10-30).** The audit engine, `core/src/scan/engine.rs`,
> over a read-only machine view: services through SCM and the `Services` key,
> drivers by the image name of every driver key, registry keys in both views
> where WOW64 redirects, paths expanded per game library, the deny-list on
> every path and key, and the classification below. It is tested against a
> machine built from a committed observation diff. On Windows the view is
> `core/src/scan/win.rs` — SCM, the `Services` key, the registry in the view
> asked for, `symlink_metadata`, and `WinVerifyTrust` offline — and
> `wardsweep scan` runs the audit ([`11`](11-CLI-REFERENCE.md)), tested against
> the machine the tests run on. Not yet: games, the bounded filesystem walk,
> the signature cache, and the ownership graph (S2). The sections below are the
> specification it follows.

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

**An attestation signature names no vendor.** Microsoft re-signs every
third-party kernel driver submitted through its hardware dev center as
*Microsoft Windows Hardware Compatibility Publisher*; every `.sys` of ACE's
footprint carries that signature and nothing of ACE's
(`observations/2026-08-19-anticheatexpert/notes.md`). It verifies the file and
leaves the publisher unverifiable, so a driver signed that way is `probable`:
neither the mismatch that makes `suspicious` nor the match that confirms,
whatever the catalog lists. The first `wardsweep scan` of a machine with ACE
installed, on 2026-10-30, called ACE's driver `suspicious` until this rule
existed.

**An unelevated audit can end with nothing confirmed.** On 2026-10-31,
Arknights: Endfield installed ACE 29.6, and an audit of that install with the
committed drafts found 17 artifacts. Every one was `probable`, and none was
`confirmed`. Three things block confirmation:
- ACE 29.6's service admits only SYSTEM and Administrators, so the unelevated
  audit cannot read its configuration. The service is reported unreadable,
  never absent, and its key is still found.
- Its drivers carry the attestation signature.
- The images of its per-title core drivers are absent while no game runs.

The executable that does name the vendor sits in ACE's own folder.
Confirmation would have to come from a signature check there, and the
filesystem walk that would do it is not built
(`observations/2026-10-31-anticheatexpert/notes.md`).

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

### Not WMI

`Win32_SystemDriver` looks like an easier way to enumerate drivers and is not
one: it can report a driver that no longer exists.

Measured during the AntiCheatExpert observation
(`observations/2026-08-19-anticheatexpert/`), immediately after the vendor's own
uninstaller ran:

| Source | Reports `ACE-ADVT`? |
|---|---|
| `EnumServicesStatusExW` | no |
| `HKLM\SYSTEM\CurrentControlSet\Services\ACE-ADVT` | absent |
| `sc query ACE-ADVT` | error 1060, "does not exist" |
| `driverquery` | not listed |
| **WMI `Win32_SystemDriver`** | **yes** — empty `PathName`, `ServiceType` and `StartMode` all `Unknown` |

The `.sys` files were gone from disk and the machine had not rebooted.

A scanner built on WMI would therefore report an anti-cheat driver present after
it had been completely removed — and for this tool that means offering to remove
something that is not there, on a machine the user was told is not clean. SCM is
the authority; WMI is a cache with its own opinion.

### Not SCM alone

SCM is the authority on the services it manages, and a driver does not have to
be one of them. The 2026-10-09 cycle found two that are not
(`observations/2026-10-09-ea-anticheat/`; the second is in the same cycle's
baseline, whose own observation follows):

| Driver | Its `Services` key | `sc query` | Image |
|---|---|---|---|
| EA AntiCheat's `EAAntiCheat`, a file-system minifilter | complete: type, start, error control, image, group, instance and altitude | error 1060 in the boot it was installed in; listed after a restart | absent while no game runs |
| Neverness To Everness's `PGameProtectDriver` | `ImagePath`, `Type` and `Start` only, none of the values `CreateService` always writes; its launcher rewrites `ImagePath` when it runs | error 1060, before and after a restart | at the baseline, on a drive the machine no longer had; re-pointed at the game's current install once it ran |

Both keys were written into `HKLM\SYSTEM\CurrentControlSet\Services` without
going through SCM. The filter manager and `NtLoadDriver` read a key there
directly and need no SCM record, so such a driver can load. SCM reads the key
only at boot. So EA's complete key was missing from `EnumServicesStatusExW` until
the machine restarted. NTE's incomplete one is never listed at all.

So:

- **Enumeration reads the `Services` key as well as asking SCM.** A key whose
  `Type` is a driver type (1, 2 or 8) that SCM does not name is a registry-only
  driver, and its record comes from the registry alone: there is no
  `QueryServiceConfigW` to call.
- **Removal cannot go through `DeleteService`** for such a key, since SCM has
  nothing to delete. How Stage 3 removes one is not decided yet
  ([`06`](06-REMOVAL-PIPELINE.md)).
- **A missing image is not evidence of removal.** EA's driver has no image on
  disk while no game runs, and its key is still the anti-cheat's. An absent file
  under a present key is the normal state of that driver, not an orphan.
- **Nor is SCM's word after an uninstall.** EA's uninstaller deleted the
  minifilter's key the way the installer wrote it, past SCM, and until the next
  boot SCM kept an entry: `OpenService` still succeeds, and every query fails
  with error 2. A scan that believes SCM there reports a driver that is gone,
  the same mistake `Win32_SystemDriver` made above.

The observation harness found the same blind spot first: the snapshot's
services domain is SCM's view, and `suggest` now looks for registry-only drivers
in the registry diff (`docs/16`).

## Authenticode verification

`WinVerifyTrust` with `WTD_UI_NONE`, `WTD_REVOKE_WHOLECHAIN`, then extract the
signer CN via `CryptQueryObject` / `CertGetNameStringW`.

Cached **per scan volume** by `(file_id, size, mtime)` for the session — file ID
rather than path, so a file reached through two paths is verified once. See
[`10`](10-PERF-BUDGET.md). Verification is the expensive step, so it runs only
after Bloom + Aho–Corasick have narrowed the set.

> No volume serial number is read. The cache is partitioned by the volume being
> walked, which the scanner already knows, so file identity needs nothing else.
> `GetVolumeInformationW` is not called anywhere, and
> `BY_HANDLE_FILE_INFORMATION.dwVolumeSerialNumber` and
> `FILE_ID_INFO.VolumeSerialNumber` are not read even though they arrive free on
> a handle already open. See [`02`](02-SAFETY-GATE.md) §Grey areas and rulings;
> enforced by `core/tests/no_destructive_code.rs`.

Expired certificates on old anti-cheat builds are **normal** and are not
downgraded — countersigned timestamps are honoured.

> **Offline, as built (2026-10-30).** WardSweep makes no network call
> ([`19`](19-ROADMAP.md)), so `WTD_REVOKE_WHOLECHAIN` goes with
> `WTD_CACHE_ONLY_URL_RETRIEVAL`: revocation is checked against what the
> machine has cached. A revocation the cache cannot answer does not fail a
> signature that otherwise verifies; one it does know makes it invalid.
> `TRUST_E_NOSIGNATURE` is unsigned only when the last error says the file
> carries no signature, and otherwise an error — the file could not be read.
> The signer's name comes from the embedded signature once it has verified,
> by the same code the observation harness uses. A file signed only through a
> Windows catalog file reads as unsigned, as `WinVerifyTrust` on one file does
> not consult catalogs; anti-cheat binaries carry their own signature. The cache above is not built:
> an audit verifies only the files a catalog names, a handful per anti-cheat,
> and the walk that needs it is not either.

**A verification that fails is unknown, not unsigned.** During the 2026-10-09
baseline, with a snapshot saturating the disk, a signature pass over EA
AntiCheat's files reported one as not signed and another with an unknown error.
With the disk idle both verified: signed by *Electronic Arts, Inc.*,
timestamped. `suspicious` needs a signature that verifies and names the wrong
publisher, or one that is invalid. An error — I/O, a timeout, a chain that cannot
be built — is retried, and an artifact whose publisher still cannot be verified
is `probable`, as one whose file is already gone is. It is never `suspicious` on
the strength of an error, and never `confirmed`. As built, an error is retried
once.

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
**\NTUSER.DAT*  **\USRCLASS.DAT*        user hives, anywhere
C:\ProgramData\Microsoft\**
Users\*\AppData\{Local,LocalLow,Roaming}\Microsoft\**
Program Files\WindowsApps\**  Program Files\Windows Defender\**
HKLM\SYSTEM\**             except <ControlSet>\Services\<catalog-named service>
HKLM\SAM  HKLM\SECURITY  HKLM\BCD*  HKLM\HARDWARE  HKLM\COMPONENTS  HKLM\DRIVERS
HKCC\**
HKLM\SOFTWARE\Microsoft\Cryptography\**  …\Windows NT\CurrentVersion\Winlogon\**
  …\Microsoft\Windows Defender\**  (and the same under SOFTWARE\WOW6432Node)
Driver files and services that ship with Windows — never unlockable by a catalog
Any path resolving to a volume root
Any path traversing a reparse point
Any top-level directory targeted as a whole: Windows, Users, ProgramData,
  Program Files, Program Files (x86), $Recycle.Bin, System Volume Information,
  Recovery, Boot, EFI, PerfLogs — on every drive, not only C:
Any folder that holds other software, targeted as a whole: a profile, its
  AppData roots and standard folders (Documents, Desktop, Saved Games,
  Documents\My Games, …), Common Files, Package Cache, a Steam installation,
  any SteamLibrary, steamapps or steamapps\common, any Epic Games library
Any registry key that holds other software's keys, targeted as a whole:
  SOFTWARE\Microsoft, …\Windows\CurrentVersion, …\Uninstall, …\Run,
  SOFTWARE\Classes, SOFTWARE\Policies, SOFTWARE\WOW6432Node, … — under HKLM
  and under each user's root
Any path with fewer than 2 components under a drive root
Any 8.3 alias that has not been expanded through the filesystem
Any UNC or device-namespace path
Any component made only of dots and spaces, or using NTFS stream syntax (`:`)
```

> **Containers are refused whole, never below.** `C:\Users\<name>` passed the
> depth floor, and so did the root every bare `%LOCALAPPDATA%`, `%APPDATA%` or
> `%USERPROFILE%` expands to, `HKLM\SOFTWARE\Microsoft`, the whole of
> `HKLM\SOFTWARE\WOW6432Node`, and a Steam library three levels down. A catalog
> naming one of those is wrong in every case; a catalog naming something
> *inside* one — `…\Uninstall\<product>`, `%LOCALAPPDATA%\<vendor>`,
> `steamapps\common\<game>` — is the footprint [`02`](02-SAFETY-GATE.md)
> permits removing, and stays allowed. Per-user Start menu shortcuts become
> unremovable, as the all-users ones under `%ProgramData%\Microsoft` always
> were. The exact lists are in `core/src/safety/denylist.rs`.

Carve-outs are earned **per anti-cheat entry**: an entry's declared driver
filenames and service names unlock those two carve-outs for that entry's own
paths and keys, and nothing else. A game entry earns none. Driver files and
service keys are anti-cheat footprint, removed only through the entry that owns
them and only when its reference count allows; a game naming one would remove it
with the game, which is G1.

> **Canonicalisation follows Win32, towards the protected reading.** Checked
> with `GetFullPathNameW` on Windows 11: `C:\ProgramData\Microsoft .` and
> `Microsoft. .` both open `C:\ProgramData\Microsoft`, `C:\ProgramData\...`
> opens `C:\ProgramData`, and `C:\ProgramData\Microsoft::$INDEX_ALLOCATION` is
> the directory itself. All four once canonicalised to something this list
> allowed. Trailing dots and spaces are now stripped in any mix, a component of
> only dots and spaces is refused, and a `:` after the drive letter is refused.
> Each rule can map a spelling onto a protected form, never away from one, and
> catalog validation refuses such spellings outright so a reviewer never has to
> resolve them. Enforced in `core/src/safety/paths.rs` and
> `core/src/catalog/validate.rs`.

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
