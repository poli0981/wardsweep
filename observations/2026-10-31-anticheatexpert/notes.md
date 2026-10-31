# AntiCheatExpert (ACE) under Stella Sora and Arknights: Endfield — observation notes

ACE's third observation. It answers two questions the 2026-10-10 notes left
open. The first was what a second title does to an ACE that is already
installed. The second was what ACE's install looks like when a different title
installs it on a machine without it. That second footprint is the input
`observe intersect` had been waiting for. `shared.json` is its first result on
real data.

## What was observed

| | |
|---|---|
| Cycle | 2026-10-31, four snapshots in one boot (started 08:34:33Z), 11:04–11:33Z, elevated |
| Titles | Stella Sora (Steam app 4813850) and Arknights: Endfield (Steam app 4732690), both in a library on `D:` |
| ACE at the start | 28.6.2606.970, installed by Wuthering Waves; its uninstall entry names Wuthering Waves' `ACE-Setup64.exe` |
| ACE at the end | 29.6.2608.998, installed by Endfield |
| Harness | the collector pinned for the cycle (SHA-256 `455b8034…`, built from `c3e1532`); diffed, redacted, intersected and drafted by the build with this cycle's harness fixes |

| Snapshot | Taken | State |
|---|---|---|
| `00-ace-installed` | 11:04:14Z | ACE 28.6 installed and stopped, no game running |
| `01-after-stella-sora` | 11:12:13Z | after Stella Sora's first launch, played past login and closed |
| `02-after-ace-uninstall` | 11:16:30Z | after ACE's own `Uninstaller.exe` |
| `03-after-endfield` | 11:29:14Z | after Endfield's first launch, played past login and closed |

Every window is a few minutes long and in one boot (`rebooted_between: false`).
Steam, the EA app and the usual background applications were running, but
there is little churn.

| File | Diff | |
|---|---|---|
| `install.json` | 02→03 | Endfield's install of ACE 29.6, from a machine without ACE |
| `residue.json` | 01→02 | ACE 28.6's uninstall by its own uninstaller |
| `shared.json` | intersection | what this footprint and `observations/2026-10-10-anticheatexpert/install.json` both hold |
| — | 00→01 | Stella Sora on the installed ACE: kept locally, see below |

## The ACE each title carries

Four titles in the library ship ACE in their own folders:

| Title | Steam app | `ACE-Setup64.exe` | `pld.dat` in its ACE folder |
|---|---|---|---|
| Wuthering Waves | 3513350 | 28.5.2606.276 | 110,494 bytes, written 2026-10-10 03:27:10Z |
| NTE: Neverness to Everness | 4508340 | 18.4.2501.194 | none |
| Stella Sora | 4813850 | 18.4.2501.194 | none |
| Arknights: Endfield | 4732690 | 29.6.2608.292 | 7,209 bytes, written 2026-10-31 11:20:15Z |

Stella Sora's payload and NTE's share `ACE-Setup64.exe`, `ACE-Service64.exe`
and `ACE-BASE.sys` byte for byte. Their `ACE-Base64.dll` and `ACE-CORE.sys`
differ: each is a per-title build of the same release.

`pld.dat` appears in a title's ACE folder when that title installs ACE.
Endfield's was written three seconds after the last of its four installs.
Wuthering Waves' carries the time of the install the 2026-10-10 observation
recorded, six seconds after it. The two titles that never installed ACE here
have none.

## Stella Sora on an installed ACE: nothing

Diff 00→01. Stella Sora ran past login into the game; its own settings key
changed, and its folder gained nine files. Of ACE's, **nothing changed**:
- no service;
- no file — every installed file kept its hash and its write time;
- no key, and no empty key;
- no install event in SCM's log;
- no `pld.dat`.

The same happened with NTE on 2026-10-10. Both titles carry ACE 18.4 and ran
beside a newer installed ACE (28.6). One run each cannot tell apart three
explanations: they never engage ACE, they engage it only past a point these
runs did not reach, or they defer to a newer ACE already installed.

The diff is kept locally rather than committed. Nothing in it is ACE's, and it
carries the game's settings key, whose value names begin with the player's
account number.

## The uninstall: nothing of ACE's left, a third time

`residue.json`, 01→02. `Uninstaller.exe` is a byte copy of Wuthering Waves'
`ACE-Setup64.exe`, and it removed:
- both services and their keys in both views, `ACE-BASE\Final` and
  `AntiCheatExpert Protection\Security` included;
- the uninstall entry;
- all seven files, and both directories;
- both per-user keys, under `{4324E6D9-…}` and `{F63EEEBB-…}\Tencent\6095005`;
- three empty keys: `CrashDumps`, `{5FCF1253-…}` and
  `HKCU\SOFTWARE\appdatalow\software`.

Snapshot 02 holds no file, directory, key, empty key or service that names ACE.
`HKCU\SOFTWARE\appdatalow` is left standing and empty. That matches
2026-10-10, where the same key was shown to predate ACE's install.

**No SCM events this time.** On 2026-10-10 the uninstaller logged 7045 for both
services before removing them. This time the System log has no Service Control
Manager event at all between 11:15:16Z and 11:16:30Z. The earlier finding, that
an ACE uninstall writes the same two install events, held for that run only.

## Arknights: Endfield installs ACE 29.6

`install.json`, 02→03, from a machine with no ACE on it.

### How it got there

The Service Control Manager's install events (7045, System log, read-only):

| UTC | Installed | By |
|---|---|---|
| 11:20:09.997 | `AntiCheatExpert Protection`, user mode, `demand`, LocalSystem, `"C:\Program Files\AntiCheatExpert\ACE-Service64.exe" -autorun` | the signed-in account |
| 11:20:10.086 | `ACE-CORE1024303`, kernel driver, `demand`, `C:\Program Files\AntiCheatExpert\ACE-CORE1024303.sys` | SYSTEM |
| 11:20:10.173 | `ACE-CORE2024303`, kernel driver, `demand`, `C:\Program Files\AntiCheatExpert\ACE-CORE2024303.sys` | SYSTEM |
| 11:20:12.931 | `ACE-ADVT`, kernel driver, `demand`, `C:\WINDOWS\system32\drivers\ACE-ADVT.sys` | the signed-in account |

At install, the two core drivers' display names carry the title's id, `24303`.
The registry then reads `ACE-CORE` for both.

### The footprint

| Kind | Observed |
|---|---|
| Services | `AntiCheatExpert Protection`: own process, interactive, `demand`. `ACE-ADVT`, `ACE-CORE1024303`, `ACE-CORE2024303`: kernel drivers, `demand` |
| Files | `C:\Program Files\AntiCheatExpert`: `ACE-BASE.sys`, `ACE-Service64.exe`, `Uninstaller.exe`. `C:\ProgramData\AntiCheatExpert\ace-drc.dat`, 579,554 bytes, unsigned. `System32\drivers\ACE-ADVT.sys`, 1,168,048 bytes |
| Registry | the four service keys in both views, with `AntiCheatExpert Protection\Security`; the uninstall entry, 64-bit view only; `HKCU\SOFTWARE\appdatalow\AntiCheatExpert\{D15B7548-…}\Tencent`; three keys left empty, `CrashDumps`, `{F39D31EB-…}` and `appdatalow\software` |
| In the game's folder | `AntiCheatExpert\pld.dat`, 7,209 bytes, unsigned |

`ACE-BASE.sys`, `ACE-Service64.exe` and `Uninstaller.exe` are byte copies of
Endfield's payload; once more, the installer doubles as the uninstaller.
`ACE-ADVT.sys` and `ace-drc.dat` match no file in any of the four titles'
payloads. Signatures are as before: the drivers carry Microsoft's attestation
signature and the two executables carry *ACEVILLE PTE LTD*.

### 29.6 is not 28.6

| | 28.6.2606.970 (Wuthering Waves, 2026-10-10) | 29.6.2608.998 (Endfield) |
|---|---|---|
| Kernel driver services | `ACE-BASE`, in `System32\drivers` | `ACE-ADVT`, in `System32\drivers`; `ACE-CORE1024303` and `ACE-CORE2024303`, in Program Files |
| `ACE-BASE.sys` | in Program Files and in `System32\drivers`, registered | in Program Files only, not registered |
| Core drivers | files, not registered: `ACE-CORE106095005.sys`, `ACE-CORE206095005.sys` | registered as services, and their images are **not on disk** while the game is closed |
| Title id | `6095005`, also a key: `{F63EEEBB-…}\Tencent\6095005` | `24303`, in the core drivers' names and nowhere else |
| Per-user state | `{4324E6D9-…}\Tencent`; empty `{5FCF1253-…}` | `{D15B7548-…}\Tencent`; empty `{F39D31EB-…}` |
| `ACE-BASE\Final` | present | absent |
| The service's security descriptor | Windows' default for a service, plus `(A;;RPWPSDRC;;;WD)`: anyone may start, stop or delete it | `D:(A;;…;;;SY)(A;;…;;;BA)`: SYSTEM and Administrators only, so an unelevated query is refused (5) |

The per-user GUIDs are ACE's own key names, not identifiers of this machine's
user. `{4324E6D9-…}` and `{D15B7548-…}` were both already in August's diff,
under ACE 28.0.

### The title's id

The core drivers are named `ACE-CORE1` or `ACE-CORE2`, then a `0`, then the
title's id. Wuthering Waves' id is `6095005`, the same under 28.0 in August and
under 28.6 in October, so it identifies the title, not a version. Endfield's is
`24303`. Each title's pair therefore has names of its own. Under 29.6 they are
services as well as files, so a catalog entry that covers every title needs a
pattern for service names too, not only for driver files. `suggest` now points
this out from the pair of names alone, because 29.6 writes the id nowhere else.

### After the game closed

Read with `sc query`, unelevated:
- `ACE-ADVT`, `ACE-CORE1024303` and `ACE-CORE2024303` are stopped;
- the two core images are not on disk;
- `AntiCheatExpert Protection` refuses the query.

A key whose image is missing is what `docs/05` already tells the scanner not to
call a removal; that rule was written for EA's minifilter.

## What both installs share

`shared.json` is the intersection of the two footprints, matched by identity:
service name, file path, and key with its view. **ACE's part of it** is:
- the service `AntiCheatExpert Protection` and its key, in both views;
- the uninstall entry, 64-bit view;
- `ACE-BASE.sys`, `ACE-Service64.exe` and `Uninstaller.exe` in
  `C:\Program Files\AntiCheatExpert`;
- `C:\ProgramData\AntiCheatExpert\ace-drc.dat`;
- the empty `CrashDumps` and `appdatalow\software` keys.

**No kernel driver service is in both.** The drivers change from one version
to the next, and the core pair from one title to the next.

The remaining 33 files and 37 keys are churn both windows happened to share:
Steam's logs, browser beacons, Windows notification and update state. Matching
by identity cannot tell such churn from footprint; a third title would thin it.

`AntiCheatExpert Protection\Security` is in Endfield's footprint, but on
2026-10-10 the key was recorded as unreadable. The intersection therefore
cannot show it: that is a gap in what was seen, not a difference between the
installs.

`suggest` run on `shared.json` drafts:
- the service `AntiCheatExpert Protection`;
- the driver `ACE-BASE.sys`;
- both folders;
- the uninstall entry and the service key.

That is the part of ACE every observed install had. A test pins `shared.json` to
the two committed footprints.

## What else the windows caught

- A CPUID SDK driver, `cpuz163`. SYSTEM installed it under a random file name in
  `C:\ProgramData\CPUID Software\sdk\` during both game sessions (11:08:31Z and
  11:20:36Z), as it had on earlier days, and it was gone before the next
  snapshot. It is in neither diff: a driver that comes and goes between two
  snapshots shows only in the event log.
- Endfield downloaded about 3.5 GB into its own folder, and wrote crash-report
  stubs, its launcher's browser profile and shader caches.
- Windows diagnosed a heap leak in `Endfield.exe` (RADAR).

## Privacy

The diffs were computed, redacted and drafted by the build with this cycle's
harness fixes. These windows prompted every one of those fixes:
- Credential Manager's saved credentials, and the identity cache Windows keeps
  for signed-in accounts;
- Google Drive for desktop's folder, named after the account's identifier;
- the packaged Claude app's data folder;
- a game SDK's identifier for the installation, `Gryphline\sdk_data`;
- the account's, the character's and a session's identifiers in Endfield's
  settings key, under the hashed names Unity writes. `redact` reads past the
  hash now.

| | `install.json` | `residue.json` |
|---|---|---|
| Registry records removed by the policy | 2 | 0 |
| File records removed by the policy | 92,518 | 92,518 |
| Account names masked | 276 | 31 |
| Machine SIDs masked | 6 | 7 |
| Identifiers masked | 22 | 3 |

One identifier was supplied with `--also-id`: an application folder named after
a developer account. `observe review` still lists the following, and each was
read and left as it is:
- Unix timestamps in Endfield's crash-report names;
- content hashes in shader caches, Endfield's resource store and a driver
  package;
- Windows Spotlight's cache ids in keys the walk could not read;
- ACE's per-user GUIDs;
- a container layer's GUID.

## The draft

```
wardsweep-observe suggest --diff install.json --signer "ACEVILLE PTE LTD"
```

- `kind = "kernel"`, `risk = "high"`.
- Three services: `AntiCheatExpert Protection` and the two core drivers.
- Three drivers: `ACE-BASE.sys` and the core pair.
- `%ProgramFiles%\AntiCheatExpert` and `%ProgramData%\AntiCheatExpert`.
- Five registry keys.

`ACE-ADVT` is left out, because nothing in the diff ties it to the publisher:
its file sits in `System32\drivers` and carries Microsoft's signature. The
evidence that it is ACE's is outside the diff:
- the same account installed it three seconds after `AntiCheatExpert
  Protection`, in the same run;
- it is named like the rest;
- August's observation saw it beside ACE 28.0.

A reviewer adds it back. `suggest` also names the core pair as per-title
drivers, and the 182 files in Endfield's own folder as the game's. `shared`
stays `true`. A test pins the draft to `install.json`.

## Still to do

1. **A second title that engages ACE on an installed one.** Wuthering Waves
   carries 28.5 and Endfield's 29.6 is installed now. Launching Wuthering Waves
   would show whether it adds its own core pair, replaces the install, or
   leaves it alone.
2. **29.6's own uninstall.** This version registers drivers whose images are
   absent, and its service refuses unelevated queries.
3. **Stella Sora on a machine without ACE.** This would show whether a title
   carrying 18.4 installs ACE at all.
4. Per-title names now cover services as well as driver files. The schema
   decision (`docs/04`) is the maintainer's.
5. In the PR that adds the catalog entry, paste `signtool verify /v /pa` for
   every binary (`docs/16` checklist).
