# Riot Vanguard — observation notes

Both halves are done: uninstalled by the vendor's own uninstaller, then
reinstalled by the Riot Client. Riot Vanguard is the first anti-cheat observed
here that **leaves something behind** — which makes it the first evidence for
the claim this project is built on, and the amount it leaves is small enough
that saying so honestly matters more than saying so loudly.

It is also the observation that cost the tooling three defects: two harness
blind spots and a wrong assumption in the draft generator, none of which would
have been visible without a second anti-cheat to compare against.

## Pre-state, 2026-08-19

| | |
|---|---|
| Vanguard installer version | 1.18.5-11+20260805.032431 |
| Services | `vgc` — win32, `demand`, `error_control = ignore`; `vgk` — kernel driver, `error_control = ignore` |
| Referencing game | VALORANT, `G:\Riot Games\VALORANT\live` — **refcount 1** |
| Uninstaller | `C:\Program Files\Riot Vanguard\uninstall.exe`, signed *Riot Games, Inc.* |

The stable footprint under `C:\Program Files\Riot Vanguard` is **eight files,
207,097,451 bytes**: seven signed *Riot Games, Inc.* — `vgc.exe` (92 MB),
`vgk.sys` (71 MB), `vgm.exe`, `vgtray.exe`, `log-uploader.exe`, `vgrl.dll`,
`uninstall.exe` — and an unsigned `vgc.ico`. Two more files under
`%LOCALAPPDATA%\Riot Games\Riot Vanguard`. Four registry keys: the two service
keys in both WOW64 views, and the uninstall entry.

> **Correction.** The first version of this note said "eleven files, eight of
> them signed". Both numbers were wrong. Seven are signed, not eight — the same
> sentence then listed seven names. And eleven was a count taken at one moment
> that included whatever log files existed then; the number of logs moves. The
> catalog entry needs the eight stable files, and would have been wrong about
> both figures.

Unlike AntiCheatExpert, **every Vanguard binary carries the vendor's own
Authenticode CN**, including the kernel driver. Signer clustering works fully
here and only half worked there — which is worth knowing before leaning on it.

### The logs rotate, and that is a third thing the reboot explains

| Snapshot | Logs present |
|---|---|
| `vg-00-current`, 13:11 UTC | 8, all dated 2026-08-12 |
| `10-vanguard-baseline`, 13:26 UTC | 3, all dated 2026-08-19 |
| `11-vanguard-baseline-2`, 13:41 UTC | 4, all dated 2026-08-19 |

Every log from the previous week vanished and fresh ones appeared, between two
snapshots fifteen minutes apart. Nothing uninstalled anything: **the machine
restarted, and Vanguard rotated its logs at startup.** Without a recorded boot
session that reads as eight files deleted and three created during an
observation about an uninstall.

## What the uninstaller removed

`uninstall.exe`, run by the maintainer, with the Riot Client closed. No reboot
was demanded and none was needed.

| Domain | Removed |
|---|---|
| Services | `vgc`, `vgk` |
| Registry | `Services\vgc` and `Services\vgk` in **both** WOW64 views, `Uninstall\Riot Vanguard`, the `UFH\ARP` backing entry, and its own `Run` value |
| Files | 12 files, **207,107,759 bytes** — the eight stable ones plus the four logs that happened to exist at that moment |

The `Run` value is worth naming separately:
`HKLM\...\CurrentVersion\Run\Riot Vanguard = "C:\Program Files\Riot Vanguard\vgtray.exe"`
was **deleted**. An autostart entry pointing at a binary the same uninstaller
had just deleted would have been the most user-visible failure available, and
it did not happen.

Nothing was queued in `PendingFileRenameOperations`. The only entry there
belongs to `gamingservicesproxy`, and the second is the empty string that
terminates the list — checked because a pending rename is exactly how a loaded
driver gets deleted across a reboot, which is spike **S1**'s whole subject.
Vanguard did not need one: with the client closed, `vgk` was not loaded.

## What it left behind

Three different authors, and separating them is the entire point.

### Vanguard's own — 2 files and 2 directories

```
C:\Program Files\Riot Vanguard\             empty
C:\Program Files\Riot Vanguard\Logs\        empty
%LOCALAPPDATA%\Riot Games\Riot Vanguard\vgtray-settings.json    607 B
%LOCALAPPDATA%\Riot Games\Riot Vanguard\vgtray.log            2,073 B
```

`vgtray-settings.json` is tray configuration plus the result of a hardware
pre-check the client runs. `vgtray.log` is twenty-three lines, one per tray
start since 2026-08-12, each recording a Direct3D device creation.

Neither is large and neither is harmful. Both are residue by the only
definition that matters here: **the vendor's own uninstaller ran to completion
and they are still on the disk.**

#### G3 held, on a file that would have broken it

`vgtray-settings.json` records whether several platform security features were
present when Vanguard first checked. That is exactly the class of value Safety
Gate G3 forbids WardSweep from reading, *including for reporting*.

The snapshot contains the file's path, size and timestamp and **nothing else**:
`.json` is not in `HASHED_EXTENSIONS`, so it was not hashed, and the filesystem
walk never reads contents at all. The values in it were read by hand, in
PowerShell, by a person deciding what this file was — and they are deliberately
not transcribed here.

Worth stating because the boundary is easy to lose: the harness may record
*that* a file exists without recording what it says, and a residue report can
name a file it is not allowed to open.

### Windows's own — 1 value

`HKCU\...\AppCompatFlags\Compatibility Assistant\Store` still holds an entry
keyed by the path of the now-deleted `uninstall.exe`. AntiCheatExpert left the
same class of thing. It is written by Windows about a program, not by the
program, and a scan must not offer to remove it — the key is shared with every
other application on the machine.

### The observer's own — 1 value

`HKCU\...\Explorer\TypedPaths\url1 = C:\Program Files\Riot Vanguard`.

This is not Vanguard's. It was written by Windows because somebody navigated to
that folder in Explorer during the observation — which is to say, **the
observation wrote it**. It names the anti-cheat, it survives the uninstall, and
a residue scanner that matched on names would report it as Vanguard's with
complete confidence.

That is the strongest argument yet for the attribution rule `suggest` already
enforces. It is also a warning about method: the act of observing changes the
machine, and a diff attributes the change to whatever the observation was
about unless someone looks.

## Correction: the start-type finding had the wrong cause

The previous note recorded that `vgk`'s start type moved
`demand` → `SYSTEM_START` → `demand` and attributed it to the Riot Client being
launched. The movement is real. **The cause was not what was written.**

The machine restarted at 13:16:58 UTC, between the snapshots, and nothing in
either file said so. Corrected timeline:

| When (UTC) | What | `vgk` start type |
|---|---|---|
| 13:11 | snapshot `vg-00-current` | `demand` (3) |
| **13:16:58** | **restart, user-initiated from the Start menu** | — |
| 13:17:49 | boot | — |
| 13:18:38 | `vgtray.exe` runs — autostart, not a manual launch | — |
| 13:20 | `sc qc vgk` | **`SYSTEM_START` (1)** |
| 13:26 | snapshot `10`, services domain | **`system`** |
| 13:30 | snapshot `10`, registry domain | `Start = 3` |
| 13:35 | `sc qc` and registry together | `demand` (3) |

So the driver came up at `SYSTEM_START` after a boot and was lowered to
`demand` about ten minutes later. The conclusions from the original note all
survive — `docs/16` infers `risk` from a value that moves, `docs/06` Stage 3
sets `Start = SERVICE_DISABLED` and then reboots into a window where an
anti-cheat can re-arm itself, and this is direct material for S1 — and one of
them gets stronger, because the movement now demonstrably straddles a restart
rather than a client launch.

The reason the wrong cause went in is that a snapshot did not record which boot
it belonged to. That is fixed below.

## A snapshot is not an instant, and it caught the transition in flight

The row above where the services domain says `system` and the registry says
`Start = 3` is **one file**, describing **one service**. Both readings were
correct. The file implied they were simultaneous.

They were not: a snapshot enumerates services, then walks the filesystem for
several minutes, then walks the registry. The skew between the first and last
domain was **5 minutes 9 seconds** — and the start type changed inside that
window, so the two halves of one file straddle the moment it moved.

Fixed by recording `domain_started_utc` per domain and printing the span.
Recording it does not remove it, and nothing short of a transactional capture
would; Windows offers none across these three domains. What it does is stop the
file making a promise it cannot keep.

## Two things the harness could not see, and now can

Both were found by this observation, both are fixed in it, and both were
invisible in a way that reads as good news rather than as missing data.

### An emptied directory produced no record at all

`Snapshot::files` describes files. `C:\Program Files\Riot Vanguard` survived the
uninstall with nothing in it, so it generated no record on either side and the
diff could not mention it. **The single clearest piece of residue on the
machine was the one thing the tool was structurally unable to report.**

`Snapshot::file_empty_directories` now records directories holding no file
anywhere beneath them, topmost only — an empty `Logs` inside an empty
`Riot Vanguard` is one finding, not two — and `Diff::emptied_directories`
reports the ones that are newly empty.

### A snapshot did not say which boot it belonged to

`Snapshot::boot_session` now records one, derived as wall clock minus
`GetTickCount64`, and `Diff::rebooted_between` compares two of them with a
two-minute tolerance because both halves of that subtraction drift.

Not a Safety Gate G3 concern: a boot instant changes every time the machine
starts and is shared by every machine started at the same moment. It
distinguishes nothing. G3 is about identity, and this is state.

Both fields are `Option`, and both diff answers are `None` rather than empty
when either snapshot predates them. An empty list would read as *nothing was
left behind*, which is the one wrong answer this tool must never give — the
same rule `Coverage` has enforced since the first commit.

### Both were measured before being believed

Snapshots `13` and `14`, seven minutes apart, machine in ordinary use.

| | Measured |
|---|---|
| Empty directories on this machine | **18,216**, costing 2.46 MB — **0.93 %** of a snapshot |
| Where they are | 84 % is one tool's metadata cache, under `%LOCALAPPDATA%` |
| `emptied_directories` noise floor | **0**, in both directions |
| `C:\Program Files\Riot Vanguard` caught | yes; its `Logs` child correctly not listed separately |
| Derived boot instant vs the Windows event log | matched **to the second** |
| Drift between two derived boot instants | **7 ms**, against a 120,000 ms tolerance |
| `rebooted_between` on a pair with no reboot | `false`, and silent |

Two things follow. **No suppression rule was added**, because there is nothing
to suppress: a list of 18,216 that does not move produces a diff that does not
mention it. And the tolerance is not sized for drift — 7 ms would not need
120,000 — but for a clock step such as a time sync. It cannot hide a restart,
because a reboot moves the boot instant forward by the uptime it had at that
moment, and that uptime had to cover the whole of the earlier capture, which
takes minutes.

## Against AntiCheatExpert

| | AntiCheatExpert | Riot Vanguard |
|---|---|---|
| Own residue after its uninstaller | **none** | 2 files, 2 directories |
| Windows-written residue | MuiCache, AppCompat | AppCompat |
| Driver signed by the vendor | no — attestation-signed | **yes** |
| Reboot required | no | no |
| Autostart entry cleaned up | n/a | yes |
| Services removed cleanly | yes | yes |

Two anti-cheats, two tidy uninstallers, and between them about 2.7 KB and two
folders left on disk. **That is the honest scale of the problem so far**, and it
is a long way from what the subject is usually claimed to be. A tool that
promised to clean up after these two would be promising very little.

What the observations have actually produced is different and more useful: a
detection API that reports a driver as present after it is gone (WMI), two
harness blind spots that hid evidence, an anti-cheat that rewrites its own
driver's start type, log rotation and a service-suffix churn that both look
like an installer at work until you know a reboot happened, and a registry
value the observation itself wrote and nearly attributed to its subject. The
value here is in what it takes to know the answer, not in the answer's size.

## The reinstall half

The Riot Client was started at 21:21 local and reinstalled Vanguard without
being asked to. Captured as `15-vanguard-reinstalled` nine minutes later, in the
**same boot session** as `13` and `14` — `rebooted_between` reads `false`, so
nothing in this diff is a restart's doing.

| Domain | Installed |
|---|---|
| Services | `vgc` — win32, `demand`; `vgk` — kernel driver, **`system`** |
| Registry keys | `Services\vgc` and `Services\vgk` in both views; `Uninstall\Riot Vanguard` in the **64-bit view only** |
| Registry values | `Run\Riot Vanguard`, `UFH\ARP\0`, `RunNotification\StartupTNotiRiot Vanguard` |
| Files | 9, **207,105,553 bytes** — the same eight stable files, plus one fresh log |

Byte for byte the same eight files, and a footprint symmetric with the removal.
Whatever else is true of this uninstaller, it puts back exactly what it took.

### `vgk` is installed at `SYSTEM_START`, and the baseline said `demand`

This is the third reading of that value and the first one taken at a known
moment in the software's own lifecycle:

| When | `vgk` start type |
|---|---|
| Four baseline snapshots, machine up for hours | `demand` (3) |
| Minutes after a restart | `system` (1) |
| **Minutes after a fresh install** | **`system` (1)** |

So `system` is what Vanguard *installs*, and `demand` is what the value settles
to. A catalog entry derived from an observation taken hours after an install
records the settled value and calls it the fact.

Two things follow for the catalog, and they pull in opposite directions:

1. **`SYSTEM_START` is not `BOOT_START`.** The diff reports
   `is_boot_start = false`, so `docs/16`'s rule — `SERVICE_BOOT_START` implies
   `risk = critical` — correctly does **not** fire, and the draft says
   `risk = high`. Vanguard's driver loads early, but not in the class that
   forces the reboot stage.
2. **The value a scan happens to read is not the value the installer wrote**,
   and the difference is one step of severity. The inference rule is sound; what
   it is fed is a moment.

### The residue survived a reinstall too

`vgtray-settings.json` and `vgtray.log` under `%LOCALAPPDATA%` still carry their
pre-uninstall timestamps — 20:31:14 and 20:18:38, both from before the
uninstaller ran. The vendor's own reinstall did not reset them either. "The
uninstaller left them behind" understates it: **nothing in the vendor's own
install-uninstall-reinstall cycle touches them at all.**

### `suggest` passed a test signer clustering would have failed

`Riot Games, Inc.` signs the Riot Client as well as Vanguard, and the install
diff contains **51 Riot Client files** alongside the anti-cheat's. Signer
clustering alone — which `docs/16` calls the single most useful signal — would
have pulled the entire launcher into the draft.

It did not. The draft contains `%ProgramFiles%\Riot Vanguard` and three registry
keys, and nothing of the client, because attribution runs on tokens taken from
the service names and the anti-cheat's own directory rather than on the
publisher. This is the first case where the two signals disagree and the
narrower one was right.

### …and `suggest` was wrong about WOW64 views

Every key in a draft was emitted as `view = "both"`, on the stated grounds that
"the observation cannot distinguish *only in one view* from *we only looked
once*". **That was never true of this harness**, which opens both views
explicitly and stamps every record with the one it came from.

Vanguard is the counter-example. `HKLM\SYSTEM` is not WOW64-redirected, so the
two service keys genuinely exist in both views. `HKLM\SOFTWARE` *is* redirected,
so the uninstall entry exists only in the 64-bit view — and the draft claimed
both, which asserts a key nobody observed.

`suggest` now derives the view from what was seen and says so in the review
notes when it narrows. The committed `draft.toml` records `view = "64"` for the
uninstall entry.

### What the draft still cannot say

`suggest` has no input shape for *what survived the uninstall*. Residue is by
definition unchanged between the two snapshots, so it appears in a diff as
nothing at all — neither added nor removed — and can only be recovered by
comparing against a clean baseline, which is exactly what a machine with the
game already installed does not have.

So Vanguard's residue is known to the byte and the draft cannot carry it. The
`--residue` flag exists, and on this machine there is nothing to put in it.
Recorded in `docs/PROGRESS.md` under "Open, needs a maintainer decision".

## Still to do

| Step | What |
|---|---|
| 1 | Baseline — `10-vanguard-baseline`, `11-vanguard-baseline-2` after the timestamp fix — done |
| 2 | Uninstall by the maintainer — done |
| 3 | Snapshot `12-vanguard-uninstalled`, diff — done |
| 4 | Snapshot `13-vanguard-uninstalled-dirs`, the first to record directories and boot session — done |
| 5 | Snapshot `14-noise-floor` and its diff against `13` — done |
| 6 | Riot Client reinstalled Vanguard; snapshot `15-vanguard-reinstalled`, diff, draft — done |
| 7 | A second title carrying Vanguard, so `shared` can be argued about at all — not done |

`draft.toml` is committed and is **a hypothesis, not an entry**. It carries
seven review items, `id` and `display` are placeholders, and `shared = true`
must stay so until a second title has been observed — `docs/04` is explicit that
a wrong `shared = false` is the G1 violation this project exists to prevent.

Raw snapshots are **not** committed. They are at
`%LOCALAPPDATA%\WardSweep\observations\`. The redacted diffs the draft was
derived from are: `install.json` (`14` → `15`) and `residue.json`
(`11` → `12`).
