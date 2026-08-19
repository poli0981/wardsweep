# AntiCheatExpert — observation notes

Anything the tooling could not capture, per
[`docs/16`](../../docs/16-OBSERVATION-HARNESS.md) §Storage.

## What this observation is

The full **uninstall-and-reinstall cycle** from `docs/16`, run on a machine
where the game was installed before the harness existed.

The referencing game is **Neverness To Everness**, a 68.6 GB Steam title at
`D:\another\bbb\Neverness To Everness`. ACE keeps nothing inside the game
directory — everything lives in `C:\Program Files\AntiCheatExpert` and
`System32\drivers` — so the cycle costs an ACE reinstall, which the game
performs on next launch, and **not** a 68.6 GB game reinstall.

Both diffs are therefore available: the residue the uninstaller leaves, and the
true install footprint.

### Three attempts at the refcount, and only the third was right

Worth recording in full, because determining "which installed games reference
this anti-cheat" is the whole of spike **S2**, and it took three tries by hand
on a machine with the answer sitting on it.

**Attempt 1 — "orphan". Wrong.** Scanning `C:\Program Files`,
`C:\Program Files (x86)`, `D:\SteamLibrary`, `E:\steam-f2p-extension` and
`D:\another\epic` turned up no game using ACE, so the conclusion was that its
game had already gone. The game was in `D:\another\bbb\`, a library path none
of those covered, and the maintainer had to supply it.

**Attempt 2 — "Neverness To Everness only". Incomplete, by luck.** With the game
named, the refcount looked like 1. But ACE's own uninstall entry says:

```
DisplayIcon = D:\SteamLibrary\steamapps\common\Wuthering Waves\Client\
              Binaries\Win64\AntiCheatExpert\ACE-Setup64.exe
```

which names a *different* game — implying a refcount of at least 2.

**Attempt 3 — refcount is 1, and the registry value is stale.** Wuthering Waves
is **not installed**. That path does not exist. The uninstall entry still points
at the game that installed ACE, and was not updated when that game was removed.
Neverness To Everness carries its own copy of the installer, at
`…\Client\WindowsNoEditor\HT\Binaries\Win64\AntiCheatExpert\ACE-Setup64.exe`,
and is the only current referrer.

Three findings for S2, all concrete:

1. **Absence of a game in the libraries you thought to look in is not evidence
   of absence.** A refcount resolver must enumerate library paths from launcher
   manifests, never from a list of likely directories.
2. **An anti-cheat's own uninstall entry names the game that installed it, not
   the games that currently need it, and is not updated when that game is
   removed.** Using it as refcount evidence would have over-counted here. It is
   still useful — it is what revealed Wuthering Waves had ever been involved —
   but only as a lead to verify, never as a count.
3. **Over-counting is the safe direction and under-counting is the G1
   violation.** Attempt 1 under-counted, and would have declared an orphan for
   an anti-cheat a game still needs. `docs/13` S2 already requires the refcount
   to "err toward over-counting when evidence is ambiguous"; this is what that
   costs and why.

### Wuthering Waves left a kernel anti-cheat behind

A secondary observation, and the project's founding claim in miniature: the game
that installed ACE has been uninstalled, and ACE — two kernel drivers, a
`LocalSystem` service and 15 MB under `C:\Program Files` — is still here. It is
not removable in this case, because another game now references it. But nothing
about the uninstall told the user it had been left.

### A third anti-cheat nobody was looking for

The baseline also found **EA Javelin Anticheat** — `EAAntiCheatService`, at
`C:\Program Files\EA\AC\`, 460 MB across four files — which no amount of
looking for "ACE" or "Vanguard" would have surfaced. Three kernel-class
anti-cheats on one ordinary developer machine, found by enumerating rather than
by searching for names already known. That is the argument for a catalog built
from observation instead of from a list.

## Pre-state, 2026-08-19

Recorded before anything was touched.

| | |
|---|---|
| Windows | 11 Pro 10.0.29648 |
| ACE version, per the uninstall entry | 28.0.2604.938 |
| Services | `ACE-BASE` and `ACE-ADVT` — kernel drivers, start `demand`, **stopped**; `AntiCheatExpert Protection` — `LocalSystem`, `demand` |
| Uninstaller | `C:\Program Files\AntiCheatExpert\Uninstaller.exe` |
| Referencing game | Neverness To Everness, `D:\another\bbb\`, 68.6 GB, carries its own `ACE-Setup64.exe` |
| Refcount | **1**, verified three ways — see below |
| Previously referenced by | Wuthering Waves, now uninstalled; ACE was left behind |

Footprint as the baseline recorded it. **Every line here came from the snapshot;
three of these were missed by checking the machine by hand first** — the
`ACE-ADVT` service, the `AntiCheatExpert Protection` service, and `ace-drc.dat`.

| Path | Signer | Size |
|---|---|---|
| `C:\Program Files\AntiCheatExpert\ACE-BASE.sys` | MS Hardware Compatibility | 4 230 360 |
| `C:\Program Files\AntiCheatExpert\ACE-CORE106095005.sys` | MS Hardware Compatibility | 3 885 704 |
| `C:\Program Files\AntiCheatExpert\ACE-CORE206095005.sys` | MS Hardware Compatibility | 3 235 392 |
| `C:\Program Files\AntiCheatExpert\ACE-Service64.exe` | **ACEVILLE PTE LTD** | 3 251 088 |
| `C:\Program Files\AntiCheatExpert\Uninstaller.exe` | **ACEVILLE PTE LTD** | 899 984 |
| `C:\ProgramData\AntiCheatExpert\ace-drc.dat` | none | 2 419 092 |
| `C:\WINDOWS\System32\drivers\ACE-BASE.sys` | MS Hardware Compatibility | 4 230 360 |
| `C:\WINDOWS\System32\drivers\ACE-ADVT.sys` | MS Hardware Compatibility | 1 149 112 |

Registry: ten keys under `HKCU\SOFTWARE\appdatalow\AntiCheatExpert\{GUID}\`
across three GUIDs, in both WOW64 views, plus the uninstall entry and two
service keys.

**The `System32\drivers\ACE-BASE.sys` copy has the same SHA-256 as the one under
Program Files** (`4423d3ed7bd1b988…`), so the driver is staged rather than
built per-machine.

### Signer clustering only half works here

The drivers are signed by *Microsoft Windows Hardware Compatibility Publisher* —
attestation signing, normal for a third-party driver — so they do **not** cluster
with the vendor. Only `ACE-Service64.exe` and `Uninstaller.exe` carry the real
vendor CN, **ACEVILLE PTE LTD**, and those two are the *only* files on the whole
machine signed by it.

`docs/16` calls signer clustering "the single most useful signal". On an
attestation-signed driver it is not a signal at all, and an entry that leaned on
it would miss every `.sys` file in the footprint. Worth stating in
`docs/16` rather than discovering twice.

## Two things a guessed catalog entry would get wrong

1. **The driver file names carry a version.** `ACE-CORE106095005.sys` and
   `ACE-CORE206095005.sys` embed `06095005`, which also appears as a registry
   subkey (`…\AntiCheatExpert\{GUID}\AntiCheatExpert\6095005`). An entry that
   hardcodes these names matches one build and silently misses every other. Any
   entry derived from this observation needs a pattern, or needs to rely on
   `ACE-BASE.sys` plus the directory.
2. **The driver is `demand` start, not boot.** Worth recording because the same
   was true of `vgk` on this machine, against the common assumption.

## Coverage gaps in the harness at the time of this run

Stated so the diff is not read as more complete than it is.

- **Three** of seven domains are captured: services, filesystem, registry.
  Scheduled tasks, firewall rules, event log sources and environment are
  **not** — and every snapshot and diff says so in its own `coverage` field,
  which is where the authoritative answer lives rather than here.
- The filesystem walk covers `%ProgramFiles%`, `%ProgramFiles(x86)%`,
  `%ProgramData%`, `%LOCALAPPDATA%`, `%APPDATA%` and `System32\drivers`. It does
  **not** cover other volumes, so anything ACE left on `D:`, `E:` or `G:` is
  invisible here.
- Snapshots were taken on a machine in ordinary use rather than freshly booted
  and idle, which `docs/16` §"Reducing noise" asks for. The measured baseline
  for that condition is 18 unrelated file changes over five minutes, all
  application state; anything at that scale in the diff is not ACE.

## Result: the uninstaller left nothing of its own

`Uninstaller.exe` removed **its entire footprint**:

| | Removed |
|---|---|
| Services | 3 — `ACE-BASE`, `ACE-ADVT`, `AntiCheatExpert Protection` |
| Files | 8, including both copies of `ACE-BASE.sys` |
| Registry keys | 19, across both WOW64 views |

Nothing under `C:\Program Files\AntiCheatExpert`,
`C:\ProgramData\AntiCheatExpert` or `System32\drivers` survived, and no service
key remained.

### What did survive is Windows, not the vendor

Six registry values, in two keys across both views:

```
MuiCache :: ...\Temp\xido.0.exe.ApplicationCompany = ANTICHEATEXPERT.COM
MuiCache :: ...\Temp\xido.0.exe.FriendlyAppName    = ACE-Setup exe
AppCompatFlags\Compatibility Assistant\Store ::
        C:\Program Files\AntiCheatExpert\Uninstaller.exe
```

All six are **written by Windows**, not by the vendor: the shell's cached
display strings for an executable that ran, and the Program Compatibility
Assistant's record that the uninstaller executed.

**These should not go in a catalog entry.** They are not the anti-cheat's
footprint; they are the operating system's record that it existed. Removing
`MuiCache` and `AppCompat` entries is what a registry cleaner does, and
[`19`](../../docs/19-ROADMAP.md) lists "registry optimiser, junk cleaner, PC
booster" under *explicitly not planned* - "different product, different (worse)
trust model".

### So the honest finding is a negative one

**ACEVILLE's uninstaller is clean.** A project that exists to sweep residue has
to be able to say that, and say it as readily as it says the opposite. On this
machine, for this version, there was no residue to sweep.

That does not make an ACE catalog entry pointless - it makes it an *orphan*
entry. If the referencing game is removed, ACE stays behind exactly as observed
here, because nothing uninstalls it but its own uninstaller. That is the
[`02`](../../docs/02-SAFETY-GATE.md) grey-area case ruled **allowed**: refcount
0, Orphan Sweep, the primary use case.

### What the draft got wrong before it got it right

`suggest` was run twice. The first draft proposed
`%SystemRoot%\System32\drivers` as a path, along with a running application's
`leveldb` directory and a token-broker cache - ordinary machine churn between
the two snapshots, swept in because every added path was taken.

The deny-list would have refused that entry at runtime, so the harm was bounded.
But a reviewer reading the draft could not have known that, which is the
failure. Two changes followed:

- a path or key must be **attributable** to the anti-cheat, by publisher
  signature, by being an observed service's image, or by living in a directory
  the anti-cheat names;
- the draft is checked against the **same deny-list the broker enforces**, with
  the same `Exceptions` its own `services` and `drivers` fields would unlock.

The second point matters more than it looks. Validating with `Exceptions::none()`
made the generator refuse the service keys the entry itself declares -
technically correct, practically wrong, and it would have taught a contributor
to delete three correct lines.

## WMI disagrees with SCM about what was removed

Found while checking whether the uninstall had really taken. Immediately after
`Uninstaller.exe` ran, with no reboot:

| Source | Reports `ACE-ADVT`? |
|---|---|
| `EnumServicesStatusExW` (what the harness uses) | no |
| `HKLM\SYSTEM\CurrentControlSet\Services\ACE-ADVT` | absent |
| `sc query ACE-ADVT` | error 1060, "does not exist" |
| `driverquery` | not listed |
| **WMI `Win32_SystemDriver`** | **yes**, with empty `PathName` and `ServiceType`/`StartMode` both `Unknown` |

The `.sys` files were gone from disk. The obvious hypothesis — that the driver
was still resident in the kernel because no reboot had happened — does not hold:
`driverquery` enumerates loaded drivers and does not list it either.

So WMI is returning a stale entry, and **a detection engine built on
`Win32_SystemDriver` would report an anti-cheat present after it was fully
removed.** Recorded in [`05`](../../docs/05-DETECTION-ENGINE.md), which already
specified `EnumServicesStatusExW` but did not say why the easier API is wrong.

Two things were nearly recorded as findings and were not, because the evidence
did not support them:

- *"the driver is still loaded"* — `driverquery` refutes it.
- *"471 drivers exist in WMI but not in SCM"* — an artifact of comparing against
  `Get-Service | Where ServiceType -match 'Driver'`, which returns nothing in
  PowerShell 7. The number meant nothing.

Both are written down because a record that only keeps the conclusions that
survived teaches nobody which checks were worth running.

## The reinstall half is still pending

Two attempts, neither of which installed anything:

- **`02-launcher-ran`** — the launcher ran and patched. It downloaded fresh ACE
  payload into the game directory (`ACE-Base64.dll`, `ACE-CORE.sys`,
  `ACE-CORE.sys2`) but installed nothing machine-wide. Diff against
  `01-uninstalled`: one Windows gamepad driver, some Qt cache, and ordinary
  churn. **No ACE.**
- **`03-game-frontend-ran`** — the game frontend ran and stopped at a resource
  repair prompt (`loadCheckDirListAndCheck … code:-34`). The client itself never
  started. **Still no ACE.**

That is itself worth knowing: **the launcher does not install the anti-cheat,
and neither does the frontend. The game client does.** A machine can therefore
hold a game that is installed, patched and ready to play while its anti-cheat is
entirely absent — so the presence of a game does not imply the presence of its
anti-cheat, which is the converse of the refcount question and matters to how a
scan reports "clean".

Snapshots are named for what they are rather than for what they were meant to
be. Calling `02` a reinstall when nothing was reinstalled is the kind of label
this whole design exists to avoid.

## A note on what is committed here

Only one diff was taken: `00-current` to `01-uninstalled`, committed as
`residue.json`. `draft.toml` was generated from the **same data reversed**, so
that the removals read as additions and `suggest` could see a footprint.

There is deliberately no `footprint.json`. It would be that same diff under a
second name, and two files implying two independent observations is worse than
one file that says what it is. The true install footprint arrives with the
reinstall, at step 7.

## Timeline

| Step | What | When |
|---|---|---|
| 1 | `00-current` snapshot taken | 2026-08-19 |
| 2 | Uninstall via `Uninstaller.exe` — **run by the maintainer, not by WardSweep**; no reboot required | 2026-08-19 |
| 3 | `01-uninstalled` snapshot | 2026-08-19 |
| 4 | Diff `00-current` → `01-uninstalled`: what the uninstaller removed, and what it left | 2026-08-19 |
| 5a | Launcher run — patched the game, installed nothing (`02-launcher-ran`) | 2026-08-19 |
| 5b | Game frontend run — stopped at a resource repair prompt, installed nothing (`03-game-frontend-ran`) | 2026-08-19 |
| 5 | Get the game **client** to run, so it installs ACE | pending |
| 6 | `04-reinstalled` snapshot | pending |
| 7 | Diff `01-uninstalled` → `04-reinstalled`: the true install footprint | pending |

Raw snapshots are **not** committed: they list every file under the profile.
They are kept at `%LOCALAPPDATA%\WardSweep\observations\`.
