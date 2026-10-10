# AntiCheatExpert (ACE), installed by Wuthering Waves — observation notes

The second observation of ACE, and the first of its **install**. The August
observation (`observations/2026-08-19-anticheatexpert/`) saw ACE leave this
machine through its own uninstaller. This one sees it arrive, from a baseline
with no ACE on the machine, installed by a different title.

That makes ACE the first anti-cheat observed here with two titles behind it:
Neverness To Everness in August, Wuthering Waves now. One title is not enough to
set `shared = false`, and two is only the start of an argument for it.

## What was observed

| | |
|---|---|
| Game | Wuthering Waves on Steam, app 3513350, in a library on `D:`. Installed 2026-10-09 18:06Z, after the "before" snapshot |
| Before | `01-after-fc26`, 2026-10-09 16:37Z: no ACE service, driver, directory or key |
| After | `02-after-ww`, 2026-10-10 04:13Z: after two sessions of the game, with the game closed |
| Anti-cheat version | 28.6.2606.970, from its uninstall entry. The August observation saw 28.0.2604.938 |
| Harness | the collector pinned for this cycle (SHA-256 `fdc1b7d2f192b786…`); diffed, redacted and drafted by the build with #52 |

The window is long: eleven and a half hours, a restart, and a machine in
ordinary use. The diff says so (`rebooted_between: true`), and most of it is
churn. Steam, the EA app and another launcher were running when the "after"
snapshot was taken. The anti-cheat's own part is small and stands out.

## How it got there

The Service Control Manager's install events (7045, System log, read-only):

| UTC | Installed | By |
|---|---|---|
| 2026-10-10 03:27:04 | `AntiCheatExpert Protection`, `"C:\Program Files\AntiCheatExpert\ACE-Service64.exe" -autorun` | the signed-in account, through an elevated installer |
| 03:27:05 | `ACE-BASE`, `C:\WINDOWS\system32\drivers\ACE-BASE.sys` | SYSTEM, a second later |

That was the game's first launch. The installer is the game's own payload at
`Client\Binaries\Win64\AntiCheatExpert\` (on `D:`, which the walk does not
cover; listed by hand). The uninstall entry `AntiCheatExpert` names that
payload's `ACE-Setup64.exe` as its icon, as the August observation's entry named
the game that installed it then.

Every file ACE installed is a **byte-identical copy of that payload** (SHA-256,
compared by hand):

| Installed | Copy of the game's |
|---|---|
| `C:\Program Files\AntiCheatExpert\Uninstaller.exe` | `ACE-Setup64.exe`: the installer is the uninstaller |
| `C:\Program Files\AntiCheatExpert\ACE-Service64.exe` | `ACE-Service64.exe` |
| `C:\Program Files\AntiCheatExpert\ACE-BASE.sys` and `system32\drivers\ACE-BASE.sys` | `ACE-BASE.sys` |
| `C:\Program Files\AntiCheatExpert\ACE-CORE106095005.sys` | `ACE-CORE.sys` |
| `C:\Program Files\AntiCheatExpert\ACE-CORE206095005.sys` | `ACE-CORE.sys2` |

## The footprint

| Kind | Observed |
|---|---|
| Service | `AntiCheatExpert Protection`: own process, interactive, `demand`, error control normal |
| Driver | `ACE-BASE`: kernel driver, `demand`, `\??\C:\WINDOWS\system32\drivers\ACE-BASE.sys` |
| Files | `C:\Program Files\AntiCheatExpert`: five, 15,472,496 bytes; `C:\ProgramData\AntiCheatExpert\ace-drc.dat`, 1,804,428 bytes, unsigned; `system32\drivers\ACE-BASE.sys`, 4,125,432 bytes |
| Registry | both service keys, with `ACE-BASE\Final` beside them; the uninstall entry, 64-bit view only; `HKCU\SOFTWARE\appdatalow\AntiCheatExpert` with `{4324E6D9-…}\Tencent`, `{F63EEEBB-…}\Tencent\6095005`, and two keys left empty, `CrashDumps` and `{5FCF1253-…}` |

Signatures, as in August:

- The drivers are attestation-signed by *Microsoft Windows Hardware
  Compatibility Publisher*, so they do not cluster with the vendor's signer.
- `ACE-Service64.exe` and `Uninstaller.exe` are signed by *ACEVILLE PTE LTD*.
- `suggest` attributes the drivers by directory instead.

### ACE keeps per-title state, keyed by a game id

`6095005` appears twice, and nowhere else:

- in the per-user key `{F63EEEBB-…}\Tencent\6095005`;
- zero-padded, in the names of the two core drivers, `ACE-CORE106095005.sys`
  and `ACE-CORE206095005.sys`.

It is this title's id. So a second title would most likely add its own pair of
core drivers and its own key, beside the shared service, base driver and
uninstaller. That is what `docs/04`'s `shared` and the G1 refcount have to
reason about. **Not observed yet:** launching a second ACE title with ACE
installed would show it.

### Running, then stopped

Checked read-only while the game ran, and again after it closed:

| | Game running | Game closed |
|---|---|---|
| `ACE-BASE` | running | stopped |
| `AntiCheatExpert Protection` | stopped | stopped |
| `system32\drivers\ACE-BASE.sys` | present, written at the second session's start | still present |

Unlike EA AntiCheat's driver, ACE's driver image stays on disk while no game
runs.

### Neverness To Everness ran too, and installed nothing of ACE's

NTE's Unreal save folder appeared in the window. The NTE log says nothing of
ACE, and ACE's state names one game id. Whatever NTE did at 2026-10-09 ~18:00Z,
it did not install or register ACE.

### Nothing of ACE's was on the machine before

Snapshots 00 and 01 are format 2 and record keys left empty. Neither has any
key under `HKCU\SOFTWARE\appdatalow\AntiCheatExpert`. That is consistent with
the August observation, where ACE's uninstaller left nothing of its own. It
cannot rule out something else having removed a key in between.

## What else the window caught

- `EAAntiCheat` appears as an **added service** though nothing installed it in
  this window. Its key was written straight into the registry on 2026-10-09,
  and SCM only read it at this restart (`observations/2026-10-09-ea-anticheat/`).
  A services diff that crosses a restart can show a driver "arriving" that
  arrived earlier.
- `PROCEXP152.SYS`: Process Explorer's driver, from running it elevated.
- Store application and browser updates, Steam updates, the NVIDIA App,
  Discord, and Visual Studio Code's logs.

## Privacy

The diff was computed, redacted and drafted by the build with #52, whose last
rules this diff prompted:
- Windows' key stores, out of G3: a machine key's file name ends in the
  machine's identifier;
- file-picker history;
- Gaming Services' list of the Steam library;
- the Claude command line's caches;
- Visual Studio Code's edit history and chat sessions;
- Proton Mail Bridge's mail store.

| Kind | Removed by the policy |
|---|---|
| Registry records | 13,442 |
| Registry values | 8 |
| File records | 81,481 |
| Unreadable items | 43 |
| Emptied directories | 8 |

`redact` masked:
- account names, 3,110 times;
- machine SIDs, 296 times;
- the machine's name, 4 times, inside binary values;
- 55 identifiers.

Nine of the identifiers were supplied with `--also-id` after reading the diff:
- NTE save files named after the player's account;
- Unreal's crash-reporter folders, named after an installation id;
- the Kuro SDK's account files, named after an identifier;
- an EA app folder named after a hash.

`Anonymous` survives four times, and the report flags it because it begins with
a name it looked for; it is the ordinary word.

## The draft

```
wardsweep-observe suggest --diff install.json --signer "ACEVILLE PTE LTD"
```

- `kind = "kernel"`, `risk = "high"`.
- Both services and three drivers.
- `%ProgramFiles%\AntiCheatExpert` and `%ProgramData%\AntiCheatExpert`.
- Five registry keys.
- No `--only` was needed: nothing else in the window clusters with ACE.

`suggest` tried to add `C:\WINDOWS\System32\drivers` as a path because a
driver lives there, and the deny-list refused it. It names the core drivers by
this title's file names. A catalog entry has to cover any title's, and that is
a reviewer's call, not an observation's. `shared` stays `true`. A test pins
the draft to `install.json`.

## Still to do

1. **A second title with ACE installed.** Snapshot, launch NTE until it reaches
   the game, close it, snapshot: what a second title adds to a shared ACE.
2. **The residue half.** ACE's own `Uninstaller.exe`, then a snapshot. Every
   title's next launch reinstalls it, which is the cycle `docs/16` describes.
3. In the PR that adds the catalog entry, paste `signtool verify /v /pa` for
   every binary (`docs/16` checklist).
