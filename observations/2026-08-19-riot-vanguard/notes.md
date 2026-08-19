# Riot Vanguard — observation notes

In progress. The baseline is taken; the uninstall has not happened yet. Two
findings came out of the baseline alone and are recorded now because neither
depends on the rest of the cycle.

## Pre-state, 2026-08-19

| | |
|---|---|
| Vanguard installer version | 1.18.5-11+20260805.032431 |
| Services | `vgc` — win32, `demand`, `error_control = ignore`; `vgk` — kernel driver, `error_control = ignore` |
| Referencing game | VALORANT, `G:\Riot Games\VALORANT\live` — **refcount 1** |
| Uninstaller | `C:\Program Files\Riot Vanguard\uninstall.exe`, signed *Riot Games, Inc.* |

Eleven files under `C:\Program Files\Riot Vanguard`, eight of them signed
*Riot Games, Inc.* — `vgk.sys` (71 MB), `vgc.exe` (92 MB), `vgm.exe`,
`vgrl.dll`, `vgtray.exe`, `log-uploader.exe`, `uninstall.exe` — plus three logs
and an icon. Two more under `%LOCALAPPDATA%\Riot Games\Riot Vanguard`. Four
registry keys: the two service keys in both WOW64 views, and the uninstall
entry.

Unlike AntiCheatExpert, **every Vanguard binary carries the vendor's own
Authenticode CN**, including the kernel driver. Signer clustering works fully
here and only half worked there — which is worth knowing before leaning on it.

## `vgk`'s start type is transient

The value moved during the observation window, unprompted:

| When | Source | `vgk` start type |
|---|---|---|
| 11:41 – 12:52 UTC | four snapshots | `demand` (3) |
| ~13:18 UTC | Riot Client launched | — |
| ~13:20 UTC | `sc qc vgk` | **`SYSTEM_START` (1)** |
| ~13:26 UTC | snapshot, services domain | **`system`** |
| ~13:30 UTC | same snapshot, registry domain | `Start = 3` |
| 13:35 UTC | `sc qc` and registry together | `demand` (3) |

So Vanguard **raised its own driver's start type while its client was running
and lowered it again**, inside about ten minutes. Nothing in this project
touched it.

Three consequences:

1. **`docs/16` infers `risk` from the start type**, and the value moves. A
   catalog entry that fixes `risk = critical` from one observation has fixed a
   reading, not a fact. The inference rule is still right — `SERVICE_BOOT_START`
   *does* mean critical — but the observation behind it needs a timestamp and a
   note about what was running.
2. **`docs/06` Stage 3 sets `Start = SERVICE_DISABLED`, then deletes after a
   reboot.** If the game runs in between, an anti-cheat that rewrites its own
   start type can re-arm itself. `docs/03` already requires the broker to
   "re-verify the gate invariants against the *current* machine state" on
   resume; this is a concrete instance of why.
3. It is direct material for **S1**, whose whole subject is boot-start driver
   removal across a reboot. `SYSTEM_START` is not `BOOT_START`, but it is a step
   toward it and it loads early.

## A snapshot is not an instant, and it used to claim to be

The row above where the services domain says `system` and the registry says
`Start = 3` is **one file**, describing **one service**. Both readings were
correct. The file implied they were simultaneous.

They were not: a snapshot enumerates services, then walks the filesystem for
several minutes, then walks the registry. Measured immediately afterwards, the
skew between the first and last domain was **5 minutes 9 seconds**.

Fixed by recording `domain_started_utc` per domain and printing the span, so a
reader can see the skew instead of assuming it away. Recording it does not
remove it — nothing short of a transactional capture would, and Windows offers
none across these three domains. What it does is stop the file making a promise
it cannot keep.

This is why the discrepancy was worth chasing rather than dismissing as a
misreading: the anti-cheat's behaviour and the tool's limitation were only
separable because both were checked against a third source.

## Still to do

| Step | What |
|---|---|
| 1 | Baseline taken — `10-vanguard-baseline`, and `11-vanguard-baseline-2` after the timestamp fix |
| 2 | **Close the Riot Client**, then run `uninstall.exe` — by the maintainer, not by WardSweep |
| 3 | Snapshot; Vanguard is expected to require a reboot, unlike ACE |
| 4 | Diff for what the uninstaller removed and what it left |
| 5 | Launch VALORANT so it reinstalls Vanguard |
| 6 | Snapshot, diff for the true install footprint |

Raw snapshots are **not** committed. They are at
`%LOCALAPPDATA%\WardSweep\observations\`.
