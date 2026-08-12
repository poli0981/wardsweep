# 02 — Safety Gate

**Status: FROZEN.** This document was written before any implementation and does
not change in response to feature requests, user demand, or convenience. Changes
require a maintainer decision recorded in `CHANGELOG.md` with rationale.

---

## The five prohibitions

### G1 — No anti-cheat removal that leaves a game playable

An anti-cheat is removed **only** as a consequence of removing every installed
game that references it. There is no standalone removal entry point:

- Not in the UI
- Not in the CLI
- Not behind a flag, environment variable, config key, or debug build
- Not by hand-editing a plan file — plans are validated against the refcount
  invariant on load, and a plan removing a referenced anti-cheat is rejected

**Invariant (enforced in `core/src/safety/refcount.rs`):**

> For every anti-cheat `A` in an approved plan, the set of installed games
> referencing `A` must be a subset of the games being removed in the same job.

This is checked at plan build, re-checked at plan approval, and re-checked
immediately before Stage 3 executes. A violation aborts the job.

### G2 — No runtime interference

WardSweep never stops, suspends, unloads, patches, hooks, injects into, or
otherwise interacts with a *running* anti-cheat process or loaded driver.

- Preflight enumerates game processes, launcher processes, and anti-cheat
  processes. If any are running, the job **aborts** with instructions to close
  them. It does not offer to close them.
- Driver removal is done by setting `Start = SERVICE_DISABLED` and deleting the
  service after a reboot. Never by `NtUnloadDriver` or equivalent.
- No `TerminateProcess` against anything anti-cheat related, ever.

### G3 — No hardware identity access or modification

WardSweep does not read or write:

`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`, SMBIOS/DMI UUID, disk
serial numbers, volume GUIDs, MAC addresses, TPM state, CPU serial, or any
other hardware fingerprint.

It does not enumerate them for reporting either. There is no legitimate audit
reason that outweighs the misuse signal.

### G4 — No ban-evasion framing

No feature, string, log message, doc, issue template, or release note refers to
bans, HWID resets, trace cleaning, account recovery, or "playing again after".
Issues framed this way are closed with a pointer to this document.

Rationale: framing determines audience. A tool described as a residue cleaner
attracts people cleaning residue. The same tool described as a trace cleaner
attracts a different crowd and a different set of feature requests.

### G5 — No kernel driver of our own

Everything is done through documented Win32, SCM, and registry APIs. WardSweep
ships no `.sys` file.

Rationale: a signed driver capable of deleting other drivers is a
vulnerable-driver problem waiting to happen — precisely the BYOVD pattern that
anti-cheat vendors exist to stop. Shipping one would make WardSweep part of the
problem it is cleaning up after.

---

## Derived design constraints

| Constraint | Follows from |
|---|---|
| No "remove anti-cheat" button anywhere in the UI | G1 |
| Plans are signed/validated, not free-form editable | G1 |
| Preflight aborts (not "force closes") on running processes | G2 |
| Boot-start drivers require a reboot; no runtime unload | G2 |
| No WMI/SMBIOS/registry queries for machine identity | G3 |
| Issue templates omit any "why" field mentioning bans | G4 |
| Pure user-mode; no WDK dependency in the build | G5 |

## What is explicitly allowed

To avoid over-correction, these are fine and are the point of the project:

- Deleting a service and its driver file after every referencing game is gone
- Deleting registry trees created by the anti-cheat installer
- Deleting `%ProgramData%` / `%LOCALAPPDATA%` caches, logs and telemetry stores
- Removing scheduled tasks and firewall rules created by the game or anti-cheat
- Reporting, in full detail, what an anti-cheat installed and where — this is
  transparency, not reverse engineering
- Removing the game itself, completely

## Grey areas and rulings

| Case | Ruling |
|---|---|
| User has Valorant and LoL; wants Valorant gone | Vanguard is shared. Removing Valorant alone leaves refcount 1 → Vanguard stays, and the UI says so explicitly. Removing both → Vanguard eligible. |
| User wants the anti-cheat driver "disabled, not deleted" | Refused. Disabling without removing the game is G1 and G2. |
| Game is already uninstalled; anti-cheat remains | **Allowed** — refcount is already 0. This is Orphan Sweep, the primary use case. |
| Anti-cheat service is set to manual/demand start | Irrelevant to eligibility. Refcount governs. |
| User asks for a report of what Vanguard collects | Refused as a feature. WardSweep documents *footprint* (files, services, keys), not behaviour. Behavioural analysis is someone else's project. |
| Game files are gone but launcher still lists the game | Treated as installed until the launcher entry is removed. Conservative direction. |
| Anti-cheat shared with a game on a *different drive/user profile* | Counts toward refcount. Per-machine scope, not per-user. |

## Review checklist

Any PR touching `core/src/safety/`, `core/src/exec/`, or `catalog/` must answer:

- [ ] Can this code path remove an anti-cheat while a referencing game remains?
- [ ] Can it act on a running process or loaded driver?
- [ ] Does it read or write any hardware identifier?
- [ ] Does any user-visible string reference bans or traces?
- [ ] Does it introduce a driver, or a dependency that ships one?

Five "no"s or the PR does not merge.
