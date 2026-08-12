# 01 — Vision & Scope

## The problem

Modern competitive games ship anti-cheat that runs at kernel level: a
boot-start driver, a Windows service, scheduled tasks, and registry state that
outlives the game. Uninstalling the game frequently does not remove any of it.

Three concrete failure modes drive this project:

1. **Orphaned drivers.** A driver whose game was removed two years ago still
   loads at every boot. The user has no idea it is there and no obvious way to
   find out.
2. **Incomplete vendor uninstallers.** Launcher uninstallers remove the game
   directory but leave `%ProgramData%` state, service registrations, firewall
   rules, and scheduled tasks.
3. **Shared anti-cheat confusion.** Users who *do* find the anti-cheat manually
   delete it, and break four other games that were quietly sharing it.

Generic uninstallers (Revo, BCUninstaller, IObit) do not know which anti-cheat
belongs to which game, do not understand shared anti-cheat, and treat kernel
drivers like any other leftover.

## Who this is for

- Someone who has stopped playing a competitive game and wants the kernel driver
  off their machine, cleanly, without guesswork.
- Someone who inherited a machine, or reinstalled games over years, and wants to
  know what is actually running at boot.
- Someone doing a pre-sale wipe, a work/personal separation, or debugging a
  performance or stability problem that traces to an anti-cheat driver.

## Who this is *not* for

Anyone trying to keep playing while removing the anti-cheat, or trying to
escape a ban. See [`02-SAFETY-GATE.md`](02-SAFETY-GATE.md). The design makes
those uses structurally impossible rather than merely discouraged.

## Product principles

**Auditing is the product; removal is a feature.**
Most of the value is in *knowing*. A user who runs the read-only audit and
decides to keep everything has been well served. Audit mode requires no
elevation and is the default entry point.

**Never surprise the user.**
The plan is fully visible before anything is written. Every artifact shows what
it is, why it was matched, and what happens if it is wrong.

**Reversibility over thoroughness.**
Given a choice between removing one more registry key and being able to undo the
whole job, undo wins. Anything WardSweep is not confident about is reported, not
removed.

**Official path first.**
The vendor uninstaller runs first, every time. WardSweep's job is to clean up
after it, not to replace it.

**Zero network by default.**
No telemetry, no phone-home, no analytics. Catalog updates are opt-in, signed,
and can be done via offline file import.

## Scope

### In scope — v1

- Read-only audit and residue report (no elevation)
- Detection of anti-cheat by publisher + service + driver + path + hash
- Game ↔ anti-cheat ownership mapping with reference counting
- Removal of selected games via vendor/launcher/MSI uninstallers
- Removal of anti-cheat whose refcount reaches zero, including boot-start
  drivers, across a reboot
- Residue sweep: filesystem, registry (both WOW64 views), scheduled tasks,
  firewall rules, Run keys, event log sources, shader caches
- Orphan Sweep mode (anti-cheat with no owning game)
- Quarantine + one-click rollback
- CLI with JSON output
- HTML / Markdown / JSON report export
- EN / VI localisation

### Out of scope — v1

- macOS / Linux (Windows-only by nature of the problem)
- Console anti-cheat
- Server-side anything
- Anti-cheat *installation*, repair, or version management
- VAC — it lives inside the Steam client; removing Steam is the user's call
  and is a normal application uninstall, not an anti-cheat operation
- Generic application uninstalling (WardSweep is not a Revo replacement)

### Out of scope — permanently

Everything in the [Safety Gate](02-SAFETY-GATE.md).

## Success criteria

| Criterion | Target |
|---|---|
| Audit scan on a heavily-used machine | < 15 s, < 40 MB broker RSS |
| False positive rate on catalog matching | 0 confirmed cases |
| Removal jobs fully rolled back on request | 100 % of quarantined artifacts |
| Shared anti-cheat incorrectly removed | 0 — this is a P0 defect class |
| Machine rendered unbootable by WardSweep | 0 — this ends the project |

The last two are why [`13-P0-SPIKES.md`](13-P0-SPIKES.md) exists.

## Naming

**WardSweep.** A ward is a protective boundary — the anti-cheat's own framing —
and sweep is what the tool does to what it leaves behind. Deliberately neutral:
no "purge", "killer", "nuke", or anything that reads as hostility toward the
vendors or invites the ban-evasion crowd.
