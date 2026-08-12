# 15 — Test Machine Protocol

> **Read this before running anything destructive on a physical machine.**

## Context

Kernel anti-cheat is the hardest part of this project to test, and it is
specifically hostile to the safe way of testing it: several products — Vanguard
most notably — refuse to install or run under a hypervisor. So the boot-start
driver path (spike S1) **cannot** be validated in a VM. It requires real
hardware.

This document exists so that requirement does not turn into "test it on the
machine you work on and hope".

## The risk, concretely

The failure modes are not "the test didn't pass". They are:

| Failure | Consequence |
|---|---|
| Wrong service key deleted under `CurrentControlSet\Services` | `INACCESSIBLE_BOOT_DEVICE` / `0x7B` on next boot |
| `PendingFileRenameOperations` overwritten instead of appended | Another installer's pending operations destroyed |
| Deny-list bypassed via junction traversal | Deletion escapes the intended tree |
| Registry hive loaded and not unloaded | Affected user cannot log in |
| Boot-start driver disabled with a dependency chain unhandled | Boot loop |
| Quarantine on a volume with no free space | Job aborts mid-stage |

None of these are exotic. Each is a plausible early bug in exactly the code
these tests exist to exercise.

## Tiered test environments

Use the least dangerous environment that can answer the question.

### Tier 0 — Fixtures (no OS risk)

Golden corpus, sandboxed registry hives, temp filesystem trees. Covers matching,
planning, refcounting, deny-list, path canonicalisation, IPC, quarantine
manifest logic. **Most of the test suite lives here.** See
[`12`](12-TESTING-STRATEGY.md).

### Tier 1 — Hyper-V VM with checkpoints

Covers: launcher integration, user-mode anti-cheat, residue sweep, quarantine,
rollback fidelity (S5), reboot orchestration with a *dummy* boot-start driver.

```powershell
New-VM -Name WS-Test -Generation 2 -MemoryStartupBytes 8GB -NewVHDSizeBytes 120GB
Checkpoint-VM -Name WS-Test -SnapshotName clean
# ... run test ...
Restore-VMSnapshot -VMName WS-Test -Name clean -Confirm:$false
```

A **dummy boot-start driver** — a minimal test-signed or KMCS-exempt driver
under test-signing mode, doing nothing — lets S1's *orchestration* (disable →
reboot → resume → delete) be validated in the VM without needing real
anti-cheat. Only the interaction with real anti-cheat then needs hardware.

Do this before any hardware test. It removes most of the risk.

### Tier 2 — Dedicated physical test OS

For real kernel anti-cheat that refuses to run in a VM.

**A separate Windows installation on a separate drive or partition, not the
working OS.**

Setup:
- Second NVMe or a partition ≥ 250 GB
- Clean Windows 11 install, **physically disconnect or unmount the working
  drive during installation** so the installer cannot touch its boot files
- Local account, no Microsoft account, no OneDrive, no linked data
- Full disk image of this test OS immediately after setup and again after each
  game install — this becomes the reset point
- Boot selection via firmware boot menu, not a shared bootloader entry

Why a separate physical install rather than the working OS: everything
destructive is contained, resets take minutes instead of a rebuild day, and a
bug that bricks it costs nothing but time.

### Tier 3 — The working machine

**Default answer: don't.**

If a scenario genuinely cannot be reproduced anywhere else, the preconditions
below are mandatory and non-negotiable.

## Preconditions for any Tier 2 or Tier 3 run

- [ ] **Full disk image taken and verified restorable.** Not File History, not a
      restore point — a bootable block-level image (Macrium Reflect, Veeam
      Agent, Windows `wbadmin` image backup, or `dd`-equivalent) stored on a
      drive that is disconnected during the test.
- [ ] **Restore actually tested at least once.** An untested backup is a
      hypothesis.
- [ ] **WinPE / Windows recovery USB prepared and confirmed bootable**, with
      `regedit`, `dism`, and the image restore tool on it. Prepare this *before*
      the test, not after the machine fails to boot.
- [ ] BitLocker recovery key exported and stored off the machine — deleting a
      boot-start driver can trigger a recovery prompt.
- [ ] System Restore enabled, manual restore point created.
- [ ] Working drive disconnected or, at minimum, offline in Disk Management.
- [ ] Test run from CLI with `--data-dir` pointing at a known location so
      quarantine and job state are easy to find from recovery media.
- [ ] Dry-run output reviewed **line by line** before `--confirm`. Every time.

## Staged test order

Escalate risk deliberately. Never start at the dangerous end.

| Stage | Target | Why first |
|---|---|---|
| 1 | User-mode anti-cheat only | No driver, no reboot, fully reversible |
| 2 | Kernel AC with a *demand-start* driver | Driver present, stoppable at runtime |
| 3 | Kernel AC with an *auto-start* driver | Reboot path exercised, still stoppable |
| 4 | Shared anti-cheat, multiple games | Refcount (S2) on real data |
| 5 | **Boot-start driver** | Highest risk, last, image taken immediately before |

Between stages: restore the image, or at minimum roll back the job and verify
the machine is healthy (clean boot, `driverquery` matches expectation, no new
Event Log errors).

## Note on the games themselves

The games installed for this work are **test fixtures**, installed to exercise
install and uninstall paths. There is no intent to play them, and this makes the
protocol simpler in useful ways:

- **Uninstall and reinstall freely.** The clean-install → snapshot → install →
  snapshot cycle in [`16`](16-OBSERVATION-HARNESS.md) is the highest-value thing
  the test machine can produce, and it depends on being willing to reinstall.
- **Nothing needs preserving.** No saves, no ranks, no settings. Skip the
  save-protection path in real testing and cover it with fixtures instead.
- **Prefer free-to-play titles** for the same anti-cheat where a choice exists —
  reinstalls are then bandwidth, not money.
- **Use throwaway accounts** where a game requires one, and keep them out of the
  main platform account. Not because anything here risks a ban — WardSweep does
  nothing at runtime and never touches a game while it runs — but because a test
  machine that gets imaged and reimaged repeatedly is not somewhere to leave
  credentials to an account that matters.

Since the games already installed on the machine predate the observation
harness, their "before" state is gone. To recover it: uninstall via the official
uninstaller, snapshot, reinstall, snapshot. That cycle produces better catalog
data than any amount of inspecting the current state.

## Recording results

Each hardware session produces `spikes/SXX-RESULT.md` containing:

- Machine spec, Windows build (`winver` exact), test OS tier used
- Game and launcher versions, anti-cheat version if determinable
- Observation-harness diffs, attached
- Exact commands run, in order
- Full broker log
- Boot health after each reboot: `driverquery /v`, `fltmc filters`,
  System Event Log errors
- Verdict and, for failures, the precise state the machine was left in

The log is more valuable than the verdict. A failure with a complete log closes
a question; a failure without one has to be repeated.

## Emergency procedures

**Machine will not boot after a WardSweep run:**

1. Boot the WinPE USB.
2. `reg load HKLM\OFF C:\Windows\System32\config\SYSTEM`
3. Inspect `HKLM\OFF\ControlSet001\Services\<name>` — a deleted or corrupt
   service key is the likely cause. Recreate from the quarantine snapshot at
   `%ProgramData%\WardSweep\quarantine\{job}\services\*.json`.
4. `reg unload HKLM\OFF`
5. If that fails: Last Known Good Configuration, then the System Restore point,
   then the disk image.

**Files deleted that should not have been:** they are in quarantine, not gone.
The tree under `quarantine\{job}\files\` mirrors the original layout and can be
copied back manually with Explorer or `robocopy` from recovery media — no
WardSweep binary required. This is the reason the quarantine layout preserves
original structure.

## What this protocol is not

It is not caution for its own sake. It is the recognition that this project's
worst realistic bug is "made a machine unbootable", and that the whole point of
the design — quarantine, rollback, deny-lists, staged pipeline — is to make that
outcome impossible. The test protocol is where those guarantees get checked
before a user relies on them.
