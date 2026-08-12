# 13 — P0 Spikes

Seven go/no-go gates. **No feature work begins until all seven have a recorded
PASS, FAIL, or explicit deferral.** Three of them (S1, S2, S5) determine whether
the automatic-removal product exists at all.

Each spike is throwaway code. The deliverable is a written finding in
`spikes/SXX-RESULT.md`, not a merged implementation.

---

## S1 — Boot-start driver removal across a reboot

**Question:** Can a `SERVICE_BOOT_START` driver be removed safely and
reliably by disable → reboot → delete, with the job resuming automatically?

**Method:**
1. On real hardware (VMs will not host it), with a full disk image taken first
2. Set `StartType = SERVICE_DISABLED` via `ChangeServiceConfigW`
3. Queue the `.sys` via `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)` — appending to
   `PendingFileRenameOperations`, never overwriting
4. Register the resume scheduled task
5. Reboot. Confirm the driver did not load (`driverquery`, `fltmc`, Event Log)
6. Confirm the task fired and the broker resumed
7. Delete the service, verify the key is gone
8. Roll back and verify the driver loads again after a second reboot

**Pass:** driver gone, machine healthy, job resumed unattended, rollback restores
a working driver.

**Fail:** ship "guided manual removal" instead — WardSweep produces exact
instructions and verifies afterwards, but does not perform the removal.

**Risk if wrong:** unbootable machine. This is why [`15`](15-TEST-MACHINE-PROTOCOL.md)
requires an image before this spike runs.

---

## S2 — Shared anti-cheat reference counting

**Question:** Can we determine, reliably, every installed game that references a
given anti-cheat — across Steam, Epic, EA, Ubisoft, Battle.net, Riot, and
standalone installs?

**Method:** install a known set of titles sharing one anti-cheat across at least
four launchers. For each, verify detection of installed state via launcher
manifest, install path, and uninstall registry entry. Then uninstall one at a
time and verify the refcount decrements correctly at each step. Include: game
installed on a second volume; game installed under a second user profile; game
whose directory was manually deleted but whose launcher entry remains.

**Pass:** refcount is correct in every case, and errs toward over-counting when
evidence is ambiguous.

**Fail:** restrict removal to anti-cheat with `shared = false`, plus orphans
where zero evidence of any referencing game exists anywhere.

**Risk if wrong:** a direct G1 violation — the exact harm this project exists to
avoid.

---

## S3 — Split-privilege architecture

**Question:** Does the unelevated UI + elevated broker split work end to end,
including reconnection and survival across a reboot?

**Method:** minimal UI, minimal broker. Verify: unelevated audit produces
results with no UAC prompt; one prompt at apply; pipe DACL rejects a third
process; broker verifies the client image; UI kill → relaunch → reconnect by
session GUID → event stream resumes; broker kill → UI reads job state from
SQLite read-only.

**Pass:** all of the above.
**Fail:** single elevated process, always-admin. Costs a UAC prompt on every
launch and enlarges the attack surface, but is workable.

---

## S4 — Performance on a genuinely messy machine

**Question:** do the [`10`](10-PERF-BUDGET.md) budgets hold on a real machine
with years of accumulated installs, rather than on a synthetic corpus?

**Method:** run the audit scan on the dirtiest machines available. Measure peak
RSS, wall time, time-to-first-finding. Profile where the time actually goes.

**Pass:** within budget on the reference machine, within hard-fail on the worst.
**Fail:** relax budgets, or make the full registry sweep opt-in and default to
targeted catalog keys only.

---

## S5 — Rollback fidelity

**Question:** can a complete removal be restored to a byte-identical state?

**Method:** on a VM snapshot, capture the full pre-state (file hashes and
metadata, registry export, service configs, task XML, firewall rules). Run a
full removal. Roll back. Capture again. Diff per the table in
[`12`](12-TESTING-STRATEGY.md).

Special attention to: service SDDL and failure actions, ACLs on restored
directories, registry default values, `REG_MULTI_SZ` ordering, and boot-start
drivers (which need a second reboot to load again).

**Pass:** everything round-trips, or every exception is documented.
**Fail:** reduce scope — quarantine files only, registry becomes read-only
reporting. A tool that cannot undo itself should not modify the registry.

---

## S6 — Antivirus false-positive rate

**Question:** how badly do AV engines and SmartScreen react to an unsigned Rust
binary that deletes services and drivers?

**Method:** build release artifacts, upload to VirusTotal, record the detection
count and which engines. Install from a fresh download on a clean Windows 11 and
observe SmartScreen and Defender behaviour end to end. Repeat after a rebuild to
see whether detections are build-specific.

**Pass criterion is deliberately lenient:** detections are expected. The spike
fails only if Defender *blocks execution outright* in its default configuration
on a clean machine, which would make the tool undeliverable.

**Mitigation (current scope):** publish the VirusTotal permalink with every
release and file false-positive reports as they appear — see
[`14`](14-DISTRIBUTION-TRUST.md). Code signing is deferred, not adopted.

---

## S7 — Silent vendor uninstall coverage

**Question:** which launchers actually support unattended uninstall, and what
does each do when it fails?

**Method:** for Steam, Epic, EA App, Ubisoft Connect, Battle.net, Riot, MSI and
UWP: attempt silent uninstall, measure completion detection, and check what
residue is left. Specifically verify the `appmanifest_*.acf` behaviour and the
Epic `.item` manifest.

**Pass:** silent path works for a majority; a documented fallback exists for the
rest.
**Fail:** launch the interactive uninstaller and wait on the process handle,
with the residue sweep still fully automatic.

---

## Result template

`spikes/SXX-RESULT.md`:

```markdown
# SXX — <title>
**Date:** · **Verdict:** PASS | FAIL | PARTIAL · **Environment:**

## Question
## Method
## Observations
## Verdict and consequences
## Follow-ups
```

## Dependencies

```
S3 ──▶ S1 ──▶ S5
 │            ▲
 └──▶ S2 ─────┘
S4, S6, S7 independent
```

S3 first (nothing else is testable without it). S1 and S2 in parallel. S5 last
among the blockers, since it validates the others' output.

## Deferral

A spike may be deferred only with a written reason and a scope reduction that
makes it irrelevant to the milestone. "We'll figure it out later" is not a
deferral — the point of a gate is that it holds.
