# 19 — Roadmap

Milestones are gated on evidence, not on dates. The dominant risk is shipping
removal code before the safety machinery is proven, so the early milestones
deliberately ship no removal at all.

---

## v0.1 — Audit only

**No removal code exists in the binary.**

- Catalog schema + signing + verification
- Detection engine: services, registry (both views), filesystem, Authenticode
- Ownership graph and reference counting
- Read-only audit, unelevated, with honest partial-scan reporting
- Findings UI (WPF-UI shell, Scan + Findings screens)
- HTML / Markdown / JSON report export
- CLI `scan`, `catalog`
- Observation harness (`observe`) — separate binary, read-only

**Exit criteria:** S2 (refcount) and S4 (performance) resolved. Catalog covers
the initial anti-cheat set with entries derived from real observation diffs.

**Why ship this first:** it is genuinely useful on its own, it builds the
catalog through real use, it establishes trust before asking for elevation, and
it produces the VirusTotal and false-positive baseline (S6) on a binary that
cannot hurt anyone.

---

## v0.5 — Removal without boot-start drivers

- Split-privilege broker (S3)
- Plan builder with tier classification and live refcount preview
- Stage 0–2: preflight, plan, vendor uninstall (S7)
- Stage 5–6: residue sweep, verify
- Quarantine + rollback (S5)
- Service removal for **non-boot-start** services only
- CLI `plan`, `apply`, `rollback`, `quarantine`
- Orphan Sweep for user-mode anti-cheat

**Exit criteria:** S3, S5, S7 pass. Rollback fidelity demonstrated on VM
snapshots. No unresolved P0 defect in the safety module.

**Deliberately excluded:** boot-start drivers, reboot orchestration. This
milestone is safe to ship even if S1 fails.

---

## v1.0 — Complete pipeline

- Stage 3–4: boot-start driver handling, reboot orchestration, resume task (S1)
- Full Orphan Sweep including kernel anti-cheat
- Catalog update channel (opt-in, signed, offline import)
- Vietnamese localisation at parity
- Diagnostics bundle
- Velopack installer + portable zip
- VirusTotal permalinks and false-positive tracking established per release

**Exit criteria:** all seven spikes resolved. S1 validated on real hardware per
[`15`](15-TEST-MACHINE-PROTOCOL.md). Rollback verified for boot-start drivers
across two reboots.

**If S1 failed:** v1.0 ships without automatic boot-start removal. In its place,
a guided manual path — WardSweep generates the exact steps, the user performs
them, WardSweep verifies afterwards. Less convenient, equally honest, and not a
reason to delay the rest.

---

## v1.x — Coverage and polish

- UWP / Microsoft Store game removal path
- Anti-Cheat Reference panel (footprint documentation per entry)
- Japanese localisation
- Scheduled audit with notification on new anti-cheat detected
- Catalog contribution flow from the observation harness straight to a PR
- Per-user scoped removal for multi-user machines

---

## Explicitly not planned

| Not planned | Why |
|---|---|
| Anti-cheat bypass, HWID tooling, ban evasion, trace cleaning | Safety Gate — permanent |
| Generic application uninstaller | Not the problem being solved; BCUninstaller exists |
| Registry "optimiser", junk cleaner, PC booster | Different product, different (worse) trust model |
| Driver of our own | Safety Gate G5 |
| Cloud sync, accounts, telemetry | Zero-network is a feature |
| macOS / Linux | The problem is Windows-shaped |
| Anti-cheat install/repair | Vendors' job |

---

## Decision points

**If S1 fails** → guided manual boot-start removal, everything else unchanged.

**If S2 fails** → removal restricted to `shared = false` anti-cheat and orphans
with zero evidence of any referencing game. Cuts coverage significantly but
keeps the G1 guarantee absolute, which is the right trade.

**If S5 fails** → registry becomes read-only reporting; files still quarantined.
A tool that cannot undo itself has no business editing `HKLM\SYSTEM`.

**If S6 fails hard** (Defender blocks execution outright) → revisit the deferred
code-signing decision in [`14`](14-DISTRIBUTION-TRUST.md) before v1.0, since
the tool would otherwise be undeliverable.

Each of these is a scope reduction that keeps the product honest, not a reason
to work around the finding.
