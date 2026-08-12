# 20 — Glossary

**Anti-cheat** — Software distributed with a game to detect or prevent cheating.
Ranges from user-mode process scanning to boot-start kernel drivers.

**Artifact** — Any single removable item in a plan: a file, directory, registry
key, service, scheduled task, firewall rule, or event log source. Every
destructive operation acts on an artifact ID from a broker-built plan.

**Audit mode** — Read-only scan requiring no elevation. Reports what exists and
changes nothing. The default and recommended entry point.

**Boot-start driver** — A driver with `StartType = SERVICE_BOOT_START`, loaded
by the boot loader before most of the OS. Cannot be stopped at runtime; removal
requires disable → reboot → delete. Vanguard's `vgk.sys` is the canonical case.

**Broker** — The elevated, headless Rust process that performs all destructive
operations. The UI has no destructive code path.

**Catalog** — The signed TOML file describing anti-cheat and game footprints.
Versioned and licensed separately from the application.

**Confirmed / Probable / Suspicious** — Detection confidence tiers. `Suspicious`
(right path, wrong or missing publisher) is never auto-selected for removal.

**Deny-list** — Compiled-in set of paths and registry keys that can never be
modified, checked after canonicalisation and after catalog expansion. Not
configurable by the catalog.

**Dry run** — The default for every destructive command. Prints the full plan
and exits without writing.

**Gate / Safety Gate** — The five permanent prohibitions in
[`02-SAFETY-GATE.md`](02-SAFETY-GATE.md), referred to as G1–G5.

**Orphan** — A confirmed anti-cheat with reference count zero: its game is
already gone. The most common real-world case.

**Orphan Sweep** — The scan mode that finds and removes orphans without needing
a game selection.

**Observation harness** — Read-only snapshot/diff tooling used to derive catalog
entries from real machines. See [`16`](16-OBSERVATION-HARNESS.md).

**PPL** — Protected Process Light. Windows protection level used by some
anti-cheat services; blocks handle acquisition even from Administrators. All
lifecycle control therefore goes through SCM.

**Plan** — An immutable, content-addressed artifact tree with tier
classifications and refcount decisions. Destructive commands reference a plan
by ID; they cannot name targets directly.

**Preflight** — Stage 0. Aborts on running games, launchers or anti-cheat;
creates the restore point and registry exports. Never fixes things
automatically.

**Quarantine** — The staging store where removed artifacts are moved rather than
deleted. Structure-preserving and browsable in Explorer. Default retention 14
days.

**Reference count (refcount)** — The number of installed games referencing a
given anti-cheat. Anti-cheat is eligible for removal only when this reaches
zero as a result of the current job. Enforcement of G1.

**Residue** — What remains after an official uninstaller has run: caches,
registry trees, tasks, firewall rules, launcher bookkeeping. The founding
premise of the project.

**Reparse point** — Junction or symbolic link. Enumerated but **never**
traversed, at scan time and at deletion time.

**Restore point** — Windows System Restore checkpoint, created best-effort at
preflight. A bonus, not the guarantee — quarantine is the guarantee.

**Shared anti-cheat** — Anti-cheat used by multiple titles (EAC, BattlEye,
Vanguard across Valorant and League of Legends). `shared = true` makes refcount
enforcement mandatory. Defaults to `true` when unknown.

**SmartScreen** — Windows reputation-based execution warning. Unsigned builds
trigger it; documented and expected. See [`14`](14-DISTRIBUTION-TRUST.md).

**Tier** — Plan classification: `SAFE` (ticked), `REVIEW` (unticked, expanded),
`PROTECTED` (save data, separate section), `BLOCKED` (not selectable, reason
shown).

**VAC** — Valve Anti-Cheat. Deliberately out of scope: it is a Steam client
component, not a separately installable product.

**WOW64 redirection** — 32-bit processes reading `HKLM\SOFTWARE` are redirected
to `WOW6432Node`. Every `HKLM\SOFTWARE` key is opened in **both** views;
ignoring this misses roughly half of all uninstall entries.
