# Disclaimer

**Read this before using WardSweep.**

WardSweep deletes kernel drivers, Windows services, registry keys, and program files.
Used carelessly, or in a situation its author did not anticipate, it can leave a game
unplayable or a machine in a state requiring repair or reinstallation. You decide
whether to run it.

---

## Relationship to the licence

WardSweep is licensed **GPL-3.0-or-later**. Sections 15, 16 and 17 of that licence
already disclaim warranty and limit liability, and those sections are the operative
legal terms. This document does **not** add restrictions on top of the GPL — it could
not, since the GPL forbids imposing further restrictions on the rights it grants.

What it does is state, in plain language, the specific ways this particular program can
fail, so that "no warranty" is an informed understanding rather than boilerplate nobody
read.

> **This is not legal advice and has not been reviewed by a lawyer.** Before v1.0 it
> should be reviewed by counsel familiar with software distribution in the relevant
> jurisdictions.

---

## No warranty

To the maximum extent permitted by applicable law, WardSweep is provided **"as is"**,
without warranty of any kind, express or implied, including warranties of
merchantability, fitness for a particular purpose, accuracy, and non-infringement.

To the maximum extent permitted by applicable law, the author shall not be liable for
any direct, indirect, incidental, special, consequential, exemplary or punitive damages
— including loss of data, game installations, accounts, progress, purchased content or
profits, business interruption, or the cost of repairing or reinstalling an operating
system — arising from use of, or inability to use, this software, even if advised of
the possibility of such damages.

---

## Specific limitations

### 1. Coverage is incomplete by nature

Many games ship anti-cheat written in-house rather than a recognised third-party
product. **WardSweep will miss these.** The catalog covers known products; it cannot
cover software it has never seen.

An empty scan result means "nothing recognised", not "nothing present". WardSweep does
not claim a machine is clean and the UI is deliberately written to avoid implying it.

### 2. A scan without administrator rights is a partial scan

Audit mode runs unelevated by design. It cannot read parts of `HKLM` or other users'
profiles. Those locations are reported as `access_denied`, never as absent, and the
report says the scan was partial.

Do not read a partial scan as a complete picture.

### 3. Detection can be wrong

Anti-cheat vendors change service names, driver filenames, install paths, registry
layouts and signing certificates without notice. A catalog entry correct on the day it
was written can be wrong the following week.

Consequences of a stale entry: failing to detect a product that is present,
misidentifying one product as another, misreporting a dependency, or proposing an
incomplete plan. Entries are updated as changes are identified. There is no guarantee
about how quickly, and no service level commitment of any kind.

### 4. Removal breaks the game — that is the intended outcome

Removing an anti-cheat removes a component the game requires. WardSweep only removes
anti-cheat as a consequence of removing every game that references it (see
[`docs/02-SAFETY-GATE.md`](docs/02-SAFETY-GATE.md)), so this should not surprise you —
but if a game is reinstalled afterwards, expect to reinstall its anti-cheat too.

Some anti-cheat products reinstall themselves on next game launch. Some require a full
game reinstall. WardSweep cannot predict which.

### 5. Rollback does not restore games

Quarantine and rollback cover files, registry keys, service configurations, scheduled
tasks and firewall rules — see [`docs/07-ROLLBACK-QUARANTINE.md`](docs/07-ROLLBACK-QUARANTINE.md).

**Games uninstalled in Stage 2 cannot be restored.** They are removed by their own
official uninstaller and must be reinstalled normally. The confirmation dialog states
this before you commit.

Windows System Restore is a secondary net, not a guarantee. Windows rate-limits restore
points, may decline to create one, and may discard existing ones under disk pressure.
Quarantine is the actual guarantee; the restore point is a bonus.

### 6. Restart-pending operations depend on Windows

Removing a boot-start kernel driver requires queueing the deletion for the next restart.
That queue (`PendingFileRenameOperations`) is a Windows mechanism outside WardSweep's
control. Power loss, a forced shutdown, another installer, or a third-party "cleaner"
clearing the queue can leave the operation incomplete.

An incomplete operation is recoverable — the job stays resumable and rollback stays
available — but it is not instantaneous and it is not silent.

### 7. Account and ban risk

WardSweep makes **no claim whatsoever** about how any anti-cheat vendor or game
publisher will interpret its use, and offers no assurance regarding account standing.

The tool is designed so it cannot remove an anti-cheat from a machine where a
referencing game remains installed, does nothing to a running game or driver, and never
touches hardware identifiers — see [`docs/02-SAFETY-GATE.md`](docs/02-SAFETY-GATE.md).
Those design decisions are not promises about any third party's conduct, policy or
enforcement.

If your account matters to you, understand what you are doing before you do it.

### 8. Antivirus software will probably flag it

WardSweep stops services and deletes kernel drivers. That behaviour resembles malware at
the level an antivirus engine inspects.

Builds are **not code-signed**, so Windows SmartScreen will warn on first run. Every
release publishes SHA-256 hashes and a VirusTotal permalink so you can verify the bytes
yourself, and false positives are reported to vendors as they appear — see
[`docs/14-DISTRIBUTION-TRUST.md`](docs/14-DISTRIBUTION-TRUST.md) and
[`docs/RELEASES.md`](docs/RELEASES.md).

A detection is not a defect in WardSweep. It is also not a reason to disable your
antivirus, and WardSweep will never ask you to.

### 9. Catalog entries are community-contributed

The catalog accepts external contributions. Every entry must be derived from an
observation-harness diff and reviewed before merging — but review is not proof of
correctness, and no representation is made about the accuracy of any entry.

### 10. Managed and shared devices

Running WardSweep on a device you do not own or administer — a work computer, a school
machine, a shared or managed system — may violate policies that apply to you.
Determining that is your responsibility.

### 11. Pre-release software

WardSweep is pre-alpha. The safety machinery described in the documentation is
specified, not yet proven — see [`docs/13-P0-SPIKES.md`](docs/13-P0-SPIKES.md). Until
those gates pass, treat every run as experimental and follow
[`docs/15-TEST-MACHINE-PROTOCOL.md`](docs/15-TEST-MACHINE-PROTOCOL.md).

---

## What WardSweep does guarantee, as a matter of design

Not legal guarantees — design commitments, verifiable in the source:

- Nothing is deleted without first being moved to quarantine
- The full plan is shown and must be approved before any write
- Dry-run is the default for every destructive command
- An anti-cheat is never removed while a referencing game remains installed
- Nothing is stopped, unloaded or terminated while running
- No hardware identifier is read or written
- No network connection is made unless you explicitly request a catalog update
