# Releases — verification and detection tracking

Every release is listed here with artifact hashes, VirusTotal permalinks, and
the status of any false-positive reports. Process is defined in
[`14-DISTRIBUTION-TRUST.md`](14-DISTRIBUTION-TRUST.md).

WardSweep deletes Windows services and kernel drivers. Some antivirus engines
flag that behaviour generically. Detections are expected, are tracked here, and
are reported to vendors as they appear.

---

## Artifact verification

| Version | Artifact | SHA-256 | VirusTotal | Detections at publish |
|---|---|---|---|---|
| _(none yet)_ | | | | |

Template row:

```
| 0.5.0 | `WardSweep-0.5.0-Setup.exe` | `abc123…` | [report](https://www.virustotal.com/gui/file/abc123…) | 4 / 70 |
```

---

## False-positive reports

| Version | Engine | Detection name | Reported | Submission ID | Status | Resolved |
|---|---|---|---|---|---|---|
| _(none yet)_ | | | | | | |

Status values: `submitted` · `in progress` · `resolved` · `closed — no action` ·
`recurring`

`recurring` means the vendor cleared a previous build but the detection returned
on a later one. Re-file per build; note the prior submission ID in the new
report.

---

## Submission channels

| Vendor | Channel | Notes |
|---|---|---|
| Microsoft Defender | `https://www.microsoft.com/wdsi/filesubmission` | Select **"Software developer — false positive"**. Record the Submission ID. Sign in or supply an email to receive updates. |
| Others | Per-vendor web forms | URLs move; verify before filing. Priority order in [`14`](14-DISTRIBUTION-TRUST.md). |

### What to include, every time

- Detection name and where it was observed (on-machine Defender vs. VirusTotal
  cloud verdict — these differ)
- Repository URL and the exact release tag
- One paragraph: user-invoked uninstaller that removes game anti-cheat services
  and drivers, with explicit consent, quarantine and rollback
- Explicit statement: **not packed, not obfuscated, not self-modifying**
- Link to `docs/02-SAFETY-GATE.md`
- Link to the GitHub Actions run that produced the binary

---

## Known SmartScreen behaviour

Builds are **not code-signed** (deferred — see [`14`](14-DISTRIBUTION-TRUST.md)).
Users will see *"Windows protected your PC"* on first run and must choose
**More info → Run anyway**.

This is stated on every release page along with the reason. Users are always
directed to verify the SHA-256 first.

We do **not** ask users to disable their antivirus, and we do not publish AV
exclusion instructions as a first-line fix.
