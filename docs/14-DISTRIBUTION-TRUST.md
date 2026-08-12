# 14 — Distribution & Trust

## The problem, stated plainly

WardSweep disables services, deletes kernel drivers, edits `HKLM\SYSTEM`, writes
to `PendingFileRenameOperations`, and registers a `SYSTEM`-level scheduled task
that runs at boot.

Every one of those behaviours is on a malware behavioural classifier's list.
The tool is not malware, but it is *behaviourally indistinguishable* from it,
and machine-learning classifiers do not read intent. **Detections are expected
and are not a defect.**

The response is not to hide the behaviour. It is to be maximally legible: state
what the tool does, publish the exact bytes, and give users a way to verify them
independently.

## Current trust posture

Scope for now is deliberately minimal:

1. **A VirusTotal permalink with every release.**
2. **A false-positive report filed when a detection appears.**

That is it. No code signing certificate is purchased. The consequences are
accepted and documented below rather than papered over.

### What this means for users

Users downloading an unsigned binary will see:

> **Windows protected your PC** — Microsoft Defender SmartScreen prevented an
> unrecognised app from starting.

They must click **More info → Run anyway**. This is a real friction cost and it
is stated up front in the README and on the release page, along with the reason.

Being honest about this is better than the alternative: a user who is surprised
by a SmartScreen warning on a driver-deleting tool is right to be suspicious.
One who was told to expect it, and who can check the hash and the VirusTotal
report first, is in a much better position.

## VirusTotal policy

### Per release

1. Build release artifacts in CI (`windows-latest`, reproducible flags).
2. Record SHA-256 of every artifact — installer, portable zip, `wardsweep.exe`,
   `wardsweep-broker.exe`, `WardSweep.UI.exe`.
3. Upload each to VirusTotal.
4. Wait for the scan to settle (roughly 5–10 minutes; engines report at
   different speeds — an early snapshot undercounts).
5. Copy the **permalink** (`https://www.virustotal.com/gui/file/<sha256>`).
6. Paste into the release notes, alongside the hash.

### Where the links live

| Location | Content |
|---|---|
| GitHub release notes | Permalink + SHA-256 per artifact, plus detection count at publish time |
| `README.md` | Link to the latest release's report |
| UI **About** screen | Permalink for the *installed* build + SHA-256 of the running binaries |
| `docs/RELEASES.md` | Historical table across versions |

The About screen matters most. A user who is already nervous can verify the
binary on their disk against the published hash without leaving the app.

### Release notes template

```markdown
### Verification

| Artifact | SHA-256 | VirusTotal |
|---|---|---|
| `WardSweep-0.5.0-Setup.exe` | `abc123…` | [report](https://www.virustotal.com/gui/file/abc123…) |
| `WardSweep-0.5.0-portable.zip` | `def456…` | [report](https://www.virustotal.com/gui/file/def456…) |

**Detections at publish time: N / 70.**

WardSweep deletes Windows services and kernel drivers. Some antivirus engines
flag that behaviour generically. Detections listed above have been reported to
the respective vendors as false positives — see `docs/RELEASES.md` for status.

This build is **not code-signed**. Windows SmartScreen will warn on first run.
Verify the SHA-256 above before running.
```

Publishing the detection count rather than hiding it is deliberate. A user who
finds a detection themselves and was not warned loses trust permanently.

### Caveats worth knowing

- VirusTotal detection counts fluctuate between rescans without the file
  changing. Cloud ML verdicts in particular come and go, and detection *names*
  vary across rescans of equivalent builds.
- Detections are frequently build-specific: the same code rebuilt can score
  differently. Do not treat a clean report on one build as a permanent state.
- A VirusTotal upload makes the file public. That is fine — the source is
  GPL-3.0 and the binaries are published anyway.

## False-positive reporting

Reports are filed when a detection appears, per vendor, per build.

### Microsoft (the one that matters most)

Submissions go through the Microsoft Security Intelligence portal at `https://www.microsoft.com/wdsi/filesubmission`, selecting the **"Software developer — false positive"** submission type. After uploading, note the **Submission ID** that is generated for the sample; sign in or provide a valid email address to receive analysis updates.

Include in the submission:

- The detection name Microsoft reported, and where it was observed (Defender
  on-machine vs. the VirusTotal cloud verdict — they are not always the same)
- Link to the public GitHub repository and the exact release tag
- A one-paragraph explanation of *why* the behaviour looks the way it does:
  a user-invoked uninstaller that removes game anti-cheat services and drivers,
  with explicit consent, quarantine, and rollback
- The build is not packed, not obfuscated, not self-modifying — state this
  explicitly, it is a common first question
- Link to `docs/02-SAFETY-GATE.md` — the design constraints are documented and
  public, which is unusual and worth pointing at

Microsoft security researchers analyse all submissions, and signing in at the submission site allows submissions to be tracked. Files with the potential to affect a large number of computers are prioritised — which means a low-download project should expect to wait.

Realistic expectations:

- A "no threats detected, case closed" reply does not always stop the detection
  recurring on the next build. Re-file per build if it does.
- Signing does not make a behavioural classifier stand down. Even signed
  binaries get flagged when the *behaviour* triggers the classifier.
- Controlled Folder Access blocking is a separate mechanism from malware
  detection and is not resolved by a malware submission.

### Other vendors

Each maintains its own submission channel; most are a web form requiring the
sample and a justification. Maintain the current URLs in `docs/RELEASES.md`
rather than here — they move.

Priority order, by how much user pain a detection causes:

1. **Microsoft Defender** — the default on every target machine
2. Avast / AVG (shared engine)
3. Bitdefender (engine is OEM'd widely, so one fix helps several products)
4. Kaspersky, ESET, Malwarebytes
5. Everything else — file if a user reports it, do not chase proactively

### Tracking

`docs/RELEASES.md` carries a table per release:

| Version | Engine | Detection name | Reported | Submission ID | Status |
|---|---|---|---|---|---|
| 0.5.0 | Microsoft | `Trojan:Win32/…` | 2026-08-12 | `7c6c214b-…` | In progress |

Users hitting a detection can see it is known and being handled, rather than
filing a duplicate issue or, worse, assuming the worst.

## Reducing detections at the source

Cheaper than arguing with classifiers:

- **No packing, no obfuscation, no self-modifying code.** Packers are the single
  strongest heuristic signal. Rust release builds with symbols stripped are
  fine; anything UPX-like is not.
- **Reproducible builds** where achievable, so a third party can rebuild from
  the tag and compare hashes.
- **Build in public CI.** A GitHub Actions run ID in the release notes is
  independently checkable provenance.
- **No network at rest.** WardSweep makes no outbound connection unless the user
  explicitly requests a catalog update. Beaconing behaviour is a strong
  heuristic; not having any avoids the question entirely.
- **No dynamic code loading**, no `LoadLibrary` of downloaded content, no
  reflective loading.
- **Meaningful version resources** on the PE: product name, company, description,
  version. Blank version info correlates with malware.
- **Ship the PDB** alongside releases. Analysts can symbolise, and it costs
  nothing.

## Code signing — deferred, not rejected

Out of scope for now. Recorded here so the decision is revisitable rather than
forgotten.

If the project is open source, SignPath Foundation offers free code signing for qualifying open-source projects, providing OV-level certificate signing through a managed pipeline. Approved projects get access to the SignPath platform and can wire signing into their CI/CD pipeline; applications typically take from a few days to a few weeks to process.

Eligibility notes that matter for this project specifically — the project must use an OSI-approved open source licence without commercial dual-licensing, must not contain proprietary components, must be actively maintained, must already be released in the form to be signed, and its functionality must be documented on its download page. GPL-3.0 and the public docs satisfy most of that.

The one to watch: the project must not contain malware or potentially unwanted programs. A tool that deletes kernel drivers will reasonably attract scrutiny under that condition. If SignPath is pursued later, the application should lead with `docs/02-SAFETY-GATE.md` and the explicit refusal to support bypass or ban evasion.

The paid alternative is Azure Trusted Signing, Microsoft's managed code signing service — not free, but around $9.99/month for the Basic tier as of 2026, far below a traditional OV certificate, and Microsoft's recommended option for Windows apps distributed outside the Store. It issues short-lived certificates valid for roughly three days, which suits CI signing and makes key theft largely pointless.

Either way, signing is not a cure. Defender does not trust a file merely because it is digitally signed — if the behavioural classifier flags it, the signature alone will not bypass detection. Signing removes the "unknown publisher" friction and starts building SmartScreen reputation; it does not stop behavioural detections.

**Revisit when:** the project has real users, is genuinely maintained rather than
experimental, and SmartScreen friction is measurably costing installs.

## Packaging

- **Velopack** for the installer and delta updates, consistent with the rest of
  the portfolio.
- **Portable zip** as a first-class artifact. Some users will not run an
  installer for a tool like this, and that instinct is correct.
- No bundled third-party offers, no toolbars, no optional partner software,
  ever. One such bundle would permanently and correctly classify WardSweep as
  a PUP.

## What is never done to reduce detections

- Requesting users disable their antivirus. Ever, in any documentation, for any
  reason. A tool that asks you to turn off Defender before running is one you
  should not run.
- Shipping AV exclusion instructions as a first-line fix.
- Obfuscating or packing to evade detection. That is evasion, and it is the
  behaviour the classifiers are actually looking for.
- Silently retrying an operation that AV blocked. Report it and stop.
