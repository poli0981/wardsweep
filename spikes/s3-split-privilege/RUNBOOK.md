# S3 runbook — the parts a script cannot see

`scripts/run-s3.ps1` asserts everything that produces a machine-readable fact.
It cannot assert the one thing criteria 1 and 2 are actually about: **how many
UAC prompts appear, and when.** A consent prompt leaves no trace a normal
process can read, by design — that is the point of the secure desktop.

So that half is observed by a person, once, and written down.

## Before you start

| Check | Why it matters |
|---|---|
| UAC is at its default level ("Notify me only when apps try to make changes") | At *Never notify*, an elevated broker starts silently and criterion 2 passes for a reason that does not generalise to any user's machine. Check with `Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' ConsentPromptBehaviorAdmin` — the default for an administrator account is `5`. |
| Your terminal is **not** elevated | An elevated parent starts an elevated child with no prompt at all. Run `whoami /groups \| findstr /i S-1-16-12288` — output means you are elevated; there should be none. |
| Nothing else is mid-install | A concurrent installer's own prompt would be indistinguishable from ours. |

Neither of these reads a hardware identifier, and neither is changed by the
spike. Safety Gate G3 is about machine identity; a UAC policy value is not one.

## The observation

```powershell
pwsh scripts/run-s3.ps1 -Interactive
```

Watch the screen from the moment the script starts and count prompts.

| Step | Expected | Record |
|---|---|---|
| Build, and everything up to `=== Criterion 2 ===` | **Zero** prompts. The whole audit path, the intruder checks, the kill-and-reconnect, and all of criterion 6 run unelevated. | prompts so far: ___ |
| `=== Criterion 2 ===` | **Exactly one** prompt, naming `s3-broker.exe`. | prompt appeared: yes / no |
| Accept it | The script reports `apply\|elevated=true` and streams the job to completion. | elevated: ___ |

Then repeat the last step and **decline** the prompt:

```powershell
pwsh scripts/run-s3.ps1 -Interactive -SkipBuild
```

| Step | Expected | Record |
|---|---|---|
| Decline the prompt | `spawn\|mode=elevated\|verb=runas\|result=uac_declined`, and the script continues rather than crashing. | result: ___ |
| Afterwards | No job row was created — `S3.Ui.exe read-state --state-dir <dir>` reports no job. `docs/03-ARCHITECTURE.md`: "UAC declined → Job never starts; nothing was written." | state: ___ |

## What to write down either way

The prompt count is the finding, not the pass. Record:

- how many prompts appeared, and at which step
- whether the prompt named `s3-broker.exe` or something less legible — a prompt
  the user cannot identify is a trust problem even when the count is right
- whether the elevated broker's console window flashed visibly (it is started
  `WindowStyle = Hidden`, but `runas` does not always honour that)
- how long the elevated broker took to create its pipe after the prompt was
  accepted, since the UI's connect timeout has to cover a user who hesitates

## Cleaning up

The spike writes only to `%LOCALAPPDATA%\WardSweep\spike-s3\`. To reset:

```powershell
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\WardSweep\spike-s3"
```

Nothing under `%ProgramData%\WardSweep\` is touched, no service is created, and
no registry key is written — so there is nothing else to undo.
