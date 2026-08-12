# 03 — Architecture

## Process split

```
┌─────────────────────────────────────────┐
│  WardSweep.UI.exe                       │  Medium IL — NOT elevated
│  C# / .NET 10 / WPF / WPF-UI 4.3.0      │
│  Renders plan, collects approval        │
└───────────────┬─────────────────────────┘
                │ named pipe \\.\pipe\wardsweep-{session-guid}
                │ length-prefixed JSON, restrictive DACL
┌───────────────▼─────────────────────────┐
│  wardsweep-broker.exe                   │  High IL — elevated
│  Rust, headless, no window              │
│  All destructive operations             │
└───────────────┬─────────────────────────┘
                │
    ┌───────────┼───────────┬──────────────┐
    ▼           ▼           ▼              ▼
  SCM       Registry   Filesystem   Task Scheduler
```

### Why split

| Alternative | Problem |
|---|---|
| Single elevated WPF app | UAC prompt on every launch, including read-only audit. Elevated GUI is a larger attack surface (shatter-class issues, drag-drop from medium IL). |
| Single unelevated app | Cannot do the work. |
| **Split (chosen)** | Audit runs with zero prompts. One UAC prompt at Apply. Broker survives independently; UI can crash and reconnect. Broker resumes across reboot without a UI. |

The broker is also the CLI backend, so the CLI is not a second implementation.

### Elevation flow

1. UI starts unelevated. Runs audit by spawning the broker **unelevated** —
   read-only scan needs no rights beyond the user's own.
2. Unelevated scan is marked `partial`; artifacts it could not read are flagged
   `access_denied` rather than "absent". This distinction matters: never report
   "clean" from a scan that could not see everything.
3. On Apply, UI spawns a second broker instance with `runas` verb → one UAC
   prompt → elevated broker takes over the job.
4. Elevated broker registers a resume task before the first destructive write.

## Broker internals

```
core/
├── safety/        deny-list, gate invariants, refcount  ← highest scrutiny
├── catalog/       TOML parse, Ed25519 verify, index build
├── scan/          FS walker, registry walker, service enum, Authenticode
├── plan/          artifact tree, refcount resolver, risk classification
├── exec/          stages 0-6 pipeline, reboot orchestration
├── quar/          quarantine store, manifests, rollback
├── report/        HTML / MD / JSON emitters
└── ipc/           pipe server, command dispatch
```

**Command surface is closed.** There is no `DeletePath(path)` command. The UI
sends `ApplyPlan(plan_id, approved_artifact_ids[])`; the broker resolves IDs
against the plan *it* built and holds in memory. A compromised or spoofed UI
cannot express "delete C:\Windows".

## Language choices

### Rust for the core

Chosen over C++ and Go:

- `windows-rs` covers SCM, registry, VSS, Authenticode, Task Scheduler
- No use-after-free risk across the many nested `HKEY`/`SC_HANDLE` lifetimes
  the scanner juggles
- Single static binary, no CRT redistributable
- `aho-corasick`, `rayon`, `ed25519-dalek`, `rusqlite` are mature
- Go rejected: GC pauses and a ~4 MB floor conflict with the RAM budget, and
  cgo-free Win32 access is worse
- C++ would only win if a WDK driver were needed — and G5 forbids one

### C# / WPF for the UI

- WPF-UI 4.3.0 gives Fluent styling, `NavigationView`, `InfoBar`, Mica backdrop
- Matches the existing desktop stack (OmniDeck, FrameLedger)
- Virtualised `TreeView` handles the artifact tree at 100k+ nodes
- `.resx` localisation already established across the portfolio

## Data flow — audit

```
catalog.toml ──verify──▶ CatalogIndex (Aho–Corasick automaton, built once)
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
  service enum            registry walk           filesystem walk
  (SCM, one pass)      (both WOW64 views)      (rayon, bounded)
        └───────────────────────┼───────────────────────┘
                                ▼
                        candidate stream
                                │  Authenticode + hash verification
                                ▼
                        confirmed findings ──▶ ownership graph
                                                     │
                                                     ▼
                                        refcount + risk classification
                                                     │
                                    ┌────────────────┴────────────────┐
                                    ▼                                 ▼
                            IPC stream to UI                    report emitter
```

Findings stream to the UI in batches as they are produced. Nothing waits for the
full scan to finish. The UI shows partial results with a live progress ring.

## State and persistence

`%ProgramData%\WardSweep\`

```
catalog\catalog.toml        signed, replaceable
catalog\catalog.toml.sig
jobs\wardsweep.db           SQLite: jobs, artifacts, stage results
quarantine\{job-id}\        files (structure preserved) + reg exports + manifest
logs\broker-YYYYMMDD.log    tracing, rolling, 14 days
logs\ui-YYYYMMDD.log        Serilog, rolling, 14 days
reports\{job-id}.html
```

Per-user config in `%LOCALAPPDATA%\WardSweep\config.toml` (theme, language,
quarantine retention). No secrets are stored; nothing needs DPAPI.

## Reboot orchestration

The broker must survive a reboot mid-job:

1. Before Stage 3, write job state to SQLite with `status = pending_reboot`.
2. Register a scheduled task `WardSweep\ResumeJob-{id}`, trigger `AtStartup`,
   principal `SYSTEM`, `RunLevel = Highest`.
3. On resume the broker re-verifies the gate invariants against the *current*
   machine state — the user may have installed something during reboot.
4. On completion the task deletes itself. A resume task older than 7 days
   self-cancels and marks the job `abandoned` (recoverable via rollback).

Scheduled task chosen over `RunOnce` because it runs before user logon, is
inspectable, is deletable by the user, and survives a failed logon.

## Failure model

| Failure | Behaviour |
|---|---|
| Broker crash mid-stage | Job left at last committed stage; UI offers resume or rollback. Stages are idempotent. |
| Pipe drops | Broker continues the job; UI reconnects by session GUID and resumes streaming. |
| UAC declined | Job never starts; nothing was written. |
| Vendor uninstaller fails | Stage 2 records failure; downstream stages are skipped for that game; anti-cheat refcount unchanged so it is *not* removed. Fail-closed. |
| Reboot never happens | Driver stays disabled but present. Audit reports `pending_reboot`. Not an error. |
| Rollback fails partway | Manifest records which entries restored. Remaining entries stay in quarantine and can be retried or extracted manually. |
