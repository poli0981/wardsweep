# S3 — Split-privilege architecture

Throwaway code for spike **S3** in [`docs/13-P0-SPIKES.md`](../../docs/13-P0-SPIKES.md).
The deliverable of this directory is [`../S3-RESULT.md`](../S3-RESULT.md), not
an implementation. Nothing here is merged into `core/`, `cli/` or `ui/`.

**Question:** does the unelevated UI + elevated broker split work end to end,
including reconnection and survival across a process death?

## What this must never do

The Safety Gate ([`docs/02`](../../docs/02-SAFETY-GATE.md)) is frozen and
applies to throwaway code exactly as it applies to shipped code. This spike:

- performs **no** destructive operation of any kind — no SCM call, no registry
  write, no file or key deletion, no `MoveFileEx`, no service reconfiguration
- reads **no** hardware identifier (G3), and does not link the Win32 feature
  sets that would let it
- runs a *synthetic* job. `ApplyPlan` here advances a counter through fake
  stages and writes rows to its own SQLite file. It never names a real artifact
- writes only under `%LOCALAPPDATA%\WardSweep\spike-s3\`, never under
  `%ProgramData%\WardSweep\`, so it cannot disturb real product state

The Rust crate's `windows` feature list is part of that evidence: the SCM and
registry-write APIs are not compiled in, so the binary could not perform a
destructive operation even if the code asked for one.

## Structure

| Path | What |
|---|---|
| `broker/` | Rust. Creates the pipe, verifies the client, runs the synthetic job, owns the SQLite state. Elevated or not depending on how it was launched. |
| `ui/` | C# console. Stands in for `WardSweep.UI.exe`: `asInvoker`, spawns the broker, speaks the protocol, persists the session GUID. |
| `intruder/` | C# console. A third process that tries to connect and must be refused. |
| `scripts/run-s3.ps1` | Drives every automatable check and writes a transcript. |
| `RUNBOOK.md` | The steps that cannot be scripted — UAC prompt observation. |

## Building and running

```powershell
pwsh scripts/run-s3.ps1
```

It builds both halves and runs the automatable checks. Read
[`RUNBOOK.md`](RUNBOOK.md) before the elevation checks: they need an
interactive desktop and UAC at its default level.

## Why it is structurally throwaway

- The root `Cargo.toml` has `exclude = ["spikes"]`, so `cargo build --workspace`
  cannot reach `broker/`, and it has its own `Cargo.lock` that feeds nothing.
- `WardSweep.sln` does not reference `ui/` or `intruder/`.
- `spikes/Directory.Build.props` and `spikes/Directory.Packages.props` terminate
  the repository's MSBuild and NuGet inheritance chains, so spike packages never
  reach the product's central version file.
- No CI workflow path-filters on `spikes/**`.
