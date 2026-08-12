# 18 — Logging

## Purpose

Every WardSweep bug report will be about something that was deleted or something
that was not. The log has to be able to answer both, and it has to be safe for a
user to paste into a public issue.

## Sinks

| Component | Library | Path |
|---|---|---|
| Broker | `tracing` + `tracing-subscriber` | `%ProgramData%\WardSweep\logs\broker-YYYYMMDD.log` |
| UI | Serilog | `%ProgramData%\WardSweep\logs\ui-YYYYMMDD.log` |
| Job audit | SQLite | `%ProgramData%\WardSweep\jobs\wardsweep.db` |

Rolling daily, 14 files retained, 50 MB cap per file. Portable mode redirects
all three under `--data-dir`.

## Levels

| Level | Contents |
|---|---|
| `error` | Operation failed, user impact |
| `warn` | Degraded: access denied, restore point unavailable, partial scan |
| `info` | Stage transitions, job lifecycle, counts. **Default.** |
| `debug` | Per-artifact decisions, refcount resolution, tier classification |
| `trace` | Per-file scan decisions. Very large. Diagnostic only. |

## The job audit trail is separate

Rolling text logs age out. The SQLite job record does not — it is the permanent
answer to "what did WardSweep do to this machine on that day".

```sql
CREATE TABLE jobs (
  id TEXT PRIMARY KEY, created_utc TEXT, completed_utc TEXT,
  status TEXT, app_version TEXT, catalog_version TEXT,
  restore_point_seq INTEGER, plan_hash TEXT
);
CREATE TABLE job_artifacts (
  job_id TEXT, artifact_id TEXT, kind TEXT,
  original TEXT, quarantined TEXT,
  stage INTEGER, result TEXT, error_code TEXT, ts_utc TEXT
);
CREATE TABLE job_stages (
  job_id TEXT, stage INTEGER, started_utc TEXT, ended_utc TEXT,
  result TEXT, notes TEXT
);
```

Retained indefinitely (small). Survives quarantine purge — after the data is
gone the record of what happened remains.

## Redaction

Logs will be pasted into public issues. They must be safe by default.

| Data | At `info` and below | At `debug`/`trace` |
|---|---|---|
| Usernames in paths | `C:\Users\<user>\...` | Full |
| Machine name | `<machine>` | Full |
| SIDs | Last RID only: `S-1-5-21-…-1001` | Full |
| Game/AC paths | Full — not sensitive | Full |
| Registry keys | Full | Full |
| Email, tokens, licence keys | **Never logged at any level** | Never |

Redaction is applied by a `tracing` layer / Serilog enricher, not by call sites.
Relying on every call site to remember is how leaks happen.

`debug` and `trace` print a banner on enable:

```
[!] Debug logging enabled. Logs will contain full paths and usernames.
    Review before sharing publicly.
```

## Structured fields

```rust
tracing::info!(
    job_id = %job.id, stage = 3, artifact_id = %a.id,
    kind = "service", service = %name, result = "deleted",
    "artifact removed"
);
```

Fields, not interpolated prose, so logs are greppable and machine-parseable. The
message string stays constant across occurrences.

## What is always logged at `info`

- Broker start: version, catalog version + signature status, elevation state
- Scan start/end: mode, duration, counts, partial flag, access-denied count
- Plan built: plan hash, artifact counts by tier, blocked items **with reasons**
- **Every gate rejection** — G1 refcount blocks, deny-list hits. These are the
  most important lines in the file: they prove the safety machinery ran.
- Stage transitions with duration
- Every quarantine move: kind, source (redacted), destination
- Every failure with error code
- Reboot scheduled / job resumed
- Rollback start, per-entry result, completion

## What is never logged

- Anything at `debug`/`trace` when the user has not enabled it
- File *contents*, ever — only paths, sizes and hashes
- Registry *value data* for anything outside the catalog's own keys
- Hardware identifiers (Safety Gate G3 — WardSweep does not read them, so it
  cannot log them)
- Anything sent over a network. There is no network sink and there will not be
  one.

## Diagnostics bundle

```
wardsweep report --diagnostics -o bundle.zip
```

Contains: redacted broker + UI logs, job records (redacted), catalog version and
signature status, quarantine manifests with paths redacted, Windows build,
installed launcher list.

Never contains: quarantined file contents, registry export contents, usernames,
machine name.

A preview of exactly what will be included is shown before the zip is written.
The user should never have to guess what they are about to attach to an issue.

## Crash handling

Rust panics are captured by a hook that writes the payload, backtrace and
current job/stage before unwinding. `RUST_BACKTRACE=1` is set internally so
release builds still produce useful traces.

On the UI side, `DispatcherUnhandledException` and `TaskScheduler.UnobservedTaskException`
are logged and shown in a dialog offering to open the log folder.

**A broker crash never leaves the machine in an unknown state**: stages are
idempotent, the quarantine manifest is written before each operation, and the
job record identifies the last committed stage. The recovery path is resume or
rollback, and both are always available.
