# S3 — Split-privilege architecture

**Date:** 2026-08-19 · **Verdict:** PASS — all six criteria measured ·
**Environment:** Windows 11 Pro
10.0.29648, single administrator account, UAC at default, Rust 1.94.1
(x86_64-pc-windows-msvc), .NET SDK 10.0.400, all measurements on
`%LOCALAPPDATA%` (NTFS, local disk)

## Question

Does the unelevated UI + elevated broker split in
[`docs/03-ARCHITECTURE.md`](../docs/03-ARCHITECTURE.md) work end to end,
including reconnection and survival across a process death?

If not, the fallback named in [`docs/13`](../docs/13-P0-SPIKES.md) is a single
always-elevated process — a UAC prompt on every launch and a much larger attack
surface, but workable.

## Method

Throwaway code in [`s3-split-privilege/`](s3-split-privilege/): a Rust broker
(`s3-broker.exe`), a C# console stand-in for the UI (`S3.Ui.exe`), and a third
process (`S3.Intruder.exe`) whose only job is to be refused. The broker
implements enough of [`docs/08-IPC-PROTOCOL.md`](../docs/08-IPC-PROTOCOL.md) to
be real — the DACL, the framing, the message-mode pipe, `Hello`/`HelloAck`,
`ScanStart`/`ScanBatch`/`ScanComplete`, `ApplyPlan`/`StageEvent`,
`JobResume`/`JobState`, `Shutdown` — and runs a **synthetic** job that removes
nothing: seven named stages, one sequence-numbered event per tick, one SQLite
commit per stage boundary. No SCM call, no registry access, no deletion; the
`windows` crate feature list omits `Win32_System_Services` and
`Win32_System_Registry` entirely, so the binary could not have performed one.

`scripts/run-s3.ps1` drives 20 assertions and writes a transcript. Console
output on both sides is `S3|key=value|…`, one fact per line, so the two halves
land in one transcript and the assertions read the same text a human does.

Run as:

```powershell
pwsh spikes/s3-split-privilege/scripts/run-s3.ps1
```

Result of the run backing this document: **23 checks, 0 failed, 0 skipped**,
with `-Interactive` from a non-elevated shell.

The harness was revised once, after the maintainer's first three runs — see
[Defects in the harness](#defects-in-the-harness-found-by-running-it-elsewhere)
below. The numbers here are from the revised version.

## Observations

### Criterion 1 — unelevated audit, no UAC prompt · PASS (machine-checkable half)

The UI spawns the broker with `UseShellExecute = false` and no verb. The broker
reports `elevated=false` from `GetTokenInformation(TokenElevation)`, and a
synthetic audit scan round-trips over the pipe. A process that never elevated
never prompted, so the token is good evidence — but see criterion 2 for the part
that needs eyes.

### Criterion 2 — one prompt at apply · PASS

**Exactly one prompt, and it appears at Apply.** Observed by the maintainer
across four `-Interactive` runs on 2026-08-19 — accepting, declining, from an
elevated shell, and finally on the revised harness. Nothing before Apply
prompted; Apply prompted once. The prompt count is the part no script can see,
so it is attested rather than asserted, and it was attested four times.

The machine-checkable half corroborates it:

```
S3|spawn|mode=elevated|verb=runas|pid=35448
S3|apply|elevated=true
S3|apply|last_seq=43
[PASS] the broker spawned with runas is elevated — elevated=true
[PASS] the elevated broker reports through --fact-file — 8 facts
[PASS] the elevated broker ran the job to completion — last_seq=43
```

The elevated broker came up, was reached over the pipe, and ran the synthetic
job end to end under elevation. Criterion 1's `elevated=false` in the same run
is what makes the pair meaningful: the audit half of the session genuinely was
not elevated, so the single prompt is the whole cost of the split.

What the implementation established along the way:

- `Verb = "runas"` **requires** `UseShellExecute = true`, and that forecloses
  stdio redirection and handle inheritance outright. An elevated broker's stdout
  is attached to its own console and the launching UI can never read it. The
  pipe is therefore not the preferred channel to an elevated broker, it is the
  only one — which the spike had to work around with a `--fact-file` switch just
  to see what the elevated broker observed.
- A declined prompt surfaces as `Win32Exception` with `NativeErrorCode == 1223`
  (`ERROR_CANCELLED`), which maps cleanly onto the failure model in `docs/03`:
  "Job never starts; nothing was written."

### Criterion 3 — "pipe DACL rejects a third process" · PASS, but the phrasing conflates two mechanisms

The DACL grants SYSTEM, Administrators, and the launching user. **Every process
that user starts carries that SID**, so the DACL admits any of them. It keeps
out other users and remote clients and does nothing about a hostile process on
the same desktop. Three separate things were therefore measured.

**3a — the DACL on the live object.** Read back with `GetSecurityInfo` and
rendered to SDDL:

```
requested : D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;S-1-5-21-…-1001)
observed  : D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019f;;;S-1-5-21-…-1001)
```

The kernel does not store generic rights: they are mapped through the object
type's generic mapping at creation. `GA` reads back as `FA`, and `GRGW` reads
back as `0x12019F` — `FILE_GENERIC_READ | FILE_GENERIC_WRITE`. **An
implementation that verifies its own DACL by string-comparing the readback
against the string it passed in will find they never match**, and both obvious
reactions are wrong: weaken the check until it passes, or conclude the
descriptor was not applied. The assertion has to be against the canonical form,
which is what `pipe::assess_dacl` does — protected, names the user, no
`Everyone`, no `Authenticated Users`.

`GW` matters for a second reason: `FILE_GENERIC_WRITE` includes
`FILE_WRITE_ATTRIBUTES`, and .NET's `NamedPipeClientStream` calls
`SetNamedPipeHandleState` to select message read mode. Granting `GR` alone
produces a client that connects and then fails on its first read.

**3b — a different image is refused.** The intruder connects (the DACL admits
it, as expected) and the broker hangs up on the image check before reading a
single command:

```
S3|accept|pid=…|verdict=refused|reason=client image is S3.Intruder.exe, expected S3.Ui.exe
S3|intruder|mode=connect|refused_after_connect=true
```

**3c — a second client is not "refused, not queued".** `docs/08` says a second
connect attempt is refused rather than queued. With `nMaxInstances = 1` that is
not what happens: the second client blocks in `WaitNamedPipe` waiting for an
instance to free, and eventually times out.

```
S3|intruder|mode=second|result=timed_out|waited_ms=2003
```

There is no transport-level way to refuse a waiter. The refusal is necessarily
at the application layer — accept, verify, disconnect — which is what the broker
does. `docs/08` should say so.

### Criterion 4 — client image verification · PASS

`GetNamedPipeClientProcessId` → `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`
→ `QueryFullProcessImageNameW`, compared case-insensitively against the broker's
own directory and the expected file name. Two refinements:

- **TOCTOU is real and cheap to close.** A process id is unique only while the
  process lives; between the two calls the client can exit and the id be reused.
  The broker captures a timestamp *before* asking for the id and compares it
  against `GetProcessTimes`, refusing anything that started later.
- **The session-GUID clause in `docs/08` should be dropped.** It says the broker
  verifies "the session GUID it was launched with" — against the client's
  command line, that needs `NtQueryInformationProcess` or WMI. It buys nothing:
  the client already proved it knows the GUID by connecting to an unpredictable
  pipe name, and it echoes the GUID in `Hello`, where comparing it is free. The
  spike does the latter.
- Authenticode was **not** exercised. Both spike binaries are unsigned, which is
  the shipping condition too ([`docs/14`](../docs/14-DISTRIBUTION-TRUST.md)), so
  the "check when present, absence is not a rejection" rule was never on a path
  that could run. Recorded as a follow-up rather than claimed.

### Criterion 5 — UI killed mid-stream, reconnect resumes · PASS, after amending the protocol

The broker ran a 295-event job. The UI was force-killed (`Stop-Process -Force`)
at event 16; the broker detected `ERROR_BROKEN_PIPE` on its next write, kept the
job thread running, disconnected, and went back to `ConnectNamedPipe` on the
same name. A relaunched UI reconnected and streamed 17…295.

```
first leg saw 16 events, up to seq 16
S3|client-gone|at_seq=16|job_continues=true
[PASS] the resumed stream has no gap — 295 events across two legs, missing: none
[PASS] the resumed stream has no duplicate — duplicates: none
```

**This only worked because the protocol was amended.** As written, `docs/08`
requires the stream to resume but gives events no sequence number and `Hello` no
resume point, so a reconnecting UI cannot say where it got to and the broker
cannot know what to replay. The requirement is not merely unimplemented, it is
unimplementable. The spike added:

- `seq` — a monotonic `u64` on every event envelope, absent on commands and
  responses
- `resume_from` on `Hello`, and `resumed_from` echoed in `HelloAck`

One caveat on how the measurement was obtained. To make "no gap, no duplicate"
checkable, the spike UI rewrites `session.json` after **every** event, so a hard
kill leaves an exact resume point. That is right for measurement and wrong for
production: at the `ScanBatch` rates in [`docs/10`](../docs/10-PERF-BUDGET.md)
it is a file write per batch. The real UI should persist the session GUID only
and recover its position from the `JobState` snapshot the broker sends on
reconnect — which `docs/08` already specifies, and which the `seq` field is what
makes precise.

### Criterion 6 — broker killed, UI reads state read-only · PASS, and the hypothesis was wrong

The prediction going in was that a force-killed writer leaves a hot journal or a
`-wal`/`-shm` pair, that SQLite must write to recover either, and that a genuine
`Mode=ReadOnly` open would therefore fail with `SQLITE_READONLY_RECOVERY`.

**That did not reproduce.** The broker is killed with a write transaction
provably open — `--stall-commit-ms` holds each commit window and announces it, so
the harness kills inside the third one rather than wherever the kill happens to
land. Every configuration then opened read-only and returned current data:

| Journal mode | Per-stage checkpoint | Files left after the kill | Read-only open |
|---|---|---|---|
| WAL | yes | `jobs.db`, `-shm`, `-wal` | ok — 2 of 7 stages, `last_seq=9` |
| DELETE | yes | `jobs.db`, `-journal` | ok — 2 of 7 stages, `last_seq=9` |
| TRUNCATE | yes | `jobs.db`, `-journal` | ok — 2 of 7 stages, `last_seq=9` |
| WAL | **no** | `jobs.db`, `-shm`, `-wal` | ok — 2 of 7 stages, `last_seq=9` |

A hot `-journal` is present in the DELETE and TRUNCATE rows and does not defeat
the read. Killing *before* the first stage commit was also tried, at two
different offsets in all three modes: the schema and job row survive every time,
because they are committed when the store is opened, and the reader gets
`status=running, stages_completed=0` rather than an error.

The counterfactual row matters: without it, the checkpoint would have been
credited with a result it did not produce.

**One contrary observation stands unexplained.** In the maintainer's
elevated-shell run, the TRUNCATE case reported `result=failed` with
`stages_completed=0`. It has not reproduced across the deterministic runs or the
early-kill sweep above. The most probable cause is defect 3 below — a leaked
broker from the previous case holding `jobs.db` while a silent `Reset-State`
failed to delete it, so that case measured a database it had not written, which
fits `stages_completed=0` exactly. That is a harness fault, not a SQLite one.
It is recorded rather than dismissed: it was seen once, the guard is now in
place, and the error text is now printed, so a recurrence is diagnosable instead
of mysterious.

Two further probes, because "the open succeeded" is not the same as "the answer
was right", and because the spike ran somewhere more permissive than the product
will:

- **Sidecars unwritable.** `docs/03` puts the real database under
  `%ProgramData%\WardSweep\jobs\`, where a medium-integrity UI typically has
  read access and nothing more — and SQLite wants to write the `-shm` to read a
  WAL database. Simulated by copying `jobs.db`, `-wal` and `-shm` and setting
  the read-only file attribute on all three. The open still succeeded, **and
  returned `last_seq=9`, identical to the writable copy** — current, not stale.
  A silently stale read would have looked the same from outside and been far
  worse than a failure.
- **The base file alone is not a database.** With the `-wal` withheld:

  ```
  S3|read-state|result=failed|error=SQLite Error 1: 'no such table: jobs'.
  ```

  In WAL mode with no checkpoint, `jobs.db` was 4 096 bytes — a header, with the
  schema itself still in the `-wal`. Anything that collects `jobs.db` without
  its sidecars gathers a file that is not a database: the diagnostics bundle in
  [`docs/19`](../docs/19-ROADMAP.md) v1.0, a support-file collector, a backup.
  The per-stage checkpoint should stay, not for readability but so the single
  file is self-contained for copying.

### The architecture test constrains how the UI may touch the filesystem

[`UiHasNoDestructiveCodePathTests.cs`](../ui/WardSweep.UI.Tests/Architecture/UiHasNoDestructiveCodePathTests.cs)
fails the build if the UI assembly so much as references `System.IO.File`,
`Directory`, `FileInfo`, `DirectoryInfo` or `FileSystemInfo` — it reads the
TypeReference table, so a call from inside a method body counts. That rules out
`File.ReadAllText`, `File.WriteAllText`, `File.Exists` and
`Directory.CreateDirectory`, which are exactly the calls `session.json` invites.

Discovered here rather than at the first CI failure, and the spike UI is written
the way the real one will have to be:

- `FileStream` + `StreamReader`/`StreamWriter`, none of which are on the list,
  because none of them can delete anything
- existence tested by opening and catching `FileNotFoundException` — which is
  also the only answer that is not a race
- **the broker creates the state directory**, never the UI
- `Microsoft.Data.Sqlite` is fine: it takes a path *string*

### Concurrent read and write on a synchronous pipe handle · serialised

A control write with nothing outstanding returned in 0 ms. The same write, with
a `ReadFile` pending on another thread against the same handle, took 2 735 ms —
returning the instant the read completed.

```
control_write_ms=0 (no read outstanding), write_ms=2735 (read outstanding), read_ms=3035, serialised=true
```

The payload was 15 bytes into a 64 KiB output buffer, so this is not
backpressure. A synchronous handle serialises the two directions.

The consequence is concrete: `docs/08` has the broker streaming `ScanBatch`
while remaining able to receive `ScanCancel`, and `docs/09` says "Cancel is
always available and immediate". **That is not achievable on a synchronous
handle.** The real broker needs `FILE_FLAG_OVERLAPPED` and overlapped I/O with
separate events per direction. The spike deliberately did not: it is strictly
half-duplex turn-taking, which is why it could stay small, and the cost is that
it has no cancel.

### Handover between the unelevated and the elevated broker

The unelevated broker owns `\\.\pipe\wardsweep-{guid}`; the elevated one cannot
create the same name while it lives. Of the two candidate handovers, the spike
recommends **(A) shutdown-then-respawn on the same GUID**, which leaves a window
where the name is unowned — closed by `FILE_FLAG_FIRST_PIPE_INSTANCE`:

```
S3|squat|result=refused|error=CreateNamedPipeW(…) failed with Win32 error 5
```

`ERROR_ACCESS_DENIED`. Without that flag, a squatter creates another *instance*
of the same pipe and silently takes the next connection; with it, a name already
in use is a hard startup failure and the handover aborts rather than proceeding
into a pipe someone else is serving. Candidate (B), a second GUID, avoids the
window entirely but complicates session resume, and is not needed given (A)
fails closed.

### Incidental

`Microsoft.Data.Sqlite` **10.0.0** resolves `SQLitePCLRaw.lib.e_sqlite3` 2.1.11,
which carries a high-severity advisory (GHSA-2m69-gcr7-jv3q). The
`vulnerable-packages` job in `dotnet-ci.yml` scans transitively and is a hard
gate, so a UI that took the package at 10.0.0 would fail CI on a dependency it
never named. **10.0.11 resolves clean.**

### Defects in the harness, found by running it elsewhere

The maintainer's three runs found three faults in `run-s3.ps1` that the author's
runs could not have. All are fixed; they are recorded because each one is a way
a measurement can lie, and the third one nearly did.

1. **The criterion 2 block crashed before recording anything.**
   `($output | Where-Object {…}).Count` is a hard error under
   `Set-StrictMode -Version Latest` when nothing matches, because `Where-Object`
   yields `$null`. It killed the script at exactly the point the whole
   interactive run existed to measure, and — because the transcript is written
   at the end — destroyed the record of the run along with it. Fixed with `@()`,
   and the C2 block now distinguishes accepted, declined, and the UI reporting a
   fatal error.

2. **`Invoke-Capture` recorded output without echoing it.** Every command's
   output went to the transcript and nowhere else, so a run that died before
   writing the transcript showed the operator a bare error and nothing about
   what produced it. This is why the TRUNCATE failure below has no error text.
   It now echoes as it goes.

3. **`Reset-State` swallowed every deletion failure**, and nothing cleaned up a
   broker that outlived its section. A leaked broker holds `jobs.db` open, the
   delete silently does nothing, and the next case measures a database it did
   not write. It now stops strays by exact process name and reports a failed
   delete in red.

A fourth is not a defect but was reported as a failure: running from an
**elevated shell** made criterion 1 fail with `elevated=true`. That is correct
behaviour — an elevated parent spawns an elevated child silently — and
`RUNBOOK.md` warns about it, but a harness that reports FAIL for "you ran it
from the wrong shell" is a harness that trains people to ignore red. It now
detects the host's integrity level up front and marks criteria 1 and 2 SKIP,
with SKIP counted separately from FAIL in the summary and the exit code.

## Verdict and consequences

**PASS.** All six criteria measured. The audit path is genuinely unelevated, the
elevation costs exactly one prompt and it falls at Apply, the pipe is genuinely
restricted, a wrong image is genuinely refused, the broker genuinely outlives its
UI with the stream resuming gapless, and the job state is genuinely readable
without it.

Nothing found argues for the `docs/13` fallback, and **no design change to
`docs/03-ARCHITECTURE.md` is implied.** The single-elevated-process alternative
is not needed.

What did change is `docs/08-IPC-PROTOCOL.md`, in five places. The split-privilege
*architecture* survived contact; its *protocol* did not survive it unamended.

What changes as a result:

1. **`docs/08` gains `seq` and `resume_from`.** Reconnection is unimplementable
   without them. Not optional, not a nicety.
2. **`docs/08`'s "a second connect attempt is refused, not queued" is wrong** as
   a statement about the transport. It should say the refusal is at the
   application layer, after acceptance and verification.
3. **`docs/08`'s client-image check should drop the command-line GUID clause**
   and compare the GUID echoed in `Hello` instead.
4. **`docs/08` should require `FILE_FLAG_FIRST_PIPE_INSTANCE`** on every broker
   pipe creation, and describe the handover it protects.
5. **The broker needs overlapped I/O.** A synchronous handle cannot stream and
   receive `ScanCancel` at the same time, and `docs/09` promises an immediate
   cancel.
6. **The UI may not reference `System.IO.File` or `Directory`.** The broker owns
   directory creation; the UI reads through `FileStream`.
7. **Keep the per-stage WAL checkpoint**, for self-containment of `jobs.db`
   rather than for read-only access.

## Follow-ups

- **The declined-UAC path is implemented but never confirmed end to end.** The
  decline run happened on the pre-fix harness and died before recording
  anything. `ERROR_CANCELLED` handling is in the code and the harness now has a
  branch for it, but no transcript shows it firing. Cheap to close next time
  someone runs the runbook.
- **The unreproduced TRUNCATE failure.** Seen once, in an elevated-shell run, on
  the pre-fix harness that printed no error. Attributed to the stray-broker
  defect above on circumstantial grounds. If it recurs on the fixed harness the
  error text will now be in the transcript, and the attribution should be
  revisited rather than assumed.
- **Authenticode.** Never exercised, because both binaries are unsigned and that
  is the shipping condition. Needs a signed fixture before the "check when
  present" rule can be said to work.
- **Overlapped I/O.** The spike proves it is needed and does not implement it.
  Whether `ScanCancel` latency then meets `docs/10` is unmeasured.
- **A second user account.** Every check ran as one user, so the DACL's
  cross-user behaviour is argued rather than observed. `PIPE_REJECT_REMOTE_CLIENTS`
  is likewise unexercised — no remote client was tried.
- **Mandatory integrity.** No ACE was set for the integrity label, so the pipe
  carries the default. A low-integrity client was not tested; it would be blocked
  by the mandatory policy rather than by the DACL, and that is untested here.
- **`%ProgramData%` for real.** The unwritable-sidecar probe simulated the
  permission difference with file attributes. Running against a directory with a
  genuine restrictive ACL would be stronger.
- **Frame fuzzing.** [`docs/12`](../docs/12-TESTING-STRATEGY.md) names truncated,
  oversized, invalid-UTF-8 and deeply-nested frames as `cargo-fuzz` targets. The
  spike validates the length prefix and caps at 16 MiB but was not fuzzed.
