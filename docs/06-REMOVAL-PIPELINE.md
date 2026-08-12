# 06 — Removal Pipeline

Seven stages, numbered 0–6. Stages 0–2 are recoverable; 3 onward are
quarantine-backed. The
pipeline may span a reboot between stages 3 and 5.

```
0 PREFLIGHT ─▶ 1 PLAN ─▶ 2 VENDOR ─▶ 3 SERVICE ─▶ 4 REBOOT ─▶ 5 SWEEP ─▶ 6 VERIFY
   abort         approve   official    disable+     resume     residue    re-scan
   on running    required  uninstall   delete       via task              + report
```

Every stage is **idempotent**. Re-running a completed stage is a no-op. This is
what makes crash recovery and reboot resume tractable.

---

## Stage 0 — Preflight

Aborts the job, does not fix things automatically.

| Check | Failure behaviour |
|---|---|
| Running as elevated broker | Abort — should be impossible |
| Any target game process running | **Abort**, name the process (G2) |
| Any launcher running | Abort, name it — launchers lock files and rewrite manifests |
| Any anti-cheat service in `SERVICE_RUNNING` with a referencing game running | Abort (G2) |
| Free space ≥ (quarantine estimate × 1.2) | Abort with the shortfall |
| Pending reboot already outstanding (`PendingFileRenameOperations` non-empty) | Warn, offer to reboot first |
| System Restore enabled | Warn, offer to enable; proceed if declined |
| Another WardSweep job in progress | Abort |
| Catalog signature valid | Abort |

Then, before any write:

1. Create a System Restore point (`SRSetRestorePointW`, `MODIFY_SETTINGS`), if
   available. Record its sequence number in the job.
2. Export every registry key in the plan to `.reg` under the quarantine root.
3. Snapshot full service configs for every service in the plan.
4. Write the job row to SQLite with `status = preflight_complete`.

Restore point creation is best-effort — it is commonly disabled, throttled to
once per 24 h, or unavailable on non-system volumes. Quarantine is the actual
guarantee; the restore point is a bonus.

---

## Stage 1 — Plan

Builds the artifact tree and classifies every node.

### Classification

| Tier | Meaning | Default |
|---|---|---|
| `SAFE` | Confirmed, unambiguous, reversible, refcount clear | Ticked |
| `REVIEW` | Ambiguous ownership, shared directory, user data adjacent | Unticked, expanded |
| `PROTECTED` | Matches a `saves` entry | Unticked, separate section |
| `BLOCKED` | Refcount > 0 after this job, or deny-list hit | Not selectable, reason shown |

### Refcount resolution

For each anti-cheat in scope:

```
remaining_refs = installed_games_referencing(ac) - games_being_removed
if remaining_refs is empty  →  ac is eligible
else                        →  ac is BLOCKED, listing remaining_refs by name
```

Recomputed live as the user ticks and unticks. The UI shows the consequence
immediately: untick one game and the anti-cheat visibly moves from eligible to
blocked, naming the game that now holds it.

This invariant is re-verified at approval and again immediately before Stage 3.
See [`02-SAFETY-GATE.md`](02-SAFETY-GATE.md) G1.

### Output

A plan is an immutable, content-addressed document. `ApplyPlan` references it by
ID plus a list of approved artifact IDs. The broker will not act on an artifact
that is not in the plan it built.

**Dry-run is the default.** `--apply` without `--confirm` prints the plan and
exits 0 without writing.

---

## Stage 2 — Vendor uninstall

**Always first.** WardSweep cleans up after the official uninstaller; it does
not replace it.

| Platform | Method |
|---|---|
| Steam | `steam://uninstall/{appid}`, then wait for `appmanifest_{appid}.acf` to disappear |
| Epic | Launcher uninstall; fallback to the MSI product code in the `.item` manifest |
| EA App / Origin | Registry `UninstallString`, `/silent` where supported |
| Ubisoft Connect | `UninstallString` with `-uninstall {appid}` |
| Battle.net | `Battle.net.exe --uninstall --uid={uid}` |
| Riot | `RiotClientServices.exe --uninstall-product=...` |
| MSI | `msiexec /x {GUID} /qn /norestart` |
| Xbox / MS Store | `PackageManager.RemovePackageAsync` (see below) |
| Anti-cheat's own | `catalog.official_uninstall`, e.g. EAC setup with `uninstall` |

### Silent-mode reality

Not every launcher supports silent uninstall, and behaviour changes between
versions. Fallback ladder:

1. Documented silent switch
2. Interactive uninstaller, broker waits on the process handle with a timeout
3. Manual: mark the artifact `needs_user_action`, show instructions, pause the job

Never force-kill a stuck uninstaller. Time out, record, and let the user decide.

### The `.acf` problem

Deleting a Steam game directory without removing `steamapps\appmanifest_{appid}.acf`
leaves Steam believing the game is installed. It will then show it as installed,
fail to launch, and offer "verify files" loops. Equivalent traps:

- Epic: `%ProgramData%\Epic\EpicGamesLauncher\Data\Manifests\*.item`
- EA: registry install path under `HKLM\SOFTWARE\WOW6432Node\Electronic Arts`
- Ubisoft: `HKLM\SOFTWARE\WOW6432Node\Ubisoft\Launcher\Installs\{appid}`

Launcher bookkeeping is an artifact class in its own right and is always
handled alongside the directory.

### UWP / Microsoft Store games

Removal goes through `PackageManager.RemovePackageAsync`, not the filesystem.
`WindowsApps` is protected by TrustedInstaller and must never be touched
directly — the deny-list enforces this.

Important: a Store game's anti-cheat is typically a **separate Win32 install**
outside the package, so the anti-cheat side of the job proceeds normally.

### Fail-closed

If vendor uninstall fails for a game, that game is **not** counted as removed.
Its anti-cheat's refcount stays elevated, so the anti-cheat is not removed. The
job continues for other games and reports the failure.

---

## Stage 3 — Services and drivers

Order matters. Getting it wrong is how you make a machine unbootable.

```
for each eligible service (dependents first, then dependencies):
    1. QueryServiceConfig2W        → snapshot into quarantine manifest
    2. ChangeServiceConfigW        → StartType = SERVICE_DISABLED
    3. if RUNNING and not boot-start:
           ControlService(SERVICE_CONTROL_STOP), wait ≤ 30 s
    4. if stopped:
           DeleteService + move driver file to quarantine
       else:
           MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT) on the .sys
           mark service delete_pending → Stage 5
```

### Boot-start drivers

`SERVICE_BOOT_START` (Vanguard's `vgk.sys` is the canonical case) cannot be
stopped at runtime. The only correct sequence is:

**disable → reboot → delete.**

Never attempt `NtUnloadDriver`, never attempt to stop it, never try a
"forced" removal. G2 makes this a rule, not a preference. Disabling is safe —
the driver simply does not load next boot.

### Protected processes

Anti-cheat services frequently run as PPL. `OpenProcess` for termination fails
with `ERROR_ACCESS_DENIED` and this is correct and expected. All lifecycle
control goes through SCM. WardSweep does not attempt to acquire
`SeDebugPrivilege` for this or any other purpose.

### `PendingFileRenameOperations`

`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations`
is a `REG_MULTI_SZ` **shared with every installer on the system**.

```
READ existing → APPEND our entries → WRITE back
```

Overwriting it destroys pending operations queued by Windows Update or another
installer. This is a one-line mistake with system-level consequences and is
covered by a dedicated test.

---

## Stage 4 — Reboot

Entered only if Stage 3 produced deferred deletions.

1. Persist job state: `status = pending_reboot`, stage cursor, remaining artifacts
2. Register `\WardSweep\ResumeJob-{id}`: `AtStartup`, `SYSTEM`, highest run level
3. UI prompts. The user may reboot now or later — **the job is durable either way**
4. On boot the task starts the broker with `--resume {job-id}`
5. Broker **re-verifies gate invariants against current machine state** before
   resuming. If the user installed a game that now references a pending
   anti-cheat, the anti-cheat is dropped from the job and reported
6. On completion the task deletes itself

A resume task older than 7 days self-cancels, marks the job `abandoned`, and
leaves quarantine intact so rollback still works.

---

## Stage 5 — Residue sweep

Everything the official uninstallers left behind.

| Class | Examples |
|---|---|
| Filesystem | Install dirs, `%ProgramData%`, `%LOCALAPPDATA%` caches, crash dumps |
| Registry | Config trees, uninstall entries (both views), `Run` keys, class registrations |
| Services | Deferred deletes from Stage 3 |
| Scheduled tasks | `\{Vendor}\*` task folders — remove tasks, then empty folders |
| Firewall | Rules by name/pattern via `INetFwPolicy2` |
| Event log | Sources under `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\*` |
| Shader cache | `%LOCALAPPDATA%\NVIDIA\DXCache`, `%LOCALAPPDATA%\AMD\DxCache` — per-title entries only |
| Launcher bookkeeping | `.acf`, `.item`, install registry entries |
| Start menu / desktop | Shortcuts, jump lists |
| Prefetch | `%SystemRoot%\Prefetch\{NAME}-*.pf` — optional, off by default |

**Not touched:** BAM/DAM, UserAssist, SRUM, AppCompat caches, `Amcache.hve`,
event log *contents*, USN journal. These are OS forensic and telemetry stores.
Cleaning them has no functional benefit and is exactly what a trace-cleaning
tool would do — see G4. WardSweep reads a BAM timestamp to age orphan detections
and writes nothing.

### Directory deletion rules

- Open with `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`
- Canonicalise with `GetFinalPathNameByHandleW`, then deny-list check
- Never recurse through a reparse point
- Never delete a directory containing files not attributable to the plan;
  report the unexpected contents instead
- Move to quarantine, never `remove_dir_all`

---

## Stage 6 — Verify

1. Re-run the scan, scoped to the job's targets
2. Diff intended vs. actual; anything still present is `residual` in the report
3. Emit HTML / Markdown / JSON report
4. Mark quarantine expiry (default now + 14 days)
5. Set job `status = complete` or `complete_with_residuals`

`complete_with_residuals` is a normal, non-alarming outcome. Some artifacts
legitimately survive: files locked by another process, keys owned by
TrustedInstaller, per-user state in a profile that was not loaded. The report
explains each one and what the user can do.

## Stage failure summary

| Stage | On failure |
|---|---|
| 0 | Abort. Nothing written. |
| 1 | Abort. Nothing written. |
| 2 | Record; skip that game's downstream stages; **anti-cheat refcount unchanged** |
| 3 | Restore service config from snapshot; abort remaining services; offer rollback |
| 4 | Job stays `pending_reboot` indefinitely; fully rollback-able |
| 5 | Continue; record failures; report as residual |
| 6 | Report generation failure never fails the job |
