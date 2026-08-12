# 11 — CLI Reference

`wardsweep.exe` is a thin frontend over the same broker core the UI uses. It is
not a second implementation, and it is the primary interface for testing.

## Global options

```
--json                  machine-readable output on stdout, logs to stderr
--catalog <path>        override catalog location (still signature-verified)
--no-color
--log-level <level>     error|warn|info|debug|trace
--data-dir <path>       override %ProgramData%\WardSweep (portable mode)
-v, --version
-h, --help
```

## `scan`

```
wardsweep scan [--mode audit|orphan|full] [--deep-fs] [--json] [-o <file>]
```

Read-only. Runs without elevation; unreadable locations are reported as
`access_denied`, never as absent.

```powershell
wardsweep scan --mode audit --json -o audit.json
wardsweep scan --mode orphan
```

Exit: `0` findings present · `1` nothing found · `2` scan error ·
`3` partial scan (some locations unreadable)

Treat `3` as "run elevated for a complete picture", not as a failure.

## `plan`

```
wardsweep plan --game <id> [--game <id>...] [--from-scan <file>] [-o plan.json]
```

Builds and prints a plan. **Writes nothing.** Shows the artifact tree, tier
classification, refcount decisions and blocked items with reasons.

```powershell
wardsweep plan --game example-shooter --game other-title -o plan.json
```

Exit: `0` plan built · `1` no eligible artifacts · `4` plan contains BLOCKED
items (refcount > 0)

Exit `4` is informational: the plan is valid, it just cannot remove everything
you named. `apply` will proceed with the eligible subset.

## `apply`

```
wardsweep apply --plan <plan.json> [--confirm] [--tier safe|review]
                [--include-saves] [--no-restore-point] [--json]
```

**Dry-run by default.** Without `--confirm` it prints exactly what would happen
and exits 0 having touched nothing.

```powershell
wardsweep apply --plan plan.json                 # dry run
wardsweep apply --plan plan.json --confirm       # execute
```

| Flag | Effect |
|---|---|
| `--confirm` | Actually execute. Required for any write. |
| `--tier` | Ceiling on what is applied. `safe` (default) ignores `REVIEW` items. |
| `--include-saves` | Include `PROTECTED` save paths. Saves are archived to quarantine regardless. |
| `--no-restore-point` | Skip restore point creation. Quarantine is unaffected. |

Requires elevation. Refuses to run if a target game or launcher process is
running (Safety Gate G2) — it will not close them for you.

Exit: `0` complete · `5` complete, reboot required · `6` complete with
residuals · `7` aborted at preflight · `8` failed mid-job (rollback available)

## `resume`

```
wardsweep resume --job <job-id>
```

Continues a job left at `pending_reboot`. This is what the scheduled task
invokes after restart. Gate invariants are re-verified against current machine
state before anything resumes.

## `rollback`

```
wardsweep rollback --job <job-id> [--entry <id>...] [--kind file|registry|service|task|firewall] [--confirm]
```

Dry-run by default, like `apply`.

```powershell
wardsweep rollback --job 01J8XZ... --confirm                 # everything
wardsweep rollback --job 01J8XZ... --kind registry --confirm # registry only
```

Games uninstalled in Stage 2 cannot be restored. The command says so before
proceeding.

## `quarantine`

```
wardsweep quarantine list [--json]
wardsweep quarantine show --job <job-id>
wardsweep quarantine purge --job <job-id> --confirm
wardsweep quarantine purge --expired --confirm
```

## `report`

```
wardsweep report --job <job-id> --format html|md|json [-o <file>]
```

## `catalog`

```
wardsweep catalog verify [--catalog <path>]
wardsweep catalog list [--json]
wardsweep catalog show --id <anticheat-id>
wardsweep catalog import --toml <path> --sig <path>
```

`verify` is useful in CI and in bug reports — it prints the catalog version,
signature status, entry counts and schema version.

## `observe`

Wraps the observation harness — see [`16`](16-OBSERVATION-HARNESS.md).

```
wardsweep observe snapshot -o before.json
wardsweep observe snapshot -o after.json
wardsweep observe diff --before before.json --after after.json -o diff.json
wardsweep observe suggest --diff diff.json          # emits a draft catalog entry
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Nothing found / nothing to do |
| 2 | Scan error |
| 3 | Partial scan (access denied) |
| 4 | Plan contains blocked items |
| 5 | Reboot required |
| 6 | Completed with residuals |
| 7 | Aborted at preflight |
| 8 | Failed mid-job, rollback available |
| 9 | Catalog verification failed |
| 10 | Elevation required |
| 64 | Usage error |

## JSON output

`--json` emits newline-delimited JSON to stdout; all human text goes to stderr.
Safe to pipe.

```powershell
wardsweep scan --mode orphan --json | ConvertFrom-Json |
    Where-Object { $_.type -eq 'finding' -and $_.risk -eq 'critical' }
```

Schema is versioned (`"v": 1`) and changes only on a major release.

## Scripting notes

- Every destructive subcommand is dry-run without `--confirm`. Design your
  scripts to run the dry-run first and diff the output.
- `--data-dir` lets a test harness keep quarantine and job history isolated.
- The CLI never prompts. Anything requiring a decision returns a non-zero exit
  with an explanation instead of blocking on input.
