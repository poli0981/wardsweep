# 12 — Testing Strategy

The unusual property of this project: the thing under test destroys the
environment it runs in. Almost all testing therefore happens against fixtures
and snapshots, and real-machine runs are a small, carefully-staged minority.

## Layers

| Layer | What | Where |
|---|---|---|
| Unit | Pure logic: refcount, deny-list, path canonicalisation, tier classification | Any machine, incl. Linux CI for pure-logic crates |
| Golden | Scan corpus → plan JSON, byte-compared to committed expectations | CI, `windows-latest` |
| Registry sandbox | Real registry ops against a loaded temp hive | CI, `windows-latest` |
| Filesystem sandbox | Real FS ops in a temp tree, incl. junction traps | CI, `windows-latest` |
| Service | Dummy services created and removed | CI, `windows-latest` (admin runner) |
| VM integration | Full pipeline + rollback on a snapshot | Local Hyper-V, manual |
| Real hardware | Kernel anti-cheat that refuses to run in a VM | Local, staged — see [`15`](15-TEST-MACHINE-PROTOCOL.md) |

## Unit — the invariants that matter

These are the tests that exist because getting them wrong hurts someone:

```rust
#[test] fn shared_ac_blocked_when_any_referencing_game_remains();
#[test] fn shared_ac_eligible_only_when_all_referencing_games_removed();
#[test] fn refcount_counts_games_in_other_user_profiles();
#[test] fn refcount_counts_games_on_other_volumes();
#[test] fn uninstalled_game_does_not_contribute_to_refcount();
#[test] fn plan_rejected_if_it_removes_a_referenced_anticheat();

#[test] fn denylist_blocks_system32_paths();
#[test] fn denylist_blocks_after_junction_resolution();       // pre-canonical is a bug
#[test] fn denylist_blocks_8dot3_alias_of_protected_path();
#[test] fn denylist_blocks_unc_and_device_path_forms();
#[test] fn denylist_cannot_be_widened_by_catalog_entry();
#[test] fn catalog_naming_protected_path_fails_verification();

#[test] fn pending_file_rename_appends_never_overwrites();
#[test] fn wow64_both_views_produce_distinct_artifacts();
```

The deny-list tests use a table of adversarial path forms:
`C:\Windows\System32`, `C:\WINDOWS\system32`, `\\?\C:\Windows\System32`,
`C:\PROGRA~1`, `C:\Windows\..\Windows\System32`, `\\localhost\C$\Windows`,
`\\.\GLOBALROOT\Device\HarddiskVolume3\Windows`, and a junction pointing at each.

## Golden corpus

A committed synthetic tree (~120 k files, ~40 k registry keys as a `.reg`
fixture, ~200 fake services as JSON) that exercises:

- Shared anti-cheat with 0, 1 and 3 referencing games
- Boot-start driver
- Orphan anti-cheat
- `suspicious` (right path, wrong publisher)
- Save paths adjacent to cache paths
- Junction traps and long paths
- Both WOW64 views of the same logical key
- Multi-volume install
- Second user profile with an unloaded hive

Scanning the corpus must produce a byte-identical plan JSON. Any diff is either
an intentional change (update the golden, explain in the PR) or a regression.

## Registry sandbox

Tests never touch the live registry. `RegLoadKeyW` mounts a fixture hive under
`HKLM\WardSweepTest-{guid}`; a `Drop` guard unloads it. A leaked hive load is
itself a tested failure — there is a test that asserts the guard runs on panic.

## Filesystem sandbox

Temp tree per test with a `Drop` guard. Junction creation requires
`SeCreateSymbolicLinkPrivilege`, which the CI runner has; tests that need it
skip with a clear message when it is unavailable rather than silently passing.

## Service tests

CI runner is admin. Tests create dummy services pointing at a harmless stub
binary, exercise the full disable → stop → delete sequence, and assert the
snapshot/restore round-trip.

**Boot-start cannot be tested in CI** — it needs a reboot. That is spike S1 and
is validated on real hardware only.

## VM integration

Hyper-V, checkpoint before each run, restore after.

```powershell
Checkpoint-VM -Name WS-Test -SnapshotName clean
# install games, run pipeline, verify
Restore-VMSnapshot -VMName WS-Test -Name clean -Confirm:$false
```

**Known limitation:** several kernel anti-cheat products refuse to install or
run under a hypervisor. Vanguard in particular. So the VM covers user-mode
anti-cheat, residue sweeping, launcher integration, quarantine and rollback —
but not the boot-start driver path. That gap is exactly what
[`15`](15-TEST-MACHINE-PROTOCOL.md) exists to close, safely.

## Rollback fidelity (S5 acceptance)

After a full removal and rollback on a snapshot, compare against the pre-removal
snapshot:

| Aspect | Comparison |
|---|---|
| File contents | SHA-256 per file |
| File metadata | Attributes, created/modified/accessed, ACL SDDL |
| Registry | Values, types, data, default values, subkey set |
| Services | Every field of `QueryServiceConfigW` + `QueryServiceConfig2W`, incl. SDDL and failure actions |
| Scheduled tasks | Exported XML, normalised for whitespace and timestamps |
| Firewall | Rule properties |

Anything that cannot round-trip must be documented as a known limitation before
v1.0. Discovering it from a user's bug report is the failure case.

## Fuzzing

`cargo-fuzz` targets:

- IPC frame reader (truncated, oversized, invalid UTF-8, deep nesting)
- Catalog TOML parser (malformed, hostile paths, huge arrays, deep nesting)
- Path canonicaliser (all the adversarial forms above)
- `.reg` export/import round-trip

## UI tests

- ViewModel unit tests against a fake `IBrokerClient`
- Snapshot tests for the plan tree at each tier
- A test that asserts **no ViewModel type references `System.IO` or
  `Microsoft.Win32.Registry`** — enforced by an architecture test, because the
  UI process must have no destructive code path at all

## CI matrix

Every workflow is defined in this repository rather than called out to a shared
one. [`14`](14-DISTRIBUTION-TRUST.md) treats public CI as part of the trust
story for an unsigned binary, and a pipeline you cannot read from here is not
public in any useful sense.

| Workflow | Job | Runner | Gates |
|---|---|---|---|
| Rust CI | `lint` | ubuntu | `cargo fmt --check`, clippy pedantic `-D warnings`. Building with `cfg(windows)` off is also what proves no Win32 dependency has reached the portable crates. |
| Rust CI | `test-windows` | windows | clippy pedantic again — the linux job lints no Win32 code path at all — plus unit, sandbox and golden tests |
| Rust CI | `deny` | ubuntu | advisories, bans, licences, sources |
| Rust CI | `bench` | windows | `scan_corpus`, gated on the hard-fail budgets in [`10`](10-PERF-BUDGET.md). Push only. |
| .NET CI | `build-test` | windows | restore `--locked-mode`, build, `dotnet format`, test |
| .NET CI | `arch-tests` | windows | `Category=Architecture`: no destructive code path in the UI |
| .NET CI | `vulnerable-packages` | windows | transitive scan. Hard gate, and the output is parsed rather than the exit code, which is always 0. |
| .NET CI | `xaml-style` | windows | XamlStyler |
| Catalog Verify | `verify` | ubuntu | signature, schema, referential integrity, deny-list conflict, shared-flag audit |
| CodeQL | `analyze` | windows | C# `security-extended`. Windows rather than ubuntu because the solution is WPF and building the real thing on the real platform is worth the deviation. CodeQL has no Rust support; clippy pedantic and `cargo deny` cover that side. |

`catalog-verify` includes a check that no catalog entry resolves to a
deny-listed path. A catalog that would be refused at runtime must fail CI, not
ship and fail on a user's machine.

## What is deliberately not tested automatically

Real kernel anti-cheat installation. It requires real hardware, changes between
game patches, and cannot be made deterministic. It is validated manually per
[`15`](15-TEST-MACHINE-PROTOCOL.md) and the results are captured as catalog
entries and golden fixtures so the automated suite inherits the knowledge.
