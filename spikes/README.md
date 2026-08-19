# P0 Spikes

Seven go/no-go gates. **No feature work begins until all seven have a recorded
PASS, FAIL, or explicit deferral** — see [`docs/13-P0-SPIKES.md`](../docs/13-P0-SPIKES.md).

Each spike is throwaway code. The deliverable is a written finding, not a merged
implementation.

## Status

A missing `SN-RESULT.md` means the spike has not been attempted; that is
deliberately unambiguous, and `ls spikes/*-RESULT.md` is the gate check.

| Spike | Question | Verdict |
|---|---|---|
| S1 | Boot-start driver removal across a reboot | — |
| S2 | Shared anti-cheat reference counting | — |
| S3 | Split-privilege architecture | **PASS** — [`S3-RESULT.md`](S3-RESULT.md). All six criteria measured; 23 checks, 0 failed. No design change to `docs/03` implied; `docs/08` amended in five places. |
| S4 | Performance on a genuinely messy machine | — |
| S5 | Rollback fidelity | — |
| S6 | Antivirus false-positive rate | — |
| S7 | Silent vendor uninstall coverage | — |

## Order

```
S3 ──▶ S1 ──▶ S5
 │            ▲
 └──▶ S2 ─────┘
S4, S6, S7 independent
```

S3 first — nothing else is testable without it. S1 and S2 in parallel. S5 last
among the blockers, since it validates the others' output.

**Before running S1 on real hardware, read
[`docs/15-TEST-MACHINE-PROTOCOL.md`](../docs/15-TEST-MACHINE-PROTOCOL.md).** The
failure mode is an unbootable machine, and the protocol exists so "test it on
the machine you work on and hope" never becomes the plan.

## Conventions

- Results go in `spikes/S1-RESULT.md` … `S7-RESULT.md`, using
  [`TEMPLATE-RESULT.md`](TEMPLATE-RESULT.md).
- Spike code goes in `spikes/<sN-slug>/` and is **excluded from the workspace**
  (`exclude = ["spikes"]` in the root `Cargo.toml`) and **absent from
  `WardSweep.sln`**. Neither `cargo build --release --workspace` nor
  `dotnet build WardSweep.sln` can reach it, so "throwaway" is structural rather
  than aspirational.
- A spike may be deferred only with a written reason **and** a scope reduction
  that makes it irrelevant to the milestone. "We'll figure it out later" is not
  a deferral — the point of a gate is that it holds.

## Tests deferred out of M0 with a reason

`docs/12-TESTING-STRATEGY.md` names fourteen unit tests that exist because
getting them wrong hurts someone. M0 implements the deny-list half. The rest
are recorded here so the gaps are visible rather than discovered.

| Test | State |
|---|---|
| `denylist_blocks_system32_paths` | Done, `core/src/safety/denylist.rs` |
| `denylist_blocks_8dot3_alias_of_protected_path` | Done |
| `denylist_blocks_unc_and_device_path_forms` | Done |
| `denylist_cannot_be_widened_by_catalog_entry` | Done |
| `catalog_naming_protected_path_fails_verification` | Done, `core/src/catalog/validate.rs` |
| `denylist_blocks_after_junction_resolution` | **Partial.** The rule is tested (an unresolved or reparse-traversing path is refused). Creating a real junction and resolving it needs `GetFinalPathNameByHandleW`, which arrives with the scanner. |
| `shared_ac_blocked_when_any_referencing_game_remains` | Not started — needs the ownership graph |
| `shared_ac_eligible_only_when_all_referencing_games_removed` | Not started — needs the ownership graph |
| `refcount_counts_games_in_other_user_profiles` | Not started |
| `refcount_counts_games_on_other_volumes` | Not started |
| `uninstalled_game_does_not_contribute_to_refcount` | Not started |
| `plan_rejected_if_it_removes_a_referenced_anticheat` | Not started — needs the plan builder |
| `wow64_both_views_produce_distinct_artifacts` | Not started — needs the registry walker |
| `pending_file_rename_appends_never_overwrites` | Not started — `exec/` code, and v0.1 ships no removal code |
