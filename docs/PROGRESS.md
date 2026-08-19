# Progress and next steps

Where the project actually stands, and what to pick up next. `CHANGELOG.md`
records what happened; this file records what is true now and what is not done.

Last updated after **spike S3**.

---

## Where this is

The repository builds, CI runs and is green, and **nothing here can delete
anything**. That is the intended state: `docs/19-ROADMAP.md` makes v0.1
audit-only, and `docs/13-P0-SPIKES.md` gates all feature work behind seven
recorded verdicts, of which **zero exist**.

M0 delivered the parts that had to come before any of that: a workspace shaped
to what CI requires, the safety gate's first real code, and a catalog integrity
gate that runs on every relevant change.

Since then, **S3 has been run and passed** — the first of the seven verdicts,
and the root of the dependency graph. It changed `docs/08-IPC-PROTOCOL.md` in
five places and left `docs/03-ARCHITECTURE.md` untouched: the split-privilege
architecture survived contact, its protocol did not survive it unamended.

## What exists and is verified

| Area | State |
|---|---|
| Cargo workspace, .NET solution, toolchain pins | Done |
| `core/src/safety/paths.rs` — canonicalisation | Done. Extended-length, UNC, device, NT-object, drive-relative and 8.3 forms all collapse or are refused. |
| `core/src/safety/denylist.rs` — the deny-list | Done, with the adversarial path table from [`12`](12-TESTING-STRATEGY.md). Cannot be widened by a catalog. |
| `core/src/catalog/` — schema, Ed25519, integrity checks | Done |
| `tools/catalog/` — `wardsweep-catalog` | Done. Implements the six invocations `catalog-verify.yml` runs, with a parity test. |
| `catalog/catalog.toml` | Signed, and **empty of entries** on purpose — see below |
| `core/benches/scan_corpus.rs` | Done, gated on the hard-fail budgets in [`10`](10-PERF-BUDGET.md) |
| `ui/` — WPF shell | Shell only, plus the architecture tests that assert the UI has no destructive code path |
| CI — Rust, .NET, CodeQL, Catalog Verify | Done, inline in this repository, all green |
| Spike S3 — split-privilege architecture | **PASS.** All six criteria measured — 23 checks, 0 failed. `spikes/S3-RESULT.md`. Throwaway code in `spikes/s3-split-privilege/`, unreachable from either build. |
| `tools/observe/` — snapshot and diff | **Services domain only.** `snapshot` and `diff` work end to end against a real machine; every other domain is named as `not_captured` in the file rather than omitted. `suggest`, `intersect` and `redact` are not written. |

Enforced by tests rather than by review:

- `core/tests/no_destructive_code.rs` — no destructive Win32 or filesystem call
  outside `quar/` and `exec/`, and nothing reads a hardware identifier (G3).
- `tools/catalog/tests/ci_parity.rs` — the CI invocations still work.
- `ui/WardSweep.UI.Tests/Architecture/` — the UI assembly references neither the
  registry nor any filesystem type that can delete.

Each of these has been watched to fail on a deliberate violation. A gate nobody
has seen fail is not a gate.

## What is deliberately absent

- **Any removal code.** `core/src/exec/` and `core/src/quar/` are empty modules
  with doc comments.
- **Any catalog entry.** `CONTRIBUTING.md` rejects entries not derived from an
  observation diff and none has been taken. An empty catalog finds nothing,
  which is harmless; a guessed catalog deletes the wrong thing.
- **The scanner**, the plan builder, refcount, IPC, and the observation harness.

## Next, in order

**1. Finish the observation harness (`tools/observe/`).**
`CONTRIBUTING.md` ranks a real observation diff above any amount of code,
because no catalog entry may ship without one. Until this exists the catalog
cannot grow, and until the catalog grows there is nothing to detect.

The services domain is done and works on a real machine. What is left, roughly
in value order:

1. **Filesystem** — path, size, SHA-256, and Authenticode signer. `docs/16`
   calls signer clustering "the single most useful signal", and it is the one
   thing that separates an installer's additions from Windows Update noise
   without an ignore list at all.
2. **Registry**, both WOW64 views. Needed before any catalog entry can name a
   key, and `wow64_both_views_produce_distinct_artifacts` in
   [`12`](12-TESTING-STRATEGY.md) is waiting on it.
3. **`suggest`** — the draft entry generator. It must build on
   `wardsweep_core::catalog::schema` rather than define the shape a second time,
   or drafts drift from the schema and only `catalog-verify` finds out.
4. Scheduled tasks, firewall, event sources, environment.
5. **`redact`** — `docs/16` requires it before a raw snapshot may be shared, and
   nothing should be shared until it exists.

On the spike gate in [`13`](13-P0-SPIKES.md): six spikes still have no verdict,
and the gate says feature work waits for all seven. The harness is the exception
that proves the rule rather than a breach of it — **S2 needs
`observe intersect` across several titles and S7 needs the residue diff**, so
this is the measuring instrument the remaining spikes are blocked on, not a
feature they are blocking. Nothing else should start ahead of them.

Snapshot → diff → suggest, per [`16`](16-OBSERVATION-HARNESS.md). Read-only, no
removal path, a separate binary from the broker.

**2. Run S1 and S2**, which S3 has now unblocked, in parallel. **Read
[`15`](15-TEST-MACHINE-PROTOCOL.md) before S1 touches real hardware** — the
failure mode is an unbootable machine.

**3. `core/src/safety/refcount.rs` and the ownership graph.**
Pure logic, testable on Linux, and it carries the G1 invariant. Six of the
fourteen named tests in [`12`](12-TESTING-STRATEGY.md) are waiting on it. Model
it over an evidence collection rather than a live machine, or the "other user
profile" and "other volume" cases from S2 cannot be tested at all.

**4. The detection engine (`core/src/scan/`), and then v0.1.**

S1, S2 and S4–S7 remain unrun.

Deferred test coverage is tracked in [`spikes/README.md`](../spikes/README.md):
five of the fourteen named tests are done, one is partial, eight are waiting on
code that does not exist yet.

## Open, needs a maintainer decision

- **Nothing blocking.** The one Safety Gate question raised during M0 — whether
  a volume serial number engages G3 — was ruled on: refused, with the
  Authenticode cache partitioned per volume instead. See the grey-areas table in
  [`02`](02-SAFETY-GATE.md) and the rationale in `CHANGELOG.md`.
- S3 amended [`08`](08-IPC-PROTOCOL.md) rather than raising a question, because
  every change narrowed the contract to what the platform actually does. If any
  of the five is contentious, `spikes/S3-RESULT.md` records the measurement
  behind it.

## What S3 changed, in one place

Detail is in [`spikes/S3-RESULT.md`](../spikes/S3-RESULT.md); these are the
consequences that outlive the spike.

- **Events need `seq`, `Hello` needs `resume_from`.** Reconnection was
  unimplementable without them, not merely unimplemented.
- **The broker needs overlapped I/O.** A synchronous pipe handle serialises a
  write behind a pending read — measured at 2 735 ms against a 0 ms control — so
  streaming and `ScanCancel` cannot coexist on one.
- **`FILE_FLAG_FIRST_PIPE_INSTANCE` on every creation.** It is what makes the
  unelevated-to-elevated handover fail closed instead of into a squatter's pipe.
- **A DACL readback never string-matches the SDDL that was requested.** Generic
  rights are mapped at creation: `GA` returns as `FA`, `GRGW` as `0x12019F`.
- **The UI may not reference `System.IO.File` or `Directory`** — the
  architecture test reads the TypeReference table, so a call inside a method
  body counts. `FileStream` is fine; the broker creates directories.
- **`jobs.db` is not self-contained without its `-wal`.** Uncheckpointed, the
  base file had no schema at all. Anything that copies it alone — a diagnostics
  bundle, a backup — copies a header.
- **`Microsoft.Data.Sqlite` 10.0.0 fails the transitive vulnerability gate**
  (`SQLitePCLRaw.lib.e_sqlite3` 2.1.11, GHSA-2m69-gcr7-jv3q). 10.0.11 is clean.

## Known gaps

- `tools/observe` captures one of seven domains. This is visible in every
  snapshot and every diff rather than implied, but it does mean **no diff from
  this build is yet sufficient for a catalog entry** — `docs/16`'s review
  checklist asks for paths, registry keys and a verified signer CN, none of
  which are collected.
- The harness can describe a machine that already has an anti-cheat installed.
  That is a *detection*, not an observation: `CONTRIBUTING.md` requires a
  before/after cycle, and `docs/16` §"The uninstall-and-reinstall cycle" is the
  procedure for recovering a clean baseline from a machine where the game was
  installed first.

- `THIRD-PARTY-NOTICES.md` staleness is not checked by CI. Needs `cargo-about`
  configuration and a `dotnet-project-licenses` run. Worth closing before the
  first release, since it is a GPL obligation.
- `release.yml` is unverified. It only runs on a tag, so the packaging fixes and
  action version bumps in it have never executed.
- No peak-RSS measurement, and no benchmark regression threshold — only the
  absolute hard-fail budgets. [`10`](10-PERF-BUDGET.md) says which.
- `Strings.ja.resx` does not exist. `CLAUDE.md` lists EN/VI/JA; `docs/19` defers
  Japanese to v1.x.

## Verifying a checkout locally

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic
cargo test --all-features --workspace
cargo deny check advisories bans licenses sources
cargo bench --bench scan_corpus && python .github/scripts/check_bench_budget.py
dotnet restore WardSweep.sln --locked-mode
dotnet build WardSweep.sln -c Release --no-restore
dotnet format WardSweep.sln --verify-no-changes --severity warn --no-restore
dotnet test WardSweep.sln -c Release --no-build
```

To reproduce the ubuntu lint job from Windows — this is the check that catches a
Windows dependency leaking into the portable crates:

```bash
rustup target add x86_64-unknown-linux-gnu
CARGO_TARGET_DIR=target-linux cargo clippy --target x86_64-unknown-linux-gnu --all-targets --all-features -- -D warnings -W clippy::pedantic
```

It needs no cross-linker, because clippy only emits metadata and never links. If
it ever fails with a `cc` error, a C-backed crate has escaped
`[target.'cfg(windows)'.dependencies]`.

## Things that are easy to get wrong

- **The catalog signature covers raw bytes.** `.gitattributes` marks
  `catalog/*.toml` as `-text` for that reason. Removing it makes verification
  fail on Linux CI in a way that looks like a cryptography bug.
- **`*.xaml` is stored CRLF.** XamlStyler emits CRLF and has no setting to
  change it, so the repository default of `eol=lf` made the check pass locally
  and fail on every fresh checkout.
- **Windows dependencies belong under `[target.'cfg(windows)'.dependencies]`,
  never behind a cargo feature.** CI lints with `--all-features` on ubuntu.
- **The .NET ignore pattern in `.gitignore` is scoped to `ui/`** rather than
  matching `bin/` anywhere. Cargo puts binary crate roots in `src/bin/`, so the
  conventional pattern silently excludes `cli/src/bin/` — both Rust
  executables — from the repository.
- **The catalog signing key is not in this repository** and must never be. The
  public half is `catalog/pubkey.hex`, which is both compiled into the broker
  and passed to CI, so the two cannot drift.
