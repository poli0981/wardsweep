# Progress and next steps

Where the project actually stands, and what to pick up next. `CHANGELOG.md`
records what happened; this file records what is true now and what is not done.

Last updated at milestone **M0 — Foundation**.

---

## Where this is

The repository builds, CI runs and is green, and **nothing here can delete
anything**. That is the intended state: `docs/19-ROADMAP.md` makes v0.1
audit-only, and `docs/13-P0-SPIKES.md` gates all feature work behind seven
recorded verdicts, of which **zero exist**.

M0 delivered the parts that had to come before any of that: a workspace shaped
to what CI requires, the safety gate's first real code, and a catalog integrity
gate that runs on every relevant change.

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

**1. Run spike S3 — split-privilege architecture.**
It is the root of the dependency graph in [`13`](13-P0-SPIKES.md): S3 → S1 → S5
and S3 → S2 → S5. Nothing else is testable without it, and it decides whether
the elevated-broker design survives at all. Throwaway code in `spikes/`, which
is excluded from the workspace and absent from `WardSweep.sln` so neither build
can reach it. The deliverable is `spikes/S3-RESULT.md`, not a merged
implementation.

**2. Build the observation harness (`tools/observe/`).**
`CONTRIBUTING.md` ranks a real observation diff above any amount of code,
because no catalog entry may ship without one. Until this exists the catalog
cannot grow, and until the catalog grows there is nothing to detect. Snapshot →
diff → suggest, per [`16`](16-OBSERVATION-HARNESS.md). Read-only, no removal
path.

**3. `core/src/safety/refcount.rs` and the ownership graph.**
Pure logic, testable on Linux, and it carries the G1 invariant. Six of the
fourteen named tests in [`12`](12-TESTING-STRATEGY.md) are waiting on it. Model
it over an evidence collection rather than a live machine, or the "other user
profile" and "other volume" cases from S2 cannot be tested at all.

**4. The detection engine (`core/src/scan/`), and then v0.1.**

Deferred test coverage is tracked in [`spikes/README.md`](../spikes/README.md):
five of the fourteen named tests are done, one is partial, eight are waiting on
code that does not exist yet.

## Open, needs a maintainer decision

- **Nothing blocking.** The one Safety Gate question raised during M0 — whether
  a volume serial number engages G3 — was ruled on: refused, with the
  Authenticode cache partitioned per volume instead. See the grey-areas table in
  [`02`](02-SAFETY-GATE.md) and the rationale in `CHANGELOG.md`.

## Known gaps

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
