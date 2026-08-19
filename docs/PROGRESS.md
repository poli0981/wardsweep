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

Two anti-cheats have since been observed through their own uninstallers.
AntiCheatExpert left **nothing of its own**; Riot Vanguard left two files and
two empty directories. That is the honest scale of the residue problem so far,
and it is a long way from what the subject is usually claimed to be. What the
observations produced instead was method: a detection API that reports a driver
as present after it is gone, an anti-cheat that rewrites its own driver's start
type, a registry value the observation itself wrote and nearly attributed to its
subject, and two harness blind spots that hid evidence.

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
| `observations/2026-08-19-anticheatexpert/` | **First real observation.** Uninstall half of the `docs/16` cycle, committed with its diff, draft entry and notes. Reinstall half pending. |
| `tools/observe/` — the observation harness | **`snapshot`, `diff`, `suggest`, `redact`.** Services, filesystem and registry, with Authenticode signer clustering and both WOW64 views. A draft entry is generated from the shipped schema and is proven to load through the real parser. Scheduled tasks, firewall, event sources and environment are named as `not_captured` rather than omitted; `intersect` is not written. |

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

**1. Finish the AntiCheatExpert observation — one game launch.**
The uninstall half is done and committed at
`observations/2026-08-19-anticheatexpert/`. To finish it: start Neverness To
Everness so it reinstalls ACE, take a snapshot, and diff `01-uninstalled`
against it for the true install footprint. The earlier snapshots are at
`%LOCALAPPDATA%\WardSweep\observations\`.

The half that already exists is the one [`16`](16-OBSERVATION-HARNESS.md) says
"alone justifies the cycle", and its answer was that **ACEVILLE's uninstaller
leaves nothing of its own**. A project that sweeps residue has to report that as
readily as the opposite.

**2. Finish the Riot Vanguard observation — one game launch.**
The uninstall half is done and committed at
`observations/2026-08-19-riot-vanguard/`. To finish it: start VALORANT so it
reinstalls Vanguard, snapshot, and diff for the install footprint. No catalog
draft is committed until then — the removal footprint is known and the install
footprint is not, and [`16`](16-OBSERVATION-HARNESS.md) requires an entry to
come from an observation rather than from half of one.

Vanguard is **the first anti-cheat observed here that leaves anything behind**:
two files under `%LOCALAPPDATA%` and two empty directories under
`%ProgramFiles%`, against a tidy removal of 207 MB, two services and every
registry key it owned. It also cost the harness two blind spots, both fixed in
that observation — a snapshot did not record which boot it belonged to, and an
emptied directory produced no record at all.

Note that no reboot was required, contrary to expectation, because the client
was closed and `vgk` was therefore not loaded.

**3. `observe intersect`.**
The last unwritten subcommand. The intersection of the same anti-cheat observed
across three titles is what makes a `shared = true` footprint right, and it
feeds S2 directly.

**4. Run S1 and S2**, which S3 unblocked, in parallel. **Read
[`15`](15-TEST-MACHINE-PROTOCOL.md) before S1 touches real hardware** — the
failure mode is an unbootable machine. S2 should start from the evidence already
gathered, below.

**5. `core/src/safety/refcount.rs` and the ownership graph.**
Pure logic, testable on Linux, and it carries the G1 invariant. Six of the
fourteen named tests in [`12`](12-TESTING-STRATEGY.md) are waiting on it. The
three S2 findings below are what it has to be right about.

**6. The detection engine (`core/src/scan/`), and then v0.1.**

The remaining harness domains — scheduled tasks, firewall, event sources,
environment — are worth adding when an observation actually needs one, not
before. Nothing observed so far has.

S1, S2 and S4–S7 remain unrun.

Deferred test coverage is tracked in [`spikes/README.md`](../spikes/README.md):
five of the fourteen named tests are done, one is partial, eight are waiting on
code that does not exist yet.

## Evidence gathered for spikes that have not run

Recorded here so it is not lost between now and the spike.

**S2 — shared anti-cheat reference counting.** Determining which installed games
reference ACE took three attempts by hand on a machine that had the answer on
it, and the first attempt was wrong in the direction that violates G1. Full
account in `observations/2026-08-19-anticheatexpert/notes.md`; three findings
that S2 should start from rather than rediscover:

- Absence of a game from the library paths you thought to check is not evidence
  of absence. The game was in a path none of the obvious roots covered. A
  refcount resolver must enumerate libraries from launcher manifests.
- An anti-cheat's own uninstall entry names the game that **installed** it, not
  the games that **need** it, and is not updated when that game is removed.
  Useful as a lead, never as a count — it over-counted here by naming a game
  that had been uninstalled.
- Three kernel-class anti-cheats were found on one ordinary developer machine
  (Vanguard, AntiCheatExpert, EA Javelin), two of them only by enumerating
  rather than by looking for names already known.

## Open, needs a maintainer decision

- **Nothing blocking.** The one Safety Gate question raised during M0 — whether
  a volume serial number engages G3 — was ruled on: refused, with the
  Authenticode cache partitioned per volume instead. See the grey-areas table in
  [`02`](02-SAFETY-GATE.md) and the rationale in `CHANGELOG.md`.
- S3 amended [`08`](08-IPC-PROTOCOL.md) rather than raising a question, because
  every change narrowed the contract to what the platform actually does. If any
  of the five is contentious, `spikes/S3-RESULT.md` records the measurement
  behind it.
- **The G3 test cannot tell a reader from a refuser, and this now matters.**
  `core/tests/no_destructive_code.rs` fails the build if a hardware-identity
  string appears in any `.rs` file under a shipped `src/`. That is the right
  rule for code that *reads* an identifier and the wrong one for a deny-list
  that *refuses* one — a G3 deny-list written in Rust is rejected by the gate it
  enforces, and so are its tests.

  The registry collector works within the rule rather than around it: the list
  lives in `tools/observe/src/collect/g3-identity-terms.txt`, is loaded with
  `include_str!`, and its tests are driven from the file instead of naming
  terms. That is arguably better — a deny-list is data, shipped and reviewable,
  the way [`16`](16-OBSERVATION-HARNESS.md) asks noise rules to be — but it
  also means a reviewer reading the test would not expect the terms to exist
  anywhere. **Worth a maintainer's ruling on whether the test should make the
  distinction explicit.**

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

- `tools/observe` captures three of seven domains. This is visible in every
  snapshot and every diff rather than implied. A diff from this build covers
  what `docs/16`'s review checklist asks about — services, paths, registry keys
  and a signer CN — and `suggest` turns one into a draft entry that is proven
  to load through the shipped parser.
- A snapshot takes about three and a half minutes and 156 MB on a developer
  machine, against [`16`](16-OBSERVATION-HARNESS.md)'s original 40–120 MB
  estimate. The document now records the measurement. Hashing and the signer
  lookup are parallel; the remaining cost is the walk itself.
- **`redact` removes identity, not secrets, and cannot promise completeness.**
  It learns account names from profile-rooted paths and replaces them
  everywhere, but only on token boundaries — so a name embedded in a longer
  word survives. On the development machine 284 446 substitutions were applied
  and 83 occurrences remained, every one of them the English word
  `Anonymous` rather than the account. The tool reports the residue and exits
  non-zero so a script cannot publish the result by accident; a person still
  reads the file.
- **The harness has been wrong twice about what it could see, and both times
  the wrong answer looked like a clean result.** A directory left standing and
  empty produced no record at all, so the clearest residue Riot Vanguard left
  was the one thing the diff could not mention; and a snapshot did not record
  which boot it belonged to, so a reboot between two captures was invisible and
  a driver's start-type change went into the record with the wrong cause. Both
  are fixed, both are reported as `null` rather than `false`/`[]` when a
  snapshot predates them, and the general lesson is the one worth keeping: a
  domain this harness does not model is not a domain where nothing happened.
  Scheduled tasks, firewall rules, event sources and environment are still
  unmodelled.
- **`suggest` cannot read the first diff an observation produces.** It consumes
  only `added` changes, so it needs an install diff — clean → installed. But
  `docs/16` §"The uninstall-and-reinstall cycle" exists precisely because the
  machines available have the game installed already, so the first artefact of
  every observation so far has been a *removal* diff, in which everything is
  `removed`. The AntiCheatExpert draft was produced by inverting one with an
  ad-hoc script that was never committed, which means **that draft is not
  reproducible from the committed artefacts.** Either `suggest` should accept a
  removal diff directly or the inversion should be a subcommand; deciding which
  is worth doing before the second draft is written.
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
