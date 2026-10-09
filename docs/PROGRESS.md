# Progress and next steps

Where the project actually stands, and what to pick up next. `CHANGELOG.md`
records what happened; this file records what is true now and what is not done.

Last updated **2026-10-08**, after an audit of the whole tree and the work that
followed it the same day — see "The 2026-10-08 audit" below.

---

## Where this is

The repository builds, CI runs and is green, and **nothing here can delete
anything**. That is the intended state: `docs/19-ROADMAP.md` makes v0.1
audit-only, and `docs/13-P0-SPIKES.md` gates all feature work behind seven
recorded verdicts, of which **one exists** (S3, below).

M0 delivered the parts that had to come before any of that: a workspace shaped
to what CI requires, the safety gate's first real code, and a catalog integrity
gate that runs on every relevant change.

Since then, **S3 has been run and passed** — the first of the seven verdicts,
and the root of the dependency graph. It changed `docs/08-IPC-PROTOCOL.md` in
five places and left `docs/03-ARCHITECTURE.md` untouched: the split-privilege
architecture survived contact, its protocol did not survive it unamended.

Two anti-cheats have since been observed through their own uninstallers, one of
them through a full uninstall-and-reinstall cycle. AntiCheatExpert left
**nothing of its own**; Riot Vanguard left two files and two empty directories,
which its own reinstall did not reset either. A third, EA AntiCheat, has been
observed installing from a clean baseline; its uninstall is next. **That is the honest scale of the
residue problem so far**, and it is a long way from what the subject is usually
claimed to be. Anyone picking this up should know that before deciding how loud
the product's claims are allowed to be.

What the observations produced instead was method, and most of it came from
tools being wrong rather than from anti-cheats being interesting:

- **WMI reports a driver as present after it is gone.** SCM is the authority.
- **A snapshot spans five minutes and is not an instant**, and one anti-cheat's
  start type changed inside that window, so two domains of one file disagreed.
- **A reboot between two snapshots was invisible**, which put the wrong cause in
  the record until the uptime was checked by hand.
- **A directory left standing and empty produced no record at all** — the
  clearest residue on the machine was the one thing the diff could not mention.
- **`suggest` claimed `view = "both"` for every registry key**, including one
  that exists in a single WOW64 view, on grounds that were never true of this
  harness.
- **The observation writes to the machine it observes**: an Explorer
  `TypedPaths` value named the anti-cheat and survived the uninstall.

Five of those six were only visible because there was a *second* anti-cheat to
compare against. A third would probably be worth more than the next feature.

## What exists and is verified

| Area | State |
|---|---|
| Cargo workspace, .NET solution, toolchain pins | Done |
| `core/src/safety/paths.rs` — canonicalisation | Done. Extended-length, UNC, device, NT-object, drive-relative and 8.3 forms all collapse or are refused; trailing dots and spaces are stripped in any mix, and dots-only components and NTFS stream syntax are refused, each checked against `GetFullPathNameW`. |
| `core/src/safety/denylist.rs` — the deny-list | Done, with the adversarial path table from [`12`](12-TESTING-STRATEGY.md). Cannot be widened by a catalog; carve-outs are earned per anti-cheat entry, and a game entry earns none. Refuses folders and keys that hold other software when targeted as a whole, Windows-owned subtrees, and inbox driver and service names. |
| `core/src/catalog/` — schema, Ed25519, integrity checks | Done |
| `tools/catalog/` — `wardsweep-catalog` | Done. Implements the six invocations `catalog-verify.yml` runs, with a parity test; `sign` refuses a catalog any of them would refuse. |
| `cli/` — `wardsweep catalog …`, `wardsweep observe …` | Verifies the signature **and** runs the four integrity checks before using a catalog, and warns when `minimum_app_version` is newer than the build. `observe` runs the harness from beside the CLI, never from `PATH`. |
| `catalog/catalog.toml` | Signed, and **empty of entries** on purpose — see below |
| `core/benches/scan_corpus.rs` | Done, gated on the hard-fail budgets in [`10`](10-PERF-BUDGET.md) |
| `ui/` — WPF shell | Shell only, plus the architecture tests that assert the UI has no destructive code path |
| CI — Rust, .NET, CodeQL (C#, Rust, Actions), Catalog Verify, weekly dependency audit | Done, inline in this repository, least-privilege, third-party actions pinned to SHAs, all green |
| Spike S3 — split-privilege architecture | **PASS.** All six criteria measured — 23 checks, 0 failed. `spikes/S3-RESULT.md`. Throwaway code in `spikes/s3-split-privilege/`, unreachable from either build. |
| `observations/2026-08-19-anticheatexpert/` | **First real observation.** Uninstall half of the `docs/16` cycle, committed with its diff, draft entry and notes. The reinstall half now needs a new full cycle: its raw snapshots are gone (next step 1). |
| `observations/2026-10-09-ea-anticheat/` | **First observation from a clean baseline.** EA AntiCheat's install, by FC 26's first launch through Steam's install script: a service, a minifilter driver SCM does not list and whose image is absent while no game runs, and EA's own record of the games that installed it. Draft scoped with `--only` and pinned by a test. The residue half is next (step 1). |
| `tools/observe/` — the observation harness | **`snapshot`, `diff`, `suggest`, `intersect`, `redact`, `refilter`.** Services, filesystem and registry, with Authenticode signer clustering and both WOW64 views. Never records account identity, credentials, activity history or G3 material, in the registry or on disk, and the differ re-applies that policy to older snapshots. Snapshot format 2 also records registry keys left standing with no value and oversized values by size, and `diff` refuses to compare across formats. A draft entry is generated from the shipped schema, is proven to load through the real parser, and each committed draft is pinned by a test to its committed diff. Scheduled tasks, firewall, event sources and environment are named as `not_captured` rather than omitted. |

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
- **The scanner**, the plan builder, refcount and IPC.

## The 2026-10-08 audit

A read of the whole tree, pull requests #18–#29. What it found, in order of
consequence:

- **Personal data had reached the public repository.** Two committed Riot
  Vanguard diffs carried the contributor's Microsoft-account identity and the
  machine's name; all three committed diffs carried activity history. The
  harness now never records either (`tools/observe/src/policy.rs`), the differ
  applies that to snapshots older builds took, `redact` catches e-mail
  addresses and machine names, and the committed diffs were refiltered with
  the committed tools. Nothing that names an anti-cheat changed in them.
- **The harness read what Safety Gate G3 forbids reading**: a MAC-bearing
  DHCPv6 identifier, TPM state, Bluetooth device addresses and volume GUIDs,
  all in raw snapshots that never left the machine. Excluded now.
- **Five spellings slipped past the deny-list**, each checked against
  `GetFullPathNameW`, and **game entries could borrow an anti-cheat's
  carve-outs** — a path to a G1 violation through the catalog gate. Fixed with
  maintainer sign-off; `CHANGELOG.md` records the ruling.
- **The tooling said false things**: services compared without coverage, two
  per-user service instances collapsed into one record, every added driver and
  service drafted whether or not it was the publisher's, profile names left in
  draft paths, a service enumeration that aborted on `ERROR_MORE_DATA`,
  directories called empty that the walk had chosen not to look inside.
- **CI was narrower than it looked**: CodeQL analysed C# only, advisories were
  checked only when Rust files changed, and the release workflow gave every job
  write access and spliced a typed input into a script.

What it did not do is in "Open, needs a maintainer decision" below.

### The same day, after the audit

Pull requests #38 onwards, once the maintainer approved the proposals:

- **The broader deny-list hardening was approved and shipped** (#38): whole
  profiles, `AppData` roots, game library containers, Windows-owned subtrees,
  container registry keys and inbox driver and service names. `CHANGELOG.md`
  records the ruling.
- **Dependabot's first round was taken as one verified set** (#39). `sha2` 0.11
  needed a code change, and `criterion` stays below 0.8 on purpose, with the
  reason in `dependabot.yml`.
- **Snapshot and diff format 2** (#40) closed five harness gaps in one version
  bump, the registry's empty-key blind spot first among them. The committed
  diffs were upgraded to it (#42), and `redact` no longer flattens a diff onto
  one line (#41).
- **`observe intersect`** (#43), the last subcommand `docs/16` described.
- **`suggest --removed`** (#45): both committed drafts are now rebuilt from
  their committed diffs and pinned by tests.
- **Third-party notices are generated and checked** (#46): `licenses/rust.md`
  and `licenses/dotnet.md`, with the licence texts, regenerated offline from
  the lock files, compared in CI, and packed into every release.
- **CodeQL's first Rust analysis raised three alerts**, all
  `rust/cleartext-logging` and all name matches: two test loops over fake
  values in a variable called `secret`, and `keygen` printing the *path* of the
  key it wrote. Each was dismissed with its reason; nothing real was logged.
- **A snapshot is bound by the disk.** It reads about 100 GB, and one build
  measured three and a half and ten minutes on the same day; a suspected
  regression from the dependency refresh was ruled out by running the older
  build back to back with the new one.
- **The hardened deny-list costs more and still fits.** Measured with
  `scan_corpus` after #38: canonicalising a path takes about 0.4 µs, much as it
  did on 2026-08-12, and checking it against the deny-list about 35 ns, five to
  six times the August figure — together about a fifth of a second for half a
  million paths, against the 15 s audit budget in
  [`10`](10-PERF-BUDGET.md). A first run on a busy machine measured twice as
  long and was briefly recorded here; criterion's ratios are only as good as
  the moment their baseline was taken.

*Later that day the maintainer delegated the open decisions — "whatever is
most optimal" — and they were settled as follows.*

- ***The harness ships, as a separate download.*** `wardsweep observe` forwards
  to it, and releases carry it in a zip of its own rather than inside the
  installer, which keeps a binary that reads the whole machine away from the
  package whose antivirus record matters (see [`14`](14-DISTRIBUTION-TRUST.md)).
- ***Unredirected registry roots stay read through both views.*** The second
  copy is 7.9 % of a snapshot's registry records, and the whole registry walk
  takes seconds of a capture measured in minutes, so the saving is small;
  reading them once would change what `suggest` writes about their view and
  need another snapshot format. Recorded in the collector.
- ***The G3 test stays unable to tell a reader from a refuser.*** An exemption
  for code that refuses identifiers is one a reader could later hide behind.
  The rule instead is the one the registry collector already follows: a list
  that refuses identifiers is data outside every `.rs` file, loaded with
  `include_str!` and tested from the file, so naming one in Rust source stays
  an error. Recorded in `core/tests/no_destructive_code.rs`.

## Next, in order

**0. Settled: Vanguard lowers its own driver minutes into a boot.**
Read on 2026-10-09 from the System event log rather than by rebooting: `vgk`
was lowered to `demand` three times, each 4–10 minutes into a boot that began
with it higher, and each by the SYSTEM account — Vanguard's own service, not the
maintainer and not the harness. The only boots that began higher without a
lowering ended inside ten minutes. In three weeks nothing but the installer
wrote `system start`. The maintainer's account is confirmed for the lowering;
whether a working install raises it again before a reboot is still unseen.
Detail in `observations/2026-08-19-riot-vanguard/notes.md`.

Vanguard is **installed but not working** on this machine: its service
terminated with error 1 thirty-eight times on 2026-10-09, four reinstalls that
day did not change that, and no Code Integrity block explains it. Until it
works, step 2 cannot be done here.

**1. Finish the 2026-10-09 cycle: ACE and EA AntiCheat.**
Every snapshot in it comes from one collector, pinned for the cycle. `00` is
the baseline and `01` followed FC 26's first launch; the diff between them is
EA AntiCheat's install footprint, committed. Next:

- Neverness To Everness finishes updating (done by 17:27Z on 2026-10-09) and is
  launched once, which installs ACE. Snapshot `02`; the diff from `01` is ACE's
  install footprint.
- Uninstall FC 26 through Steam, whose install script runs EA's uninstaller.
  Snapshot `03`; the diff from `02` is EA AntiCheat's residue.
- Uninstall NTE, and ACE through its own uninstaller. Snapshot `04`; the diff
  from `03` is ACE's residue.
- After the cycle, restart and ask SCM about `EAAntiCheat` again.

**Earlier plan for ACE, which the cycle above replaces:**
The uninstall half is done and committed at
`observations/2026-08-19-anticheatexpert/`. ACE is not installed on this
machine at present (checked 2026-10-09), so the cycle starts with the game
client installing it — the step that failed twice in August. The plan was one
game launch and a diff against the `01-uninstalled` snapshot, but the raw snapshots are no longer
at `%LOCALAPPDATA%\WardSweep\observations\` (checked 2026-10-08), and a format
1 snapshot cannot be diffed against a format 2 one anyway. So: snapshot with
ACE installed, uninstall through the official uninstaller, snapshot, start
Neverness To Everness so it reinstalls ACE, snapshot — and the residue half is
measured again, with the format 2 harness, which can now see an emptied key.

The half that already exists is the one [`16`](16-OBSERVATION-HARNESS.md) says
"alone justifies the cycle", and its answer was that **ACEVILLE's uninstaller
leaves nothing of its own**. A project that sweeps residue has to report that as
readily as the opposite.

**2. A second title carrying Riot Vanguard** — blocked on this machine while
Vanguard is failing (step 0).
The Vanguard cycle is complete — both halves — and committed at
`observations/2026-08-19-riot-vanguard/` with a `draft.toml`. What the draft
cannot have is `shared = false`, and it must not get it from one title:
[`04`](04-CATALOG-SCHEMA.md) is explicit that a wrong `shared = false` is the G1
violation this project exists to prevent. Only a second observed title changes
that, and the same holds for AntiCheatExpert.

Vanguard is **the first anti-cheat observed here that leaves anything behind**:
two files under `%LOCALAPPDATA%` and two empty directories under
`%ProgramFiles%`, against a removal of 207 MB, two services and every registry
key it owned — and its own reinstall does not reset those two files either. It
cost the tooling three defects, all fixed there: a snapshot did not record which
boot it belonged to, an emptied directory produced no record at all, and
`suggest` claimed `view = "both"` for every registry key on the false grounds
that the observation could not tell.

Two facts worth carrying forward. No reboot was required, contrary to
expectation, because the client was closed and `vgk` was not loaded. And **`vgk`
is installed at `SYSTEM_START` but reads `demand` on a machine that has been up
for hours** — `docs/16` infers `risk` from a value that moves, so a late
observation records the later reading and calls it the fact. The endpoints are
measured; the transition between them has never been caught, and a 35-minute
poll straight after the install saw no change at all.

**3. Feed `observe intersect`.**
Written on 2026-10-08 and waiting for input: it turns footprints of one
anti-cheat under several titles into the shared footprint, which is what makes
a `shared = true` entry right and what S2 starts from. It needs at least two
titles' footprints, each from a machine where the anti-cheat was not already
installed — item 2 is the first such pair.

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
- EA AntiCheat keeps a record of the games that installed it under
  `HKLM\SOFTWARE\EA\AC\Installs`, one name per game. That makes it a lead for the
  resolver to cross-check, never a count: the ACE uninstall entry above was a
  vendor record too, and it named a game that was gone.

## Open, needs a maintainer decision

- **Nothing blocking.** The one Safety Gate question raised during M0 — whether
  a volume serial number engages G3 — was ruled on: refused, with the
  Authenticode cache partitioned per volume instead. See the grey-areas table in
  [`02`](02-SAFETY-GATE.md) and the rationale in `CHANGELOG.md`.
- S3 amended [`08`](08-IPC-PROTOCOL.md) rather than raising a question, because
  every change narrowed the contract to what the platform actually does. If any
  of the five is contentious, `spikes/S3-RESULT.md` records the measurement
  behind it.
- **Deny-list containers are lists, and lists drift.** Since 2026-10-08 the
  deny-list refuses whole profiles, `AppData` roots, game libraries, container
  registry keys, Windows-owned subtrees and inbox driver and service names (see
  `CHANGELOG.md`). Each list is written from what Windows and the three
  launchers lay out today; a new standard profile folder, a new launcher's
  library layout, or a new inbox driver is not covered until someone adds it.
  Worth a review whenever a new launcher or Windows release is observed.

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
  everywhere, in any letter case, but only on token boundaries — so a name
  embedded in a longer word survives. The tool reports the residue with each
  occurrence in context and exits non-zero so a script cannot publish the
  result by accident; a person still reads the file. Its earlier report called
  every such residue "`Anonymous` and the like", which was not true of two
  committed diffs: account identity reached the repository that way. All three
  committed diffs were refiltered and re-redacted on 2026-10-08 (see the
  observation notes), and the harness no longer records account identity or
  activity history at all.
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
- **`suggest` has no way to be told what survived an uninstall.** Residue is by
  definition *unchanged* between the two snapshots, so it appears in a diff as
  nothing at all — not added, not removed — and can only be recovered by
  comparing against a clean baseline. `docs/16` §"The uninstall-and-reinstall
  cycle" exists precisely because the available machines have the game installed
  already and therefore have no clean baseline. So the `--residue` input, which
  `docs/16` calls the more valuable of the two, is unfillable on exactly the
  machines the document contemplates. Riot Vanguard's residue is known to the
  byte and its committed draft cannot carry it.
  The related and cheaper problem is fixed: `suggest` consumed only `added`
  changes, so the AntiCheatExpert draft came from a removal diff reversed by a
  script nobody kept. `suggest --removed` (2026-10-08) reads such a diff the
  other way round, and both committed drafts are now rebuilt from their
  committed diffs and pinned by tests. The rebuilt AntiCheatExpert draft leaves
  out `ACE-ADVT`, which nothing in the diff ties to the publisher, and names it
  for a reviewer instead; its notes have the evidence to add it back.
- The harness can describe a machine that already has an anti-cheat installed.
  That is a *detection*, not an observation: `CONTRIBUTING.md` requires a
  before/after cycle, and `docs/16` §"The uninstall-and-reinstall cycle" is the
  procedure for recovering a clean baseline from a machine where the game was
  installed first.

- **The committed diffs are format 1 snapshots underneath.** Snapshot format 2
  (2026-10-08) closed the empty-key blind spot, records oversized values, stops
  double-walking `WOW6432Node` and fixes the service-type labels, but none of
  that can be applied to a snapshot already taken, and the raw snapshots behind
  the committed diffs are gone. Their `emptied_keys` is `null` — not known —
  and they say `snapshot_format_version: 1`. Only a new observation fills it.
- `HKLM\SYSTEM\CurrentControlSet\Services` and `HKCU\SOFTWARE` are walked in
  both WOW64 views although neither is redirected (apart from a few `Classes`
  subkeys), so every key under them is recorded twice, once per view: 7.9 %
  of a snapshot's registry records are the second copy. Harmless — `suggest`
  reports such keys as `view = "both"`, which they are — but not free. Kept on
  purpose: see "The same day, after the audit".

- `release.yml` is unverified. It only runs on a tag, so the packaging fixes,
  action version bumps and the 2026-10-08 permission and input changes have
  never executed.
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
dotnet tool restore && dotnet xstyler --passive --recursive --directory ui
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
- **A `cfg(windows)` split can make a shared helper dead code off Windows**, and
  Windows clippy will never say so. `#[cfg(not(windows))]` on the *public*
  function leaves anything only its Windows twin called unreachable, and
  `-D warnings` turns that into a build failure on the ubuntu job alone. Put the
  `cfg` on the smallest thing that genuinely differs — "can this platform answer
  at all?" — and let the shared code stay shared. `collect/boot.rs` is the
  worked example: the split is on `uptime_ms`, not on `boot_session`.
  **Run the ubuntu lint below before pushing**, not after CI says so; it takes
  seconds and this failure mode has cost a round trip.
- **The .NET ignore pattern in `.gitignore` is scoped to `ui/`** rather than
  matching `bin/` anywhere. Cargo puts binary crate roots in `src/bin/`, so the
  conventional pattern silently excludes `cli/src/bin/` — both Rust
  executables — from the repository.
- **The catalog signing key is not in this repository** and must never be. The
  public half is `catalog/pubkey.hex`, which is both compiled into the broker
  and passed to CI, so the two cannot drift.
