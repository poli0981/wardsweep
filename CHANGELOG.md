# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

The catalog (`catalog/catalog.toml`) is versioned separately — see
[`catalog/CHANGELOG.md`](catalog/CHANGELOG.md).

## [Unreleased]

### Added
- Initial documentation suite (20 documents).
- Safety gate defined and frozen before any implementation work.
- Seven P0 spikes identified as go/no-go gates.
- Cargo workspace (`wardsweep-core`, `wardsweep-cli`, `wardsweep-catalog`,
  `wardsweep-observe`) and the `WardSweep.sln` solution, laid out to match the
  paths the CI workflows already required.
- Deny-list and path canonicalisation in `core/src/safety/`, with the
  adversarial path table from `docs/12-TESTING-STRATEGY.md`. Canonicalisation is
  a precondition of the type system: the deny-list cannot be handed a raw
  string.
- Catalog schema, Ed25519 verification, and the `wardsweep-catalog` tool
  implementing the six checks `catalog-verify.yml` invokes.
- A signed, entry-free `catalog/catalog.toml` with its public key at
  `catalog/pubkey.hex`, compiled into the broker from the same file CI verifies
  against.
- `scan_corpus` benchmark and its committed seed corpus.
- WPF shell with an architecture test asserting the UI assembly references
  neither the registry nor any filesystem type that can delete.
- `spikes/` scaffolding and result template.
- Spike **S3** (split-privilege architecture) run, with throwaway code in
  `spikes/s3-split-privilege/` and the finding in `spikes/S3-RESULT.md`.
  Verdict **PASS**: all six criteria in `docs/13-P0-SPIKES.md` measured, 23
  assertions in `scripts/run-s3.ps1`, none failed. The audit path is unelevated,
  elevation costs exactly one prompt and it falls at Apply, the pipe is
  restricted, a wrong client image is refused, the broker outlives its UI with
  the event stream resuming gapless, and job state is readable without it.
  Nothing found argues for the single-elevated-process fallback, and
  `docs/03-ARCHITECTURE.md` is unchanged as a result.
- `tools/observe/` — the read-only observation harness, first increment.
  `snapshot` captures every service and driver via the service control manager
  and `diff` compares two snapshots; both run end to end against a real machine
  (805 services, 471 drivers, 52 boot-start on the development machine).
  `suggest`, `intersect` and `redact` are not written yet.
  - A snapshot records **which domains it did not capture**, not only which it
    did. A file that covered part of the machine and did not say so produces a
    diff that looks complete, and every domain it skipped reads as "nothing
    changed there" — the same failure `docs/03-ARCHITECTURE.md` guards against
    by marking an unelevated scan `partial`.
  - Configuration is captured, never running state. An idle machine then
    produces a diff with **zero** entries rather than the thousands
    `docs/16-OBSERVATION-HARNESS.md` warns about, because almost all of that
    noise is state.
  - The noise filter **relocates rather than discards**: a suppressed change
    moves to `suppressed` with the name of the rule that moved it. Its failure
    mode is a rule quietly eating the one service an anti-cheat installed, and a
    filter nobody can audit is one nobody can catch doing it.
  - Per-user service instances collapse to their template name. Measured on a
    real machine: a simulated reboot produces 48 spurious changes unfiltered and
    0 filtered.
  - The service control manager is opened with `SC_MANAGER_ENUMERATE_SERVICE`
    and each service with `SERVICE_QUERY_CONFIG`, so read-only is enforced by
    the handles held rather than by the calls happening not to be made.
- `tools/observe` filesystem domain: path, size, timestamp, SHA-256 and
  Authenticode signer under the roots `docs/16-OBSERVATION-HARNESS.md` names.
  - **Signer clustering works as the document promised.** On the development
    machine it names the entire Riot Vanguard footprint — seven files, one
    publisher — with no path knowledge at all.
  - `diff` compares the two snapshots' filesystem policies and **warns when
    they differ**. Changing an exclusion moves files in and out of a snapshot
    without anything happening on the machine: two development snapshots either
    side of one such change produced 109 differences of which 86 were the
    change, and a later pair produced 31 579. A diff that cannot notice that is
    a diff that invents evidence.
  - Reparse points are never traversed, and are recorded as not-traversed
    rather than silently skipped.
  - `std::fs` rather than raw Win32 for metadata, deliberately: Safety Gate G3
    bans reading a hardware identifier even for reporting, and the Win32
    structures hand you a volume serial number whether you asked or not.
- `tools/observe` registry domain: `HKLM\SOFTWARE`,
  `HKLM\SYSTEM\CurrentControlSet\Services` and `HKCU\SOFTWARE`, in **both
  WOW64 views**, with values but deliberately without timestamps.
  - The view distinctness `docs/12-TESTING-STRATEGY.md` asks about is real: on
    the development machine 2 676 keys exist only in the 32-bit view and 86 344
    only in the 64-bit one, so the two are keyed separately in a diff.
  - **Safety Gate G3 needed defence in depth, and finding that out required
    running it.** Excluding `Microsoft\Cryptography` was not close to enough:
    three unrelated applications had copied the machine identifier into their
    own keys, one had also stored a disk serial, and a telemetry cache held the
    motherboard and CPU model inside a URL. The refusal now matches on value
    name and value data, not only on key path. Refused values are dropped
    rather than masked, and each is recorded with its key and value name —
    never its data — so the refusal is auditable. Result: 54 values refused,
    and no hardware identifier anywhere in the snapshot.
  - The G3 term list is shipped as data rather than as a Rust constant, because
    `core/tests/no_destructive_code.rs` cannot tell a deny-list from a reader
    and would reject the list along with its tests. Flagged in
    `docs/PROGRESS.md` for a maintainer ruling.
- `wardsweep-observe suggest` — a draft catalog entry from an observation diff,
  with the conservative inference table from `docs/16-OBSERVATION-HARNESS.md`.
  - Built as a `wardsweep_core::catalog::schema::AntiCheat` and serialised from
    it, never as hand-written TOML, and a test parses a generated draft back
    through the shipped parser. A draft that does not load would otherwise be
    discovered by a contributor when `catalog-verify` fails on their pull
    request, long after the diff that produced it was forgotten.
  - `shared` is always `true`, `kind` follows the observed driver, and an
    unknown start type resolves to `high` rather than `low`. Every note the
    generator could not decide is printed and written into the file header.
- `wardsweep-observe redact` — replaces account names, machine-local SIDs and
  UNC host names with placeholders.
  - Two passes, because rewriting `\Users\name\` is not enough: on a real
    snapshot that left 213 occurrences behind, in file names and registry keys
    applications had written the account name into. The first pass learns the
    names from profile-rooted paths, the second replaces them elsewhere.
  - Names are learned only from paths rooted at a drive letter. Learning from
    any `\Users\` segment taught it that `desktop.ini`, `guest` and `*` were
    people — from a container layer, an Android source tree and an ASP.NET
    sample — and it then replaced those tokens across the document.
  - Matching is on token boundaries, so an account name inside a longer word
    survives by construction. The tool counts what remains, says so, and exits
    non-zero; it does not claim to have produced a clean file.
- `tools/observe` now records **which boot a snapshot belongs to** and **which
  directories hold no file beneath them**. Both gaps were found by the Riot
  Vanguard observation, and both hid evidence in the direction that reads as
  good news.
  - `boot_session`, derived as wall clock minus `GetTickCount64`, with
    `diff` reporting `rebooted_between`. A restart is the loudest cause of
    change a diff will ever see — drivers load and unload, per-user service
    instances are recreated, pending file renames are carried out — and it
    appears as churn rather than as a restart. The Vanguard start-type finding
    was first recorded with the wrong cause for exactly this reason: the
    machine had rebooted between two snapshots and neither file said so. Two
    derived instants are compared with a two-minute tolerance, because both
    halves of the subtraction drift. Not a G3 concern: a boot instant changes
    at every start and distinguishes no machine from any other.
  - `file_empty_directories`, topmost only, with `diff` reporting
    `emptied_directories`. `files` describes files, so a directory left
    standing and empty produced no record on either side and the diff could not
    mention it. Riot Vanguard's uninstaller removed all twelve of its files,
    both services and every registry key it owned, and left
    `C:\Program Files\Riot Vanguard` and its `Logs` child on disk — **the
    clearest residue on the machine was the one thing the harness could not
    report.**
  - Both fields are optional, and both diff answers are `null` rather than
    `false` or `[]` when either snapshot predates them. An empty list would
    read as "nothing was left behind", which is the one wrong answer this tool
    must never give.
  - Measured before being believed, on two captures seven minutes apart: 18 216
    empty directories exist on the development machine, costing 0.93 % of a
    snapshot, and the **noise floor is zero** in both directions — so no
    suppression rule was added. The derived boot instant matched the Windows
    event log to the second, and two derived instants drifted by 7 ms against a
    120 000 ms tolerance that exists for clock steps rather than for drift.
- `wardsweep-observe suggest` now **derives a registry key's WOW64 view from the
  observation** instead of emitting `both` for everything. The old comment said
  the observation "cannot distinguish *only in one view* from *we only looked
  once*", which was never true of this harness: it opens both views explicitly
  and stamps every record with the one it came from. Riot Vanguard is the
  counter-example — `HKLM\SYSTEM` is not redirected so its two service keys
  really are in both views, while `HKLM\SOFTWARE` is, so its uninstall entry
  exists only in the 64-bit one and the draft was claiming a key nobody
  observed. Narrowing is named in the review notes rather than done quietly.
- `spikes/Directory.Build.props` and `spikes/Directory.Packages.props`, which
  terminate the repository's MSBuild and NuGet inheritance chains. Without them
  a spike project inherits `TreatWarningsAsErrors`, the lock-file policy and the
  global analysers, and any package it needs has to be added to the central
  version file that `dotnet-ci.yml` path-filters on — so throwaway code would
  re-run the whole .NET pipeline and leave a permanent entry behind.
- `observe intersect`: what every footprint of one anti-cheat holds, across
  titles, written as a diff so `suggest` drafts from it. Matched by identity,
  never content, since titles ship different builds; a change kept by any
  footprint stays kept; coverage is what every footprint covered; and it refuses
  fewer than two footprints, the same footprint twice, an intersection as
  input, and footprints from different snapshot formats.
- `observe suggest --removed`, which reads a diff taken from an installed
  machine to an uninstalled one the other way round, so the uninstall half of
  the cycle can be drafted from without a script. The AntiCheatExpert draft is
  rebuilt with it from its committed diff and pinned by a test, as the Vanguard
  draft already was; the rebuild leaves out `ACE-ADVT`, which nothing in the
  diff ties to the publisher, and names it for a reviewer instead.
- Generated third-party notices, checked by CI. `licenses/rust.md` comes from
  `cargo about` over `Cargo.lock` and `licenses/dotnet.md` from the interface's
  `packages.lock.json` and the restored packages, with Velopack included
  because its installer and updater ship in every release. Both carry the
  licence texts, which the hand-kept tables they replace did not — and those
  tables listed `rusqlite`, Serilog and an About page that WardSweep does not
  have. `.github/scripts/notices.py` regenerates them offline; `rust-ci.yml`
  and `dotnet-ci.yml` fail when either is stale or when `about.toml` and
  `deny.toml` stop agreeing on the accepted licences; and `release.yml` packs
  them, with `LICENSE`, into every release.
- `wardsweep observe …`, the passthrough `docs/11-CLI-REFERENCE.md` always
  described: it runs `wardsweep-observe.exe` from beside the CLI — never from
  `PATH` or the working directory — with every argument unchanged, and passes
  its exit code back. It needs no catalog. Releases now carry the harness as
  `WardSweep-observe-<version>.zip`, a download of its own with its own hash,
  attestation and VirusTotal entry, rather than inside the installer: a binary
  that reads the whole registry and filesystem is what heuristic engines flag,
  and the uninstaller's users never run it.

### Changed
- `docs/08-IPC-PROTOCOL.md` amended from the S3 findings, in five places. Events
  now carry a monotonic `seq` and `Hello` carries `resume_from`: the document
  required a reconnecting UI to resume the event stream but gave it no way to
  say where it had got to, which made the requirement unimplementable rather
  than merely unimplemented. The transport is now `FILE_FLAG_OVERLAPPED`,
  because a synchronous handle was measured serialising a write behind a pending
  read and `docs/09` promises an immediate `ScanCancel` during a scan. The pipe
  is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, which is what closes the
  squatting window during the unelevated-to-elevated handover. "A second connect
  attempt is refused, not queued" was wrong about the transport — with one
  instance the second client waits in `WaitNamedPipe` and there is no way to
  refuse a waiter, so the refusal is at the application layer. And the client
  check no longer claims to verify the session GUID against the client's command
  line, which would need `NtQueryInformationProcess` for no benefit; the GUID
  echoed in `Hello` is compared instead.
- `shared = false` catalog entries now require an `[anticheat.shared_evidence]`
  table naming at least two observed titles and at least one observation.
  `audit-shared --require-evidence` had been a CI gate with no schema behind it,
  and the repository's own example entry would have failed it.
- The deny-list depth floor is 2 components under a drive root plus an explicit
  list of protected top-level directories. `docs/05-DETECTION-ENGINE.md` had
  written it as 4, which denies `%ProgramData%\<vendor>` and almost every other
  path a catalog contains. Rationale recorded in `docs/05`.
- `release.yml` now publishes the UI into the directory Velopack packs from, and
  stages `wardsweep.exe` and `wardsweep-broker.exe` into it. Neither Rust binary
  was previously packaged, despite `docs/14-DISTRIBUTION-TRUST.md` listing both
  as release artifacts requiring their own SHA-256 and VirusTotal entries.
- Clippy now runs on the Windows CI job as well as the ubuntu one. With
  `cfg(windows)` off, the ubuntu job never lints any Win32 code path.
- `docs/08-IPC-PROTOCOL.md` no longer requires the broker to verify the UI's
  Authenticode signature unconditionally: releases are unsigned by design, so
  the check as written could never pass.
- `tools/observe` snapshot and diff **format 2**. A snapshot records the
  registry keys left standing with no value beneath them, which no diff could
  see before — the registry twin of the empty-directory blind spot — and a
  value too large to keep by name, type and size; the 64-bit walk no longer
  records every 32-bit key a second time under `WOW6432Node`; service types are
  named for what their flags mean; and the `Packages` exclusion no longer
  matches a game's own `Packages` directory. A modified registry key carries
  only the values that changed into a diff. `diff` refuses two snapshots of
  different formats, since every one of those changes would read as a change on
  the machine, and `refilter` brings an older diff to the current format.

### Fixed
- `README.md` and `COPYING.md` pointed at a `COPYING` file that does not exist;
  the licence is in `LICENSE`.
- `docs/04-CATALOG-SCHEMA.md` said `WOW64Node`, which is not a real registry
  key, where it meant `WOW6432Node`.
- `docs/06-REMOVAL-PIPELINE.md` said "six stages" while defining seven (0–6).
- The Authenticode cache key differed between `docs/05` and `docs/10`.
- **Personal data in committed observation diffs.** Two Riot Vanguard diffs
  carried the contributor's Microsoft-account identity and the machine's name,
  and all three committed diffs carried activity history. The harness no longer
  records account identity, activity history or the G3 material it was reading
  (a MAC-bearing DHCPv6 identifier, TPM state, Bluetooth device addresses,
  volume GUIDs); the differ applies the same policy to older snapshots; a new
  `observe refilter` applies it to an existing diff; `redact` now catches e-mail
  addresses and the local machine's names, matches names in any case, and
  shows what it could not remove instead of calling it "`Anonymous` and the
  like". The three diffs were cleaned with those tools, and nothing in them
  that names an anti-cheat changed.
- `observe diff` compared services whether or not both snapshots captured them,
  collapsed two per-user service instances into one record and dropped the
  other, and cloned every record of both snapshots to build its indexes.
- `observe suggest`, against a third anti-cheat — EA's, observed beside the
  EA app on 2026-10-09 — produced a draft that missed the anti-cheat's service
  and its driver, called it `usermode`, and took the EA app and two unrelated
  sets of Windows keys instead. Identifiers now come from product folders
  only, a file beside a signed one is attributed, a driver registered only in
  the registry is found, named and counted, an entry's key covers the WOW64
  views of everything folded into it, event log sources are proposed or named,
  and `--only` narrows a draft to one product when a publisher signs two. The
  committed Vanguard and AntiCheatExpert drafts are unchanged.
- `observe suggest` drafted every added service and driver, attributed or not,
  matched tokens as substrings, wrote `%LOCALAPPDATA%Low\…` for LocalLow paths
  and kept profile names in others, and listed a 32-bit key twice under two
  names. Each is fixed; the committed Vanguard draft is pinned by a test to its
  committed diff.
- `observe snapshot` aborted on `ERROR_MORE_DATA` from the service control
  manager, zeroed 36 KB per registry value read, ended a key's listing silently
  on any enumeration error, and reported directories as empty that it had
  chosen not to look inside.
- `wardsweep` used a catalog after checking its signature only, and looked for
  the signature at the wrong path for any file not named `*.toml`;
  `wardsweep-catalog sign` signed catalogs that failed the deny-list; `keygen`
  could replace a key between its check and its write; the shared-flag audit
  counted one title listed twice as two observations.
- `core/tests/no_destructive_code.rs` exempted any `src/**/tests/` path and
  missed the ordinary Win32 ways to delete a file or key, several G2 calls, and
  several G3 reads.

### Notes
- Still no removal code. Nothing in this repository can delete anything: the
  `exec/` and `quar/` modules are empty, and `core/tests/no_destructive_code.rs`
  asserts no destructive Win32 or filesystem call exists outside them, and that
  nothing reads a hardware identifier (Safety Gate G3).

### Safety Gate decisions
Recorded here because `docs/02-SAFETY-GATE.md` is frozen and requires a
maintainer decision with rationale before it changes.

- **Volume serial numbers stay banned under G3, and `docs/10-PERF-BUDGET.md`
  changed instead.** The Authenticode cache was specified with
  `(volume_serial, file_id, size, mtime)` as its key, which puts a reviewer
  working the G3 checklist in the position of answering "yes, it reads an
  identifier" and then arguing about it.

  The argument for allowing it was available and honest: a volume serial number
  is assigned at format time, changes on reformat, identifies a filesystem
  rather than a device, and is not any of the things G3 enumerates. It would
  never have left the process.

  It was not taken. G3's worth is that it has no exceptions, and the first
  exception is the one that establishes exceptions are possible. The cost of
  refusing turned out to be zero: partitioning the cache per scan volume — which
  the scanner already knows, because it is walking it — makes a file index
  unique on its own, so the same "verify once per file" property holds with no
  identifier read at all.

  `docs/02` gains a grey-area ruling, `docs/05` and `docs/10` describe the
  partitioned cache, and `core/tests/no_destructive_code.rs` fails the build if
  `VolumeSerialNumber` appears in shipped source. The five prohibitions
  themselves are unchanged.

- **The deny-list's canonicalisation and its carve-outs were narrowed
  (maintainer sign-off, 2026-10-08).** Four spellings that Win32 resolves to
  protected locations — checked with `GetFullPathNameW` on Windows 11 —
  canonicalised to paths the deny-list allowed: `C:\ProgramData\Microsoft .`
  and `Microsoft. .` (trailing dots and spaces were stripped in one order
  only), `C:\ProgramData\MICROS~1 .` (which also hid the 8.3 alias), and
  `C:\ProgramData\...`, which opens `C:\ProgramData` itself. A fifth,
  `C:\ProgramData\Microsoft::$INDEX_ALLOCATION`, is the directory reached
  through its index stream. Trailing dots and spaces are now stripped in any
  mix, a component of only dots and spaces is refused, `:` after the drive
  letter is refused, and only an exact `..` pops a level.

  Separately, `check_denylist` built one set of carve-outs for the whole
  catalog and applied it to game entries as well, so a game could name another
  entry's driver file or service key and pass — and removing that game would
  then remove an anti-cheat other games still reference, which is G1.
  Carve-outs are now earned per anti-cheat entry for its own footprint, and a
  game earns none. `check_denylist` also fails a path it cannot expand or
  canonicalise instead of skipping it as "already reported by `validate`",
  since each CI check runs on its own, and `validate` refuses catalog paths
  written with a relative component or a trailing dot or space.

  Every change narrows the gate; none widens it. The broader container
  hardening raised in the same review (profile and `AppData` roots, library
  roots, `HKLM\SYSTEM` beyond `Services`) was not taken and is recorded in
  `docs/PROGRESS.md` for a separate decision.

- **Containers, Windows-owned data and Windows components are refused
  (maintainer sign-off, 2026-10-08, in reply to the proposal above).** The
  deny-list protected top-level directories and a handful of named locations,
  and let the next level down through: a whole profile (`C:\Users\<name>`), the
  root every bare `%LOCALAPPDATA%`, `%APPDATA%` or `%USERPROFILE%` expands to,
  `AppData\Roaming\Microsoft` with the user's DPAPI keys, `UsrClass.dat`, a
  Steam installation or library, `HKLM\SOFTWARE\Microsoft`, the whole of
  `HKLM\SOFTWARE\WOW6432Node`, every key under `HKLM\SYSTEM` that is not a
  service, and the `HARDWARE`, `COMPONENTS` and `DRIVERS` hives. A catalog
  could also unlock `ntfs.sys` or `Tcpip` by declaring them.

  Containers are now refused when targeted as a whole and never below, so
  everything the observations so far have produced — both committed drafts,
  the example catalog — still passes. Subtrees Windows owns are refused at any
  depth, user hives anywhere, `HKLM\SYSTEM` except catalog-named service keys,
  `HKCC` entirely, and inbox driver and service names can no longer be
  unlocked; a catalog that declares one fails `check-denylist`. `HKU\<SID>`
  is judged like `HKCU`. Per-user Start menu shortcuts become unremovable, as
  the all-users ones under `%ProgramData%\Microsoft` always were.

### Continuous integration
- **The CI workflows now exist.** Rust CI, .NET CI and CodeQL were caller stubs
  delegating to `poli0981/.github/.github/workflows/*@main`. That repository is
  real, but none of the six workflows they named are in it, so all three failed
  at startup on every push and pull request — including on an empty one. Only
  Catalog Verify, the single inline workflow, had ever run.

  They are now defined here, inline. `docs/14-DISTRIBUTION-TRUST.md` treats
  public CI as part of the trust story for an unsigned binary, and a pipeline
  that cannot be read from this repository is not public in any useful sense.

- Every action pin was several majors behind and some would not have resolved:
  `actions/checkout` v4 → v7, `setup-dotnet` v4 → v6, `upload-artifact` v4 → v7,
  `download-artifact` v4 → v8, `attest-build-provenance` v1 → v4,
  `action-gh-release` v2 → v3, and CodeQL v3 → v4.

- The Rust toolchain is installed with `rustup show` so `rust-toolchain.toml`
  stays the single source of truth for the version, and the .NET SDK with
  `global-json-file` for the same reason.

- The performance budget is a real gate: `.github/scripts/check_bench_budget.py`
  reads criterion's estimates and fails the build on the hard-fail figures in
  `docs/10-PERF-BUDGET.md`. The 15 % regression threshold the old stub asked for
  is not enforced and `docs/10` now says so — criterion's baseline does not
  survive between runs, and that threshold on a shared runner would flake more
  than it would catch.

- `dotnet list package --vulnerable` exits 0 even when it finds something, so
  the job parses its output instead of trusting the exit code.

- **CodeQL now analyses Rust and the workflows, not only C#**, Rust on Windows
  because every Win32 call and `unsafe` block is behind `cfg(windows)`. A
  weekly `audit.yml` runs `cargo deny check advisories` and the NuGet
  vulnerability gate, which previously ran only when matching files changed.
  Dependabot version updates are configured.
- **Least privilege.** `catalog-verify.yml` dropped an unused
  `pull-requests: write`; `release.yml` grants write access to the one job that
  writes and attestation rights to the one that attests, takes its dispatch
  input through the environment and validates it; every checkout drops its
  credentials; third-party actions are pinned to commit SHAs.
- `vpk` and XamlStyler are pinned in `.config/dotnet-tools.json` instead of
  installed as whatever was newest. `deny.toml` bans the HTTP and TLS crates
  its own comment called a review event.

### Handover
- `docs/PROGRESS.md` records what is true now, what is deliberately absent,
  and the next four pieces of work in order. `CHANGELOG.md` is history;
  that file is state. Updated after the 2026-10-08 audit.

### Known gaps
- `Strings.ja.resx` does not exist. `CLAUDE.md` lists EN/VI/JA, but
  `docs/19-ROADMAP.md` defers Japanese to v1.x, and a resource file full of
  English would look finished while shipping a locale that is not Japanese.

[Unreleased]: https://github.com/poli0981/WardSweep/commits/main

---

## Release checklist template

Copy into each release PR:

- [ ] All P0 spikes for this milestone marked PASS or explicitly deferred
- [ ] `cargo test` + `dotnet test` green on `windows-latest`
- [ ] Clippy pedantic clean, `TreatWarningsAsErrors` clean
- [ ] `cargo audit` / `cargo deny` clean, `dotnet list package --vulnerable` clean
- [ ] Catalog signature verifies against the pinned public key
- [ ] Dry-run corpus produces byte-identical plans against the golden fixtures
- [ ] Rollback test restores a full removal on a snapshot VM
- [ ] SHA-256 of every artifact recorded in the release notes
- [ ] **VirusTotal permalink obtained and pasted into the release notes**
- [ ] Any new detections triaged per `docs/14-DISTRIBUTION-TRUST.md`
