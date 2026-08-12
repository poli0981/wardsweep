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

### Changed
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

### Fixed
- `README.md` and `COPYING.md` pointed at a `COPYING` file that does not exist;
  the licence is in `LICENSE`.
- `docs/04-CATALOG-SCHEMA.md` said `WOW64Node`, which is not a real registry
  key, where it meant `WOW6432Node`.
- `docs/06-REMOVAL-PIPELINE.md` said "six stages" while defining seven (0–6).
- The Authenticode cache key differed between `docs/05` and `docs/10`.

### Notes
- Still no removal code. Nothing in this repository can delete anything: the
  `exec/` and `quar/` modules are empty, and `core/tests/no_destructive_code.rs`
  asserts no destructive Win32 or filesystem call exists outside them, and that
  nothing reads a hardware identifier (Safety Gate G3).

### Known gaps
- `THIRD-PARTY-NOTICES.md` staleness is not checked by CI, although both that
  file and `COPYING.md` previously claimed it was. Both now say so plainly.
  Wiring the check needs `cargo-about` configuration and a
  `dotnet-project-licenses` run, and is worth doing before the first release.
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
