# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

The catalog (`catalog/catalog.toml`) is versioned separately — see its own
`catalog/CHANGELOG.md` once entries begin landing.

## [Unreleased]

### Added
- Initial documentation suite (20 documents).
- Safety gate defined and frozen before any implementation work.
- Seven P0 spikes identified as go/no-go gates.

### Notes
- No executable code yet. Nothing in this repository can remove anything.

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
