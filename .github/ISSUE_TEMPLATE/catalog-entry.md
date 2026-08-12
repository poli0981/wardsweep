---
name: Catalog entry
about: Submit a new or corrected anti-cheat / game entry
labels: catalog
---

## Entry

<!-- Paste the draft TOML from `wardsweep observe suggest` -->

```toml

```

## Evidence

- [ ] Derived from an observation-harness diff (attach `footprint.json` and, if
      available, `residue.json`)
- [ ] `signtool verify /v /pa` output attached for each signed binary
- [ ] `shared` value justified — if `shared = false`, state the evidence across
      titles. Defaulting to `false` without evidence is not accepted.
- [ ] Save paths separated into the game's `saves` list
- [ ] `official_uninstall` command tested manually; result described below

## Environment

- Windows build (`winver`, exact):
- Game version:
- Launcher and version:
- Anti-cheat version (if determinable):

## Notes

<!-- Anything the tooling could not capture -->
