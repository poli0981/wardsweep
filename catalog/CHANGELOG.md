# Catalog changelog

The catalog is versioned independently of the application, because anti-cheat
footprints change faster than release cycles. Licence: CC BY-SA 4.0.

`catalog_version` is the version referred to here. It is not the app version and
never tracks it.

## 0.0.1

First signed catalog. **It contains no entries.**

That is deliberate rather than unfinished. `CONTRIBUTING.md` rejects entries
derived from memory, from a forum post, or from another tool's source, and
[`docs/16-OBSERVATION-HARNESS.md`](../docs/16-OBSERVATION-HARNESS.md) requires
every shipping entry to come from an observed clean → install → uninstall diff
on a real machine. No such observation exists yet.

An empty catalog finds nothing, which is honest and harmless. A guessed catalog
deletes the wrong thing on someone's machine.

- Schema version 1.
- Signed with the key whose public half is committed at `catalog/pubkey.hex`.
- `catalog.example.toml` is the annotated template; it is validated by CI but
  is not signed and is never loaded at runtime.

## Adding an entry

1. Run the observation harness through a full cycle
   ([`docs/16`](../docs/16-OBSERVATION-HARNESS.md)).
2. Verify every publisher with `signtool verify /v /pa`.
3. Leave `shared = true` unless you can fill in `[anticheat.shared_evidence]`
   with at least two observed titles and at least one observation id.
4. Attach the diff JSON to the pull request.
5. Bump `catalog_version` here and re-sign.
