# Contributing to WardSweep

## Before anything else

Read [`docs/02-SAFETY-GATE.md`](docs/02-SAFETY-GATE.md). Pull requests that
cross the gate are closed without review — this is not negotiable and is not a
judgement about the contributor.

## What is most useful right now

The project is pre-alpha. In rough order of value:

1. **Catalog entries produced by the observation harness.** See
   [`docs/16-OBSERVATION-HARNESS.md`](docs/16-OBSERVATION-HARNESS.md). A diff
   from a real clean-install → install → uninstall cycle is worth more than any
   amount of code right now.
2. **P0 spike results**, positive or negative. A documented failure closes a
   question permanently.
3. **Residue reports** from audit mode on real machines (with paths redacted).

## Catalog contributions

Every entry must include:

- The observation-harness diff it was derived from (attach the JSON)
- Windows build and game/launcher versions observed
- Authenticode publisher common name, verified with `signtool verify /v /pa`
- Whether the anti-cheat is shared across titles (`shared = true` forces refcount)
- The official uninstall command, if one exists

Entries derived from memory, from a forum post, or from another tool's source
are rejected. Wrong catalog data deletes the wrong thing on someone's machine.

## Code

- Rust: `cargo fmt`, `cargo clippy -- -D warnings` (pedantic), `cargo test`
- C#: `dotnet format`, XamlStyler, `TreatWarningsAsErrors=true`
- Conventional Commits (`feat:`, `fix:`, `docs:`, `spike:`, `catalog:`)
- Any PR touching `core/src/safety/`, `core/src/quar/`, or `catalog/` requires
  maintainer review and a test that demonstrates the invariant still holds

## Testing your change

Never test destructive changes on a machine you care about. Read
[`docs/15-TEST-MACHINE-PROTOCOL.md`](docs/15-TEST-MACHINE-PROTOCOL.md) first.
The short version: full disk image, or a disposable OS install, or don't.

## What will be refused

Feature requests for anti-cheat bypass, keeping a game playable without its
anti-cheat, hardware ID modification, ban evasion, or "clean trace" tooling.
These are refused as project policy. There is no version of the request that
gets accepted, so please don't reframe and resubmit.
