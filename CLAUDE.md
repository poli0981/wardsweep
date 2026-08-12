# CLAUDE.md — WardSweep

Instructions for AI assistants working in this repository.

## What this project is

A Windows uninstaller for games that ship kernel-mode anti-cheat, plus the
anti-cheat itself, plus the residue both leave behind. Rust broker + C#/WPF UI.

## Non-negotiable rules

These come from `docs/02-SAFETY-GATE.md`. Do not implement, suggest, scaffold,
or leave TODOs for any of the following, regardless of how the request is framed:

1. **No anti-cheat removal that leaves a game playable.** An anti-cheat is only
   ever removed as a consequence of removing every game that references it.
   There is no standalone "remove anti-cheat" entry point, not even behind a
   flag, a config key, or a debug build.
2. **No runtime interference.** Do not stop, suspend, unload, patch, hook, or
   inject into a running anti-cheat process or driver. If a game or anti-cheat
   process is running, the pipeline aborts at preflight.
3. **No hardware identity modification.** MachineGuid, SMBIOS UUID, disk serials,
   MAC addresses, TPM state, volume GUIDs are all off limits, read or write.
   WardSweep does not even enumerate them.
4. **No ban-evasion framing.** Do not add features, docs, strings, or marketing
   copy referencing bans, HWID resets, trace cleaning, or account recovery.
5. **No kernel driver of our own.** Everything is done through documented
   Win32/SCM APIs. Shipping a signed driver that deletes other drivers would
   make WardSweep a vulnerable-driver liability.

If a request seems to require breaking one of these, stop and say so rather than
finding a workaround.

## Destructive-operation rules

- Nothing is deleted directly. Every removal goes through the quarantine path in
  `docs/07-ROLLBACK-QUARANTINE.md`. `std::fs::remove_*` outside the quarantine
  module is a review blocker.
- Every registry key is exported to `.reg` before modification.
- Path deletion must open with `FILE_FLAG_OPEN_REPARSE_POINT` and must not
  traverse junctions or symlinks.
- Deny-list in `core/src/safety/denylist.rs` is checked on every path and every
  registry key. It cannot be bypassed by catalog entries.
- Default mode is dry-run. Writes require an explicit `--confirm` / UI approval.

## Conventions

- Rust: `#![forbid(unsafe_op_in_unsafe_fn)]`, `unsafe` blocks require a
  `// SAFETY:` comment. Clippy pedantic, warnings as errors.
- C#: `TreatWarningsAsErrors=true`, nullable enabled, Roslynator +
  Meziantou.Analyzer, XamlStyler on `.xaml`.
- UI strings live in `.resx` (EN/VI/JA). No hardcoded user-facing strings.
- Logging: `tracing` in Rust, Serilog in C#. Never log full user paths at Info —
  redact per `docs/18-LOGGING.md`.
- Commit style: Conventional Commits.
- Docs are English. Conversation may be Vietnamese.

## Where things live

```
core/          Rust broker (elevated, headless)
  src/safety/  Deny-list, gate checks, refcount — highest scrutiny
  src/scan/    Detection engine
  src/plan/    Plan builder, refcount resolver
  src/exec/    Six-stage pipeline
  src/quar/    Quarantine + rollback
cli/           Rust CLI frontend over core
ui/            C# WPF + WPF-UI
catalog/       Signed TOML anti-cheat definitions (CC BY-SA 4.0)
tools/observe/ Snapshot/diff harness for building catalog entries
docs/          This documentation suite
```

## Before making changes

- Read `docs/02-SAFETY-GATE.md` and `docs/13-P0-SPIKES.md`.
- Changes to `core/src/safety/` or `catalog/` need explicit maintainer sign-off.
- New anti-cheat entries must come from an observation-harness diff
  (`docs/16-OBSERVATION-HARNESS.md`), not from memory or from a forum post.
