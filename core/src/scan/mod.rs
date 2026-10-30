//! Detection engine: filesystem walker, registry walker, service enumeration,
//! Authenticode verification.
//!
//! Arrives with v0.1 (`docs/19-ROADMAP.md`), specified in
//! `docs/05-DETECTION-ENGINE.md`; `docs/13-P0-SPIKES.md` opened it on
//! 2026-10-30. What exists so far: [`libraries`], the game libraries the
//! launchers name; [`engine`], the audit itself, which matches a catalog
//! against a [`view::MachineView`] and reports in [`model`]'s terms; and, on
//! Windows, `win`, the machine view over SCM, the registry, the filesystem and
//! `WinVerifyTrust`. The three properties that matter most:
//! every `HKLM\SOFTWARE` key is opened in **both** WOW64 views and the results
//! are two distinct artifacts; reparse points are enumerated but never
//! traversed; and anything unreadable is recorded as `access_denied`, never as
//! absent, because reporting "clean" from a blind scan is the most damaging bug
//! an audit tool can have.

pub mod engine;
pub mod libraries;
pub mod model;
pub mod view;
#[cfg(windows)]
pub mod win;
