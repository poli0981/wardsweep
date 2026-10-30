//! Detection engine: filesystem walker, registry walker, service enumeration,
//! Authenticode verification.
//!
//! Arrives with v0.1 (`docs/19-ROADMAP.md`), specified in
//! `docs/05-DETECTION-ENGINE.md`; `docs/13-P0-SPIKES.md` opened it on
//! 2026-10-30. What exists so far is [`libraries`]: the game libraries the
//! launchers name, which the observation harness walks today and the
//! filesystem walk will seed from. The three properties that will matter most:
//! every `HKLM\SOFTWARE` key is opened in **both** WOW64 views and the results
//! are two distinct artifacts; reparse points are enumerated but never
//! traversed; and anything unreadable is recorded as `access_denied`, never as
//! absent, because reporting "clean" from a blind scan is the most damaging bug
//! an audit tool can have.

pub mod libraries;
