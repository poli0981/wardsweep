//! Detection engine: filesystem walker, registry walker, service enumeration,
//! Authenticode verification.
//!
//! Not implemented. Arrives with v0.1 (`docs/19-ROADMAP.md`), specified in
//! `docs/05-DETECTION-ENGINE.md`. The three properties that will matter most:
//! every `HKLM\SOFTWARE` key is opened in **both** WOW64 views and the results
//! are two distinct artifacts; reparse points are enumerated but never
//! traversed; and anything unreadable is recorded as `access_denied`, never as
//! absent, because reporting "clean" from a blind scan is the most damaging bug
//! an audit tool can have.
