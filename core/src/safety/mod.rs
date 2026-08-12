//! The safety gate: the code paths that decide what WardSweep is not allowed
//! to touch.
//!
//! `CLAUDE.md` marks this directory as requiring the highest scrutiny and
//! explicit maintainer sign-off. Two properties are load-bearing:
//!
//! - [`denylist`] is compiled in and cannot be widened by a catalog, a config
//!   file, a flag, or an environment variable.
//! - [`paths`] makes canonicalisation a precondition of the type system rather
//!   than a convention, because `docs/05-DETECTION-ENGINE.md` calls checking a
//!   pre-canonical string "a bug class, not a shortcut".
//!
//! `refcount` — the G1 invariant from `docs/02-SAFETY-GATE.md` — is not here
//! yet. It needs the ownership graph, which arrives with the detection engine.

pub mod denylist;
pub mod paths;
