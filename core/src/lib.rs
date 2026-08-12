//! WardSweep broker core.
//!
//! Everything destructive WardSweep can do lives behind this crate, and at the
//! time of writing none of it exists yet: `docs/19-ROADMAP.md` v0.1 is
//! audit-only and states plainly that "no removal code exists in the binary".
//! The modules below are laid out to match `docs/03-ARCHITECTURE.md` so that
//! future work lands where the documentation says it should.
//!
//! # Reading order
//!
//! - [`safety`] first. It is the gate everything else passes through, and
//!   `CLAUDE.md` requires maintainer sign-off to change it.
//! - [`catalog`] second. It decides what the scanner is even looking for, and
//!   an unverified catalog is refused rather than used with a warning.
//!
//! # Portability
//!
//! The lint job runs `clippy --all-targets --all-features` on ubuntu, and
//! `wardsweep-catalog` is built and executed on ubuntu by `catalog-verify.yml`.
//! Everything reachable from those two paths is pure logic. Win32 code sits
//! behind `#[cfg(windows)]` and its dependencies behind
//! `[target.'cfg(windows)'.dependencies]` — never behind a cargo feature,
//! which `--all-features` would switch on regardless of platform.

pub mod catalog;
pub mod exec;
pub mod ipc;
pub mod plan;
pub mod quar;
pub mod report;
pub mod safety;
pub mod scan;

/// The version of this build, as reported by `--version` and logged at start-up.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
