//! Authenticode signer lookup.
//!
//! `docs/16-OBSERVATION-HARNESS.md`: "**Signer clustering is the single most
//! useful signal.** Everything the anti-cheat installer dropped shares a
//! publisher, and it separates instantly from Windows Update noise."
//!
//! This reads the **embedded** signature only, and returns the signing
//! certificate's subject common name. It does not verify the signature chain:
//! the harness describes what is on disk, it does not decide whether to trust
//! it. That distinction matters — `docs/04-CATALOG-SCHEMA.md` treats
//! `authenticode_cn` as an identity signal and says a file at a matching path
//! with the *wrong* publisher is reported as suspicious rather than removed, so
//! the name here is evidence for a person to review, never a verdict.
//!
//! The reading itself is `wardsweep_core::scan::win::signer_name`, which the
//! scanner calls once a signature has verified: one implementation for both.
//!
//! # What "no signer" means
//!
//! Absent is not "unsigned". Most Windows binaries carry no embedded signature
//! at all and are signed through a catalog (`.cat`) file instead, which this
//! does not follow. Anti-cheat binaries are embedded-signed in practice, which
//! is what makes the signal worth collecting despite the gap.

#[cfg(not(windows))]
/// Never finds a signer off Windows.
#[must_use]
pub fn signer_of(_path: &std::path::Path) -> Option<String> {
    None
}

#[cfg(windows)]
pub use wardsweep_core::scan::win::signer_name as signer_of;
