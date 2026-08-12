//! Quarantine store, manifests and rollback.
//!
//! Not implemented. Arrives with v0.5 (`docs/19-ROADMAP.md`), specified in
//! `docs/07-ROLLBACK-QUARANTINE.md`.
//!
//! `CLAUDE.md` makes this module the only place `std::fs::remove_*` may appear
//! at all, and even here removal means a same-volume move with a manifest
//! written *before* the operation. Rollback fidelity is spike S5; if it fails,
//! `docs/19` reduces scope to files-only and the registry becomes read-only
//! reporting.
