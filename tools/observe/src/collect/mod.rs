//! Capturing the machine.
//!
//! Everything here produces [`crate::model`] data, so the differ and the draft
//! generator never see a handle. [`filesystem`] is portable and tested on
//! Linux; [`services`] and [`authenticode`] are Win32 and are not.
//!
//! # Read-only, structurally
//!
//! `docs/16-OBSERVATION-HARNESS.md`: "Snapshots are **read-only**. The harness
//! has no removal code path at all — it is a separate binary from the broker
//! for exactly this reason." `core/tests/no_destructive_code.rs` covers this
//! directory, and each collector's module comment says what enforces the claim
//! for its own domain.

pub mod authenticode;
pub mod filesystem;
pub mod registry;
pub mod services;

use std::path::PathBuf;

use crate::model::{Coverage, Domain, Snapshot};

/// Which domains a snapshot should try to capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    /// Services and drivers, via the service control manager.
    pub services: bool,
    /// Files under the roots in `docs/16`.
    pub filesystem: bool,
    /// Registry keys under the roots in `docs/16`, in both WOW64 views.
    pub registry: bool,
}

impl Default for Request {
    fn default() -> Self {
        Self {
            services: true,
            filesystem: true,
            registry: true,
        }
    }
}

/// The filesystem roots `docs/16-OBSERVATION-HARNESS.md` names, expanded.
///
/// Roots that do not exist on this machine are dropped rather than walked, so a
/// 32-bit-only or unusually configured system does not fill the snapshot with
/// unreadable-directory records for paths that were never going to be there.
#[must_use]
pub fn default_roots() -> Vec<PathBuf> {
    [
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramData",
        "LOCALAPPDATA",
        "APPDATA",
    ]
    .iter()
    .filter_map(|variable| std::env::var_os(variable).map(PathBuf::from))
    .chain(
        std::env::var_os("SystemRoot")
            .map(|root| PathBuf::from(root).join("System32").join("drivers")),
    )
    .filter(|path| path.is_dir())
    .collect()
}

/// Take a snapshot.
///
/// # Errors
/// If a requested domain refuses outright — the service control manager
/// declining to open, for instance. Individual items that cannot be read are
/// recorded in [`Coverage::access_denied`] instead: a machine where three
/// services are unreadable is still worth capturing, provided the file says
/// which three.
pub fn snapshot(label: &str, taken_utc: String, request: Request) -> anyhow::Result<Snapshot> {
    let mut domain_started_utc = std::collections::BTreeMap::new();
    let mut captured = Vec::new();
    let mut access_denied = Vec::new();
    let mut services = Vec::new();
    let mut files = Vec::new();
    let mut filesystem_policy = None;
    let mut registry_keys = Vec::new();
    let mut registry_policy = None;

    if request.services {
        domain_started_utc.insert(Domain::Services.to_string(), crate::clock::now_utc());
        let result = services::services()?;
        services = result.services;
        access_denied.extend(result.access_denied);
        captured.push(Domain::Services);
    }

    if request.filesystem {
        domain_started_utc.insert(Domain::Filesystem.to_string(), crate::clock::now_utc());
        let result = filesystem::walk(&default_roots(), authenticode::signer_of);
        files = result.files;
        access_denied.extend(result.access_denied);
        filesystem_policy = Some(result.policy);
        captured.push(Domain::Filesystem);
    }

    if request.registry {
        domain_started_utc.insert(Domain::Registry.to_string(), crate::clock::now_utc());
        let result = registry::registry()?;
        registry_keys = result.keys;
        access_denied.extend(result.access_denied);
        registry_policy = Some(result.policy);
        captured.push(Domain::Registry);
    }

    // Domains this build cannot capture at all, and domains the caller turned
    // off, are named the same way: as not captured. A diff cannot then present
    // their absence as "nothing changed there" — see `crate::model`.
    let not_captured = Domain::all()
        .into_iter()
        .filter(|domain| !captured.contains(domain))
        .collect();

    Ok(Snapshot {
        format_version: crate::model::SNAPSHOT_FORMAT_VERSION,
        taken_utc,
        domain_started_utc,
        harness_version: env!("CARGO_PKG_VERSION").to_owned(),
        label: label.to_owned(),
        coverage: Coverage {
            captured,
            not_captured,
            access_denied,
        },
        services,
        files,
        filesystem_policy,
        registry: registry_keys,
        registry_policy,
    })
}
