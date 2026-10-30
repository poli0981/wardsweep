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
pub mod boot;
pub mod filesystem;
pub mod launchers;
pub mod registry;
pub mod services;

use std::path::PathBuf;

use wardsweep_core::scan::libraries::{self, Library};

use crate::model::{AccessDenied, Coverage, Domain, Snapshot};

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

/// The roots to walk: [`default_roots`], then the games folder of every
/// library that none of them already holds.
///
/// A library inside a default root — Steam's own, under
/// `%ProgramFiles(x86)%` — is already walked, and walking it twice would
/// record every file in it twice. The libraries come after the default roots,
/// ordered by path, so two snapshots of the same machine list their roots in
/// the same order.
#[must_use]
pub fn walk_roots(defaults: Vec<PathBuf>, libraries: &[Library]) -> Vec<PathBuf> {
    let mut roots = defaults;
    let mut extra: Vec<PathBuf> = libraries
        .iter()
        .map(|library| PathBuf::from(library.games()))
        .filter(|games| !roots.iter().any(|root| is_within(games, root)))
        .collect();
    extra.sort_by_key(|path| path.to_string_lossy().to_ascii_lowercase());
    extra.dedup_by(|later, earlier| {
        later
            .to_string_lossy()
            .eq_ignore_ascii_case(&earlier.to_string_lossy())
    });
    roots.extend(extra);
    roots
}

/// Whether `path` is `root` or below it, compared as Windows compares paths:
/// without regard to case, and only at a separator.
fn is_within(path: &std::path::Path, root: &std::path::Path) -> bool {
    let path = path.to_string_lossy().to_ascii_lowercase();
    let root = root.to_string_lossy().to_ascii_lowercase();
    let root = root.trim_end_matches('\\');
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('\\'))
}

/// The libraries the launchers name, split into those whose games folder is
/// there to walk and the coverage gaps: manifests that could not be read and
/// libraries on a volume or in a folder that is not there.
fn libraries_to_walk() -> (Vec<Library>, Vec<AccessDenied>) {
    let found = libraries::discover(
        launchers::steam_install().as_deref(),
        launchers::epic_manifests().as_deref(),
    );
    let mut gaps: Vec<AccessDenied> = found
        .unreadable
        .into_iter()
        .map(|manifest| AccessDenied {
            domain: Domain::Filesystem,
            item: manifest.path,
            reason: format!("library manifest unreadable: {}", manifest.reason),
        })
        .collect();
    let mut present = Vec::new();
    for library in found.libraries {
        if std::path::Path::new(&library.games()).is_dir() {
            present.push(library);
        } else {
            gaps.push(AccessDenied {
                domain: Domain::Filesystem,
                item: library.games(),
                reason: "named by a launcher's library manifest and not present".to_owned(),
            });
        }
    }
    (present, gaps)
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
    // Before any domain: the answer to "did the machine restart between these
    // two snapshots?" is worth nothing if it is itself minutes stale.
    let boot_session = boot::boot_session(crate::clock::now_unix_millis());
    let mut domain_started_utc = std::collections::BTreeMap::new();
    let mut captured = Vec::new();
    let mut access_denied = Vec::new();
    let mut services = Vec::new();
    let mut files = Vec::new();
    let mut filesystem_policy = None;
    let mut file_empty_directories = None;
    let mut registry_keys = Vec::new();
    let mut registry_policy = None;
    let mut registry_empty_keys = None;

    if request.services {
        domain_started_utc.insert(Domain::Services.to_string(), crate::clock::now_utc());
        let result = services::services()?;
        services = result.services;
        access_denied.extend(result.access_denied);
        captured.push(Domain::Services);
    }

    if request.filesystem {
        domain_started_utc.insert(Domain::Filesystem.to_string(), crate::clock::now_utc());
        let (libraries, gaps) = libraries_to_walk();
        let roots = walk_roots(default_roots(), &libraries);
        let mut result = filesystem::walk(&roots, authenticode::signer_of);
        result.policy.libraries = libraries;
        files = result.files;
        access_denied.extend(gaps);
        access_denied.extend(result.access_denied);
        filesystem_policy = Some(result.policy);
        file_empty_directories = Some(result.file_empty_directories);
        captured.push(Domain::Filesystem);
    }

    if request.registry {
        domain_started_utc.insert(Domain::Registry.to_string(), crate::clock::now_utc());
        let result = registry::registry()?;
        registry_keys = result.keys;
        access_denied.extend(result.access_denied);
        registry_policy = Some(result.policy);
        registry_empty_keys = Some(result.empty_keys);
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
        boot_session,
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
        file_empty_directories,
        registry: registry_keys,
        registry_policy,
        registry_empty_keys,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use wardsweep_core::scan::libraries::{Launcher, Library};

    use super::walk_roots;

    fn library(launcher: Launcher, path: &str) -> Library {
        Library {
            launcher,
            path: path.to_owned(),
        }
    }

    #[test]
    fn libraries_follow_the_default_roots_once_each_in_order() {
        let defaults = vec![
            PathBuf::from(r"C:\Program Files"),
            PathBuf::from(r"C:\Program Files (x86)"),
        ];
        let libraries = [
            library(Launcher::Steam, r"D:\SteamLibrary"),
            // Steam's own library is under a default root, so already walked.
            library(Launcher::Steam, r"C:\Program Files (x86)\Steam"),
            library(Launcher::Epic, r"E:\Epic Games"),
            library(Launcher::Epic, r"e:\epic games"),
            library(Launcher::Steam, r"C:\SteamLibrary"),
        ];

        let roots = walk_roots(defaults, &libraries);

        assert_eq!(
            roots,
            [
                PathBuf::from(r"C:\Program Files"),
                PathBuf::from(r"C:\Program Files (x86)"),
                PathBuf::from(r"C:\SteamLibrary\steamapps\common"),
                PathBuf::from(r"D:\SteamLibrary\steamapps\common"),
                PathBuf::from(r"E:\Epic Games"),
            ]
        );
    }

    #[test]
    fn a_root_holds_only_what_is_below_it_at_a_separator() {
        // `C:\Program FilesX` is not inside `C:\Program Files`.
        let roots = walk_roots(
            vec![PathBuf::from(r"C:\Program Files")],
            &[library(Launcher::Epic, r"C:\Program FilesX\Epic Games")],
        );
        assert_eq!(roots.len(), 2, "{roots:?}");
    }
}
