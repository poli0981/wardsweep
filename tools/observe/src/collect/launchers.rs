//! Where the launchers keep their library manifests.
//!
//! Both answers live in `wardsweep_core::scan`, which the scanner shares with
//! this harness: Steam records its own directory in the registry, read on
//! Windows by `scan::win::steam_install`, and the Epic Games Launcher keeps its
//! manifests under `%ProgramData%`. The manifests themselves are read by
//! `scan::libraries`.

use std::path::PathBuf;

pub use wardsweep_core::scan::libraries::epic_manifests;

/// Steam's own directory, the one holding `steamapps\libraryfolders.vdf`.
#[cfg(windows)]
#[must_use]
pub fn steam_install() -> Option<PathBuf> {
    wardsweep_core::scan::win::steam_install()
}

/// Never finds Steam off Windows.
#[cfg(not(windows))]
#[must_use]
pub fn steam_install() -> Option<PathBuf> {
    None
}
