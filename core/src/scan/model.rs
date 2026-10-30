//! What an audit scan reports.
//!
//! The report is the contract `docs/11-CLI-REFERENCE.md` gives `wardsweep
//! scan --json`: versioned, and changed only on a major release. It says what
//! was found, what was refused because the deny-list protects it, and what
//! could not be read — and a scan with anything in the last list is partial,
//! never clean.

use serde::Serialize;

/// The report's wire version, `"v"` in every JSON record.
pub const REPORT_VERSION: u32 = 1;

/// How sure a finding is that the artifact is the anti-cheat's
/// (`docs/05-DETECTION-ENGINE.md`, "Matching strategy").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// A high-weight signal and the publisher the catalog names.
    Confirmed,
    /// A high-weight signal with no publisher to check: the file is gone, the
    /// artifact is not a file, or verification failed for a reason other than
    /// the signature itself.
    Probable,
    /// The name or path matches and the signature names someone else, is
    /// invalid, or is absent. Never chosen for removal; reported prominently.
    Suspicious,
}

/// Which WOW64 view a registry artifact was found in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum RegView {
    /// The 64-bit view.
    #[serde(rename = "64")]
    Bits64,
    /// The 32-bit view, `WOW6432Node`.
    #[serde(rename = "32")]
    Bits32,
}

/// One thing found on the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "artifact", rename_all = "snake_case")]
pub enum Artifact {
    /// A service, by name.
    Service {
        /// The service name.
        name: String,
        /// Its image as configured, when known.
        image: Option<String>,
        /// Present in `Services` but unknown to the service control manager
        /// (`docs/05`, "Not SCM alone").
        registry_only: bool,
    },
    /// A kernel driver, by file name.
    Driver {
        /// The file name the catalog names.
        file: String,
        /// The `Services` key registering it, when there is one.
        service: Option<String>,
        /// The image path, expanded.
        image: String,
        /// Whether the image is on disk. A missing image under a present key is
        /// not a removal: EA's minifilter has none while no game runs.
        image_present: bool,
    },
    /// A registry key, in one view. The same key in both views is two artifacts.
    RegistryKey {
        /// The key, as the catalog names it.
        key: String,
        /// The view it was found in.
        view: RegView,
    },
    /// A file or directory.
    Path {
        /// The path, expanded.
        path: String,
        /// Whether it is a directory.
        directory: bool,
    },
}

/// A finding: an artifact of one catalog entry, how sure the scan is, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// The catalog entry's id.
    pub anticheat: String,
    /// What was found.
    #[serde(flatten)]
    pub artifact: Artifact,
    /// How sure the scan is that it is the anti-cheat's.
    pub classification: Classification,
    /// The signals behind the classification, in words.
    pub evidence: Vec<String>,
}

/// Something a catalog entry names that the deny-list protects. Reported, never
/// offered: catalog validation should have refused it, and a protected path
/// that reaches a scan says the catalog and the deny-list disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Protected {
    /// The catalog entry's id.
    pub anticheat: String,
    /// The path or key.
    pub target: String,
    /// The deny-list's reason.
    pub reason: String,
}

/// Something the scan could not read. Unreadable is never absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Unreadable {
    /// The catalog entry's id, when the item belongs to one.
    pub anticheat: Option<String>,
    /// The service, key or path.
    pub item: String,
    /// Why, in the platform's terms.
    pub reason: String,
}

/// A stale record the scan saw and did not believe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Disbelieved {
    /// The catalog entry's id.
    pub anticheat: String,
    /// The service name.
    pub item: String,
    /// What the source claimed and why it was not taken.
    pub reason: String,
}

/// Everything one audit found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// [`REPORT_VERSION`].
    pub v: u32,
    /// Artifacts found, in catalog order.
    pub findings: Vec<Finding>,
    /// Targets the deny-list protects.
    pub protected: Vec<Protected>,
    /// Records the scan saw and did not believe: an SCM entry for a service
    /// whose key is gone.
    pub disbelieved: Vec<Disbelieved>,
    /// What could not be read.
    pub unreadable: Vec<Unreadable>,
}

impl Report {
    /// Whether anything could not be read. A partial scan is never reported as
    /// clean (`docs/05`, "Access-denied handling").
    #[must_use]
    pub fn partial(&self) -> bool {
        !self.unreadable.is_empty()
    }
}
