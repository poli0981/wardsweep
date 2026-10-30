//! The machine, as the audit reads it.
//!
//! The engine never calls Win32 itself: it asks a [`MachineView`], which the
//! broker implements over SCM, the registry and the filesystem, and the tests
//! implement over a map. So the decisions `docs/05-DETECTION-ENGINE.md` cares
//! most about — both WOW64 views, registry-only drivers, stale SCM entries,
//! unreadable never absent — are tested on Linux, where they cannot be
//! confused with what a particular machine happened to hold.
//!
//! Every method is a read. There is no method that could change anything, so
//! no implementation can be asked to.

use super::model::RegView;

/// The answer to one lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup<T> {
    /// It is there.
    Found(T),
    /// It is not there.
    Absent,
    /// It could not be read: access denied, or an error that says nothing about
    /// presence. Never to be read as absent.
    Unreadable(String),
}

/// What the service control manager says about a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    /// The configured image path, as SCM reports it.
    pub image: String,
    /// SCM opened the service and every query failed with "the system cannot
    /// find the file specified": its key is gone and SCM has not noticed. EA's
    /// uninstaller leaves its minifilter like this until the next boot.
    pub stale: bool,
}

/// A service's key under `HKLM\SYSTEM\CurrentControlSet\Services`, read
/// directly, as a driver written past SCM is only visible there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceKey {
    /// The key's name, which is the service's.
    pub name: String,
    /// `ImagePath`, as written. Empty when the key has none.
    pub image: String,
    /// `Type`: 1, 2 and 8 are drivers.
    pub service_type: u32,
}

impl ServiceKey {
    /// Whether `Type` marks a kernel, file-system or recognizer driver.
    #[must_use]
    pub fn is_driver(&self) -> bool {
        matches!(self.service_type, 1 | 2 | 8)
    }
}

/// What is at a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// A file.
    File,
    /// A directory.
    Directory,
    /// A junction or symbolic link. Enumerated, never traversed.
    ReparsePoint,
}

/// A file's Authenticode signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// A signature that verifies, and its signer's common name.
    Verified(String),
    /// No signature at all.
    Unsigned,
    /// A signature that does not verify.
    Invalid,
    /// Verification failed for another reason: I/O, a timeout, a chain that
    /// could not be built. Unknown, not unsigned (`docs/05`).
    Unknown(String),
}

/// Read-only access to the machine being audited.
pub trait MachineView {
    /// The service control manager's view of a service.
    fn service(&self, name: &str) -> Lookup<ServiceStatus>;
    /// A service's key in the registry, whether or not SCM knows it.
    fn service_key(&self, name: &str) -> Lookup<ServiceKey>;
    /// Every service key whose `Type` is a driver's.
    fn driver_keys(&self) -> Lookup<Vec<ServiceKey>>;
    /// Whether a key exists in one WOW64 view.
    fn registry_key(&self, key: &str, view: RegView) -> Lookup<()>;
    /// What is at a path, without following a reparse point.
    fn path(&self, path: &str) -> Lookup<PathKind>;
    /// A file's signature.
    fn signature(&self, path: &str) -> Signature;
}
