//! The compiled-in deny-list.
//!
//! `docs/05-DETECTION-ENGINE.md` specifies a fixed set of paths and registry
//! keys that WardSweep may never modify. Three properties matter more than the
//! list itself:
//!
//! 1. **It is compiled in.** No catalog, config file, flag or environment
//!    variable can add to it. [`Exceptions`] is the only thing a catalog
//!    contributes, and it can only unlock the two narrow carve-outs the
//!    deny-list already defines — it cannot introduce new ones. An anti-cheat
//!    entry unlocks its own driver files and service names for its own paths
//!    and keys; a game entry unlocks nothing (see
//!    `crate::catalog::validate::check_denylist`).
//! 2. **It runs on canonicalised input.** [`check_path`] accepts only
//!    [`CanonicalPath`], so a caller cannot pass `C:\PROGRA~1` or
//!    `\\?\C:\Windows` and slip past a string comparison.
//! 3. **It is checked at scan time *and* at execution time**, with
//!    [`Stage`] making explicit which evidence the caller actually has.
//!
//! Every rejection is logged at `info` — `docs/18-LOGGING.md` calls gate
//! rejections "the most important lines in the file", because they are the
//! proof the safety machinery ran.

use std::collections::BTreeSet;

use super::paths::{CanonicalPath, CanonicalRegKey, Hive, PathKind};

/// Minimum number of components below a drive root before a path may be touched.
///
/// `docs/05-DETECTION-ENGINE.md` writes this rule as "any path shorter than 4
/// components under a drive root". Taken literally that denies
/// `C:\ProgramData\ExampleAC` (2 components) and
/// `%ProgramFiles(x86)%\EasyAntiCheat` (2 components) — which is to say, almost
/// every path in the catalog and everything
/// `docs/02-SAFETY-GATE.md` explicitly permits removing. The rule's evident
/// purpose is to stop a whole top-level directory being targeted, so it is
/// implemented as a floor of 2 plus the explicit
/// [`PROTECTED_TOP_LEVEL`] list, and `docs/05` has been corrected to match.
const MIN_COMPONENTS_UNDER_DRIVE_ROOT: usize = 2;

/// Top-level directories that are never anti-cheat residue and are refused as
/// whole subtrees, on every drive.
const PROTECTED_TOP_LEVEL: &[&str] = &[
    "WINDOWS",
    "WINNT",
    "$RECYCLE.BIN",
    "SYSTEM VOLUME INFORMATION",
    "RECOVERY",
    "BOOT",
    "EFI",
    "PERFLOGS",
    "$WINDOWS.~BT",
    "$WINDOWS.~WS",
];

/// Top-level directories that exist to hold other software, and so may never be
/// removed themselves even though their children often can be.
const CONTAINER_TOP_LEVEL: &[&str] = &[
    "USERS",
    "PROGRAMDATA",
    "PROGRAM FILES",
    "PROGRAM FILES (X86)",
    "DOCUMENTS AND SETTINGS",
];

/// Deeper directories that hold other software, refused when targeted *as a
/// whole* and never below. `*` matches any one component.
///
/// The top-level list above stops `C:\Users` being removed, and stopped nothing
/// one level down: `C:\Users\<name>` — a whole profile — passed the depth floor
/// of two, and so did every root a bare `%LOCALAPPDATA%`, `%APPDATA%` or
/// `%USERPROFILE%` expands to. A catalog entry naming one of these is a mistake
/// in every case; a catalog entry naming something *inside* one is ordinary
/// footprint and stays allowed.
const CONTAINERS: &[&[&str]] = &[
    // A profile, its application-data roots, and the folders Windows makes in
    // every profile.
    &["USERS", "*"],
    &["USERS", "*", "APPDATA"],
    &["USERS", "*", "APPDATA", "LOCAL"],
    &["USERS", "*", "APPDATA", "LOCALLOW"],
    &["USERS", "*", "APPDATA", "ROAMING"],
    &["USERS", "*", "APPDATA", "LOCAL", "PROGRAMS"],
    &["USERS", "*", "APPDATA", "LOCAL", "PACKAGES"],
    &["USERS", "*", "APPDATA", "LOCAL", "TEMP"],
    &["USERS", "*", "CONTACTS"],
    &["USERS", "*", "DESKTOP"],
    &["USERS", "*", "DOCUMENTS"],
    &["USERS", "*", "DOCUMENTS", "MY GAMES"],
    &["USERS", "*", "DOWNLOADS"],
    &["USERS", "*", "FAVORITES"],
    &["USERS", "*", "LINKS"],
    &["USERS", "*", "MUSIC"],
    &["USERS", "*", "ONEDRIVE"],
    &["USERS", "*", "PICTURES"],
    &["USERS", "*", "SAVED GAMES"],
    &["USERS", "*", "SEARCHES"],
    &["USERS", "*", "VIDEOS"],
    // Shared component and installer stores.
    &["PROGRAM FILES", "COMMON FILES"],
    &["PROGRAM FILES (X86)", "COMMON FILES"],
    &["PROGRAMDATA", "PACKAGE CACHE"],
    // Launcher installations, which hold every game they installed.
    &["PROGRAM FILES", "STEAM"],
    &["PROGRAM FILES (X86)", "STEAM"],
];

/// Final components that name a game library wherever it lives: removing one
/// removes every game in it. `D:\Games\SteamLibrary` passes the depth floor;
/// `steamapps\common` is three levels down in any library.
const LIBRARY_LEAVES: &[&str] = &["STEAMLIBRARY", "STEAMAPPS", "EPIC GAMES"];

/// Directories directly inside a Steam library's `steamapps`.
const STEAMAPPS_CONTAINERS: &[&str] = &[
    "COMMON",
    "COMPATDATA",
    "DOWNLOADING",
    "SHADERCACHE",
    "SOURCEMODS",
    "TEMP",
    "WORKSHOP",
];

/// Subtrees Windows owns, refused at any depth, the way `%ProgramData%\Microsoft`
/// already is.
///
/// `AppData\Roaming\Microsoft` holds the user's DPAPI master keys and credential
/// store; `AppData\Local\Microsoft\Windows\UsrClass.dat` is a loaded registry
/// hive. Per-user Start menu shortcuts live under it too, which makes them as
/// unremovable as the all-users ones under `%ProgramData%\Microsoft` have always
/// been.
const WINDOWS_DATA: &[&[&str]] = &[
    &["USERS", "*", "APPDATA", "LOCAL", "MICROSOFT"],
    &["USERS", "*", "APPDATA", "LOCALLOW", "MICROSOFT"],
    &["USERS", "*", "APPDATA", "ROAMING", "MICROSOFT"],
    &["PROGRAM FILES", "WINDOWSAPPS"],
    &["PROGRAM FILES", "WINDOWS DEFENDER"],
    &[
        "PROGRAM FILES",
        "WINDOWS DEFENDER ADVANCED THREAT PROTECTION",
    ],
    &["PROGRAM FILES (X86)", "WINDOWS DEFENDER"],
];

/// File names of user registry hives, matched as a prefix of the final
/// component so their logs and backups are covered too.
const USER_HIVE_FILES: &[&str] = &["NTUSER.DAT", "USRCLASS.DAT"];

/// Driver files that ship with Windows. No catalog may unlock one.
///
/// The carve-out for `System32\drivers` lets an anti-cheat entry name its own
/// driver file, and nothing stopped it naming `ntfs.sys`. A wrong entry here is
/// an unbootable machine, so these names are refused whatever a catalog says.
const INBOX_DRIVERS: &[&str] = &[
    "ACPI.SYS",
    "ACPIEX.SYS",
    "AFD.SYS",
    "AMDPPM.SYS",
    "BEEP.SYS",
    "BINDFLT.SYS",
    "BOWSER.SYS",
    "CDFS.SYS",
    "CDROM.SYS",
    "CLASSPNP.SYS",
    "CLFS.SYS",
    "CLIPSP.SYS",
    "CNG.SYS",
    "DISK.SYS",
    "DXGKRNL.SYS",
    "DXGMMS2.SYS",
    "EXFAT.SYS",
    "FASTFAT.SYS",
    "FILECRYPT.SYS",
    "FILEINFO.SYS",
    "FLTMGR.SYS",
    "FVEVOL.SYS",
    "HIDCLASS.SYS",
    "HIDPARSE.SYS",
    "HTTP.SYS",
    "I8042PRT.SYS",
    "INTELPPM.SYS",
    "KBDCLASS.SYS",
    "KBDHID.SYS",
    "KSECDD.SYS",
    "KSECPKG.SYS",
    "MOUCLASS.SYS",
    "MOUHID.SYS",
    "MOUNTMGR.SYS",
    "MRXSMB.SYS",
    "MSRPC.SYS",
    "MUP.SYS",
    "NDIS.SYS",
    "NETBT.SYS",
    "NETIO.SYS",
    "NPFS.SYS",
    "NSIPROXY.SYS",
    "NTFS.SYS",
    "NULL.SYS",
    "PARTMGR.SYS",
    "PCI.SYS",
    "PDC.SYS",
    "RDBSS.SYS",
    "REFS.SYS",
    "SPACEPORT.SYS",
    "SRV2.SYS",
    "SRVNET.SYS",
    "STORAHCI.SYS",
    "STORNVME.SYS",
    "STORPORT.SYS",
    "TCPIP.SYS",
    "TDX.SYS",
    "TM.SYS",
    "TPM.SYS",
    "UCX01000.SYS",
    "UDFS.SYS",
    "USBHUB3.SYS",
    "USBSTOR.SYS",
    "USBXHCI.SYS",
    "VHDMP.SYS",
    "VOLMGR.SYS",
    "VOLMGRX.SYS",
    "VOLSNAP.SYS",
    "VOLUME.SYS",
    "WCIFS.SYS",
    "WDBOOT.SYS",
    "WDF01000.SYS",
    "WDFILTER.SYS",
    "WDFLDR.SYS",
    "WDNISDRV.SYS",
    "WFPLWFS.SYS",
    "WOF.SYS",
];

/// Services and drivers that ship with Windows. No catalog may unlock one.
const INBOX_SERVICES: &[&str] = &[
    "ACPI",
    "AFD",
    "APPXSVC",
    "BEEP",
    "BFE",
    "BROKERINFRASTRUCTURE",
    "CLIPSVC",
    "CNG",
    "COREMESSAGINGREGISTRAR",
    "CRYPTSVC",
    "DCOMLAUNCH",
    "DHCP",
    "DISK",
    "DNSCACHE",
    "EVENTLOG",
    "FASTFAT",
    "FILEINFO",
    "FLTMGR",
    "FVEVOL",
    "GPSVC",
    "KEYISO",
    "KSECDD",
    "KSECPKG",
    "LANMANSERVER",
    "LANMANWORKSTATION",
    "LSM",
    "MOUNTMGR",
    "MPSDRV",
    "MPSSVC",
    "MSRPC",
    "NDIS",
    "NETBT",
    "NPFS",
    "NSI",
    "NTFS",
    "NULL",
    "PARTMGR",
    "PCI",
    "PLUGPLAY",
    "POWER",
    "PROFSVC",
    "REFS",
    "RPCEPTMAPPER",
    "RPCSS",
    "SAMSS",
    "SCHEDULE",
    "SECURITYHEALTHSERVICE",
    "SENSE",
    "SPACEPORT",
    "STATEREPOSITORY",
    "STORAHCI",
    "STORNVME",
    "SYSTEMEVENTSBROKER",
    "TCPIP",
    "TCPIP6",
    "TDX",
    "TOKENBROKER",
    "TPM",
    "TRUSTEDINSTALLER",
    "USERMANAGER",
    "VAULTSVC",
    "VOLMGR",
    "VOLMGRX",
    "VOLSNAP",
    "VOLUME",
    "W32TIME",
    "WDBOOT",
    "WDF01000",
    "WDFILTER",
    "WDNISDRV",
    "WDNISSVC",
    "WINDEFEND",
    "WINMGMT",
    "WLIDSVC",
    "WOF",
    "WUAUSERV",
];

/// Whether a driver file name belongs to Windows itself.
#[must_use]
pub fn is_inbox_driver(file_name: &str) -> bool {
    INBOX_DRIVERS
        .iter()
        .any(|inbox| inbox.eq_ignore_ascii_case(file_name.trim()))
}

/// Whether a service name belongs to Windows itself.
#[must_use]
pub fn is_inbox_service(service_name: &str) -> bool {
    INBOX_SERVICES
        .iter()
        .any(|inbox| inbox.eq_ignore_ascii_case(service_name.trim()))
}

/// Registry keys below `HKLM` that hold other software's keys, refused when
/// targeted as a whole. Each is also refused under `SOFTWARE\WOW6432Node`.
///
/// `HKLM\SOFTWARE\Microsoft` had two components and passed the depth floor;
/// so did `HKLM\SOFTWARE\WOW6432Node`, the entire 32-bit view. The uninstall
/// entry *inside* `…\CurrentVersion\Uninstall` is footprint `docs/02` lets a
/// catalog name; the `Uninstall` key itself is every program's.
const MACHINE_CONTAINER_KEYS: &[&[&str]] = &[
    &["SOFTWARE", "CLASSES"],
    &["SOFTWARE", "CLASSES", "APPID"],
    &["SOFTWARE", "CLASSES", "CLSID"],
    &["SOFTWARE", "CLASSES", "INTERFACE"],
    &["SOFTWARE", "CLASSES", "TYPELIB"],
    &["SOFTWARE", "CLIENTS"],
    &["SOFTWARE", "MICROSOFT"],
    &["SOFTWARE", "MICROSOFT", "WINDOWS"],
    &["SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION"],
    &[
        "SOFTWARE",
        "MICROSOFT",
        "WINDOWS",
        "CURRENTVERSION",
        "APP PATHS",
    ],
    &[
        "SOFTWARE",
        "MICROSOFT",
        "WINDOWS",
        "CURRENTVERSION",
        "EXPLORER",
    ],
    &["SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "RUN"],
    &[
        "SOFTWARE",
        "MICROSOFT",
        "WINDOWS",
        "CURRENTVERSION",
        "RUNONCE",
    ],
    &[
        "SOFTWARE",
        "MICROSOFT",
        "WINDOWS",
        "CURRENTVERSION",
        "SHAREDDLLS",
    ],
    &[
        "SOFTWARE",
        "MICROSOFT",
        "WINDOWS",
        "CURRENTVERSION",
        "UNINSTALL",
    ],
    &["SOFTWARE", "MICROSOFT", "WINDOWS NT"],
    &["SOFTWARE", "MICROSOFT", "WINDOWS NT", "CURRENTVERSION"],
    &[
        "SOFTWARE",
        "MICROSOFT",
        "WINDOWS NT",
        "CURRENTVERSION",
        "IMAGE FILE EXECUTION OPTIONS",
    ],
    &["SOFTWARE", "POLICIES"],
    &["SOFTWARE", "POLICIES", "MICROSOFT"],
    &["SOFTWARE", "REGISTEREDAPPLICATIONS"],
    &["SOFTWARE", "WOW6432NODE"],
];

/// Registry subtrees below `HKLM` that Windows owns, refused at any depth. Each
/// is also refused under `SOFTWARE\WOW6432Node`.
const MACHINE_PROTECTED_KEYS: &[&[&str]] = &[
    // Safety Gate G3: machine identity lives here.
    &["SOFTWARE", "MICROSOFT", "CRYPTOGRAPHY"],
    // Logon itself.
    &[
        "SOFTWARE",
        "MICROSOFT",
        "WINDOWS NT",
        "CURRENTVERSION",
        "WINLOGON",
    ],
    &["SOFTWARE", "MICROSOFT", "WINDOWS DEFENDER"],
    &["SOFTWARE", "POLICIES", "MICROSOFT", "WINDOWS DEFENDER"],
];

/// Registry keys below a user's root (`HKCU`, or `HKU\<SID>`) that hold other
/// software's keys, refused when targeted as a whole.
const USER_CONTAINER_KEYS: &[&[&str]] = &[
    &["SOFTWARE", "CLASSES"],
    &["SOFTWARE", "CLASSES", "CLSID"],
    &["SOFTWARE", "MICROSOFT"],
    &["SOFTWARE", "MICROSOFT", "WINDOWS"],
    &["SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION"],
    &["SOFTWARE", "MICROSOFT", "WINDOWS", "CURRENTVERSION", "RUN"],
    &[
        "SOFTWARE",
        "MICROSOFT",
        "WINDOWS",
        "CURRENTVERSION",
        "RUNONCE",
    ],
    &[
        "SOFTWARE",
        "MICROSOFT",
        "WINDOWS",
        "CURRENTVERSION",
        "UNINSTALL",
    ],
    &["SOFTWARE", "POLICIES"],
    &["SOFTWARE", "WOW6432NODE"],
];

/// Hives below `HKLM` that are never footprint, refused at any depth.
const PROTECTED_MACHINE_HIVES: &[&str] = &["SAM", "SECURITY", "HARDWARE", "COMPONENTS", "DRIVERS"];

/// Why the deny-list refused an artifact.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DenyReason {
    /// Inside the Windows directory, and not the one permitted driver file.
    #[error("path is inside the Windows directory")]
    ProtectedSystemPath,
    /// A whole top-level directory such as `C:\Windows` or `C:\Users`.
    #[error("path is a protected top-level directory")]
    ProtectedTopLevelDirectory,
    /// A user's registry hive file.
    #[error("path is a user registry hive")]
    ProtectedUserHive,
    /// Inside `%ProgramData%\Microsoft`.
    #[error("path is inside ProgramData\\Microsoft")]
    ProtectedProgramData,
    /// A directory that holds other software — a profile, an application-data
    /// root, a game library — targeted as a whole.
    #[error("path is a folder that holds other software, and is never removed as a whole")]
    ProtectedContainer,
    /// Inside a subtree Windows owns, such as `AppData\Roaming\Microsoft`.
    #[error("path is inside data Windows owns")]
    ProtectedWindowsData,
    /// The root of a volume.
    #[error("path is a volume root")]
    VolumeRoot,
    /// Fewer components than [`MIN_COMPONENTS_UNDER_DRIVE_ROOT`].
    #[error("path is too shallow to be removed safely")]
    TooShallow,
    /// A UNC or device-namespace path. WardSweep is strictly local and
    /// drive-rooted; these forms exist mainly as a way around a path check.
    #[error("path uses a UNC or device namespace")]
    NonLocalNamespace,
    /// An 8.3 alias that has not been expanded through the filesystem.
    #[error("path contains an unresolved 8.3 alias")]
    EightDotThreeUnresolved,
    /// Some component of the path is a junction or symbolic link.
    #[error("path traverses a reparse point")]
    ReparsePointInPath,
    /// Execution was attempted on a path that never went through an open handle.
    #[error("path was not resolved through an open handle")]
    UnresolvedAtExecution,
    /// `HKLM\SAM`, `HKLM\SECURITY`, `HKLM\BCD*`, `HKLM\HARDWARE`,
    /// `HKLM\COMPONENTS` or `HKLM\DRIVERS`.
    #[error("registry key is inside a protected hive")]
    ProtectedRegistryHive,
    /// Under `HKLM\SYSTEM` or `HKCC` but not a service key.
    #[error("registry key is system configuration outside the services key")]
    ProtectedSystemKey,
    /// A key that holds other software's keys, such as
    /// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, targeted as
    /// a whole; or a subtree Windows owns.
    #[error("registry key holds other software's keys, or belongs to Windows")]
    ProtectedRegistryKey,
    /// A service key under `CurrentControlSet\Services` that the catalog does
    /// not name.
    #[error("registry key is a service not named by the catalog")]
    UnknownServiceKey,
    /// A hive root or single-level key such as `HKLM\SOFTWARE`.
    #[error("registry key is too shallow to be removed safely")]
    RegistryKeyTooShallow,
}

/// Where in the pipeline the check is running, and therefore what evidence the
/// caller can actually supply.
///
/// This is an argument rather than two separate functions so that an execution
/// -time caller cannot quietly get the weaker check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Catalog load and validation. Nothing exists on disk yet, so reparse
    /// points cannot be observed and paths are syntactic only.
    CatalogLoad,
    /// Scan or execution, where the path came from an open handle.
    OnDisk {
        /// Set when any component of the path was found to be a junction or
        /// symbolic link. `docs/05` requires reparse points to be enumerated
        /// but never traversed.
        traverses_reparse_point: bool,
    },
}

/// The two carve-outs a verified catalog is allowed to unlock.
///
/// There is deliberately no way to add a path or a registry prefix. A catalog
/// can name a driver filename and a service name; it cannot name a location.
/// This is what makes "the deny-list cannot be widened by a catalog entry"
/// a structural property rather than a review checklist item.
#[derive(Debug, Clone, Default)]
pub struct Exceptions {
    driver_files: BTreeSet<String>,
    service_names: BTreeSet<String>,
}

impl Exceptions {
    /// No carve-outs at all. Used during catalog validation, before any entry
    /// has been trusted.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Build the carve-outs from the driver filenames and service names one
    /// verified anti-cheat entry declared, for that entry's own footprint.
    ///
    /// Only the base filename of a driver is retained; a catalog cannot smuggle
    /// a directory in through this field. A name that belongs to Windows itself
    /// is dropped: no catalog unlocks `ntfs.sys` or `Tcpip`.
    pub fn new<D, S>(driver_files: D, service_names: S) -> Self
    where
        D: IntoIterator,
        D::Item: AsRef<str>,
        S: IntoIterator,
        S::Item: AsRef<str>,
    {
        Self {
            driver_files: driver_files
                .into_iter()
                .filter_map(|name| base_file_name(name.as_ref()))
                .filter(|name| !is_inbox_driver(name))
                .collect(),
            service_names: service_names
                .into_iter()
                .map(|name| name.as_ref().trim().to_ascii_uppercase())
                .filter(|name| !name.is_empty() && !is_inbox_service(name))
                .collect(),
        }
    }

    /// Whether the catalog named this driver filename.
    #[must_use]
    pub fn allows_driver_file(&self, file_name: &str) -> bool {
        self.driver_files.contains(&file_name.to_ascii_uppercase())
    }

    /// Whether the catalog named this service.
    #[must_use]
    pub fn allows_service(&self, service_name: &str) -> bool {
        self.service_names
            .contains(&service_name.to_ascii_uppercase())
    }
}

/// Strip any directory part a catalog may have attached to a driver name.
fn base_file_name(raw: &str) -> Option<String> {
    let name = raw
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(raw)
        .trim()
        .to_ascii_uppercase();
    (!name.is_empty()).then_some(name)
}

/// Check a path against the deny-list.
///
/// # Errors
///
/// Returns the first [`DenyReason`] that applies. A path that is denied for
/// several reasons reports the most specific one, because that is what the user
/// needs to see.
pub fn check_path(
    path: &CanonicalPath,
    exceptions: &Exceptions,
    stage: Stage,
) -> Result<(), DenyReason> {
    let outcome = evaluate_path(path, exceptions, stage);
    if let Err(reason) = &outcome {
        tracing::info!(
            gate = "denylist",
            target_kind = "path",
            reason = %reason,
            "artifact rejected by deny-list"
        );
    }
    outcome
}

fn evaluate_path(
    path: &CanonicalPath,
    exceptions: &Exceptions,
    stage: Stage,
) -> Result<(), DenyReason> {
    if let Stage::OnDisk {
        traverses_reparse_point,
    } = stage
    {
        if traverses_reparse_point {
            return Err(DenyReason::ReparsePointInPath);
        }
        if !path.is_handle_resolved() {
            return Err(DenyReason::UnresolvedAtExecution);
        }
    }

    if path.contains_short_name() {
        return Err(DenyReason::EightDotThreeUnresolved);
    }

    if path.kind() != PathKind::DriveRooted {
        return Err(DenyReason::NonLocalNamespace);
    }

    let components = path.components();
    if components.is_empty() {
        return Err(DenyReason::VolumeRoot);
    }

    let top = components[0].as_str();

    if PROTECTED_TOP_LEVEL
        .iter()
        .any(|p| p.eq_ignore_ascii_case(top))
    {
        return windows_directory_exception(path, exceptions);
    }

    if components.len() == 1
        && CONTAINER_TOP_LEVEL
            .iter()
            .any(|p| p.eq_ignore_ascii_case(top))
    {
        return Err(DenyReason::ProtectedTopLevelDirectory);
    }

    // A user hive by name, wherever it is. Checking only below `C:\Users` let
    // `C:\Documents and Settings\<name>\NTUSER.DAT` through, and a profile on
    // another drive; `UsrClass.dat` was not checked at all.
    if components
        .last()
        .is_some_and(|leaf| USER_HIVE_FILES.iter().any(|hive| leaf.starts_with(hive)))
    {
        return Err(DenyReason::ProtectedUserHive);
    }

    // C:\ProgramData\Microsoft\**
    if path.starts_with(&["ProgramData", "Microsoft"]) {
        return Err(DenyReason::ProtectedProgramData);
    }

    if WINDOWS_DATA
        .iter()
        .any(|pattern| starts_with_pattern(components, pattern))
    {
        return Err(DenyReason::ProtectedWindowsData);
    }

    if is_container(components) {
        return Err(DenyReason::ProtectedContainer);
    }

    if components.len() < MIN_COMPONENTS_UNDER_DRIVE_ROOT {
        return Err(DenyReason::TooShallow);
    }

    Ok(())
}

/// Whether `components` match `pattern` exactly, `*` matching any component.
fn equals_pattern(components: &[String], pattern: &[&str]) -> bool {
    components.len() == pattern.len() && starts_with_pattern(components, pattern)
}

/// Whether `components` begin with `pattern`, `*` matching any component.
fn starts_with_pattern(components: &[String], pattern: &[&str]) -> bool {
    pattern.len() <= components.len()
        && pattern
            .iter()
            .zip(components)
            .all(|(want, have)| *want == "*" || have.eq_ignore_ascii_case(want))
}

/// Whether a path names a directory that holds other software.
fn is_container(components: &[String]) -> bool {
    if CONTAINERS
        .iter()
        .any(|pattern| equals_pattern(components, pattern))
    {
        return true;
    }
    match components {
        [.., leaf]
            if LIBRARY_LEAVES
                .iter()
                .any(|name| leaf.eq_ignore_ascii_case(name)) =>
        {
            true
        }
        [.., steamapps, child] => {
            steamapps.eq_ignore_ascii_case("STEAMAPPS")
                && STEAMAPPS_CONTAINERS
                    .iter()
                    .any(|name| child.eq_ignore_ascii_case(name))
        }
        _ => false,
    }
}

/// The single carve-out inside the Windows directory.
///
/// `docs/05` allows "explicit driver filenames in `System32\drivers`". The
/// exception is scoped to a *file*, never to a directory: `System32\drivers`
/// itself stays denied, and so does any driver the catalog did not name.
fn windows_directory_exception(
    path: &CanonicalPath,
    exceptions: &Exceptions,
) -> Result<(), DenyReason> {
    let components = path.components();
    let is_driver_file = components.len() == 4
        && components[0].eq_ignore_ascii_case("WINDOWS")
        && components[1].eq_ignore_ascii_case("SYSTEM32")
        && components[2].eq_ignore_ascii_case("DRIVERS")
        && exceptions.allows_driver_file(&components[3]);

    if is_driver_file {
        Ok(())
    } else if components.len() == 1 {
        Err(DenyReason::ProtectedTopLevelDirectory)
    } else {
        Err(DenyReason::ProtectedSystemPath)
    }
}

/// Check a registry key against the deny-list.
///
/// # Errors
///
/// Returns the first [`DenyReason`] that applies.
pub fn check_registry_key(
    key: &CanonicalRegKey,
    exceptions: &Exceptions,
) -> Result<(), DenyReason> {
    let outcome = evaluate_registry_key(key, exceptions);
    if let Err(reason) = &outcome {
        tracing::info!(
            gate = "denylist",
            target_kind = "registry",
            reason = %reason,
            "artifact rejected by deny-list"
        );
    }
    outcome
}

fn evaluate_registry_key(key: &CanonicalRegKey, exceptions: &Exceptions) -> Result<(), DenyReason> {
    let components = key.components();

    match key.hive() {
        Hive::Hklm => evaluate_machine_key(components, exceptions),
        Hive::Hkcu => evaluate_user_key(components),
        Hive::Hku => match components {
            // A user's root, or the whole of `HKEY_USERS`.
            [] | [_] => Err(DenyReason::RegistryKeyTooShallow),
            // `HKU\<SID>_Classes` is that user's `SOFTWARE\Classes`.
            [user, rest @ ..] if user.ends_with("_CLASSES") => {
                let mut relative = vec!["SOFTWARE".to_owned(), "CLASSES".to_owned()];
                relative.extend(rest.iter().cloned());
                evaluate_user_key(&relative)
            }
            [_, rest @ ..] => evaluate_user_key(rest),
        },
        // `HKCC` is a view of `HKLM\SYSTEM`, and none of it is footprint.
        Hive::Hkcc => Err(DenyReason::ProtectedSystemKey),
        Hive::Hkcr => shallow_floor(components),
    }
}

/// `HKLM`, whose `SYSTEM` hive is refused except for catalog-named services.
fn evaluate_machine_key(components: &[String], exceptions: &Exceptions) -> Result<(), DenyReason> {
    if let Some(first) = components.first()
        && (first.starts_with("BCD")
            || PROTECTED_MACHINE_HIVES
                .iter()
                .any(|hive| first.eq_ignore_ascii_case(hive)))
    {
        return Err(DenyReason::ProtectedRegistryHive);
    }

    if let Some(service) = service_key_leaf(components) {
        // The Services container itself, and anything nested below a
        // service, are never removal targets in their own right.
        return match service {
            ServiceKey::Named(name) if exceptions.allows_service(name) => Ok(()),
            _ => Err(DenyReason::UnknownServiceKey),
        };
    }

    // Everything else under `SYSTEM` is the machine's configuration: control
    // sets, `Control`, `Enum`, `Setup`, `MountedDevices`. Every anti-cheat
    // observed so far wrote only service keys there.
    if components
        .first()
        .is_some_and(|first| first.eq_ignore_ascii_case("SYSTEM"))
    {
        return Err(DenyReason::ProtectedSystemKey);
    }

    // The 32-bit view mirrors the 64-bit one, so each rule applies in both.
    let native = match components {
        [software, wow, rest @ ..]
            if software.eq_ignore_ascii_case("SOFTWARE")
                && wow.eq_ignore_ascii_case("WOW6432NODE") =>
        {
            let mut native = vec![software.clone()];
            native.extend(rest.iter().cloned());
            Some(native)
        }
        _ => None,
    };
    for view in std::iter::once(components).chain(native.as_deref()) {
        if MACHINE_PROTECTED_KEYS
            .iter()
            .any(|pattern| starts_with_pattern(view, pattern))
        {
            return Err(DenyReason::ProtectedRegistryKey);
        }
    }
    if MACHINE_CONTAINER_KEYS
        .iter()
        .any(|pattern| equals_pattern(components, pattern))
        || native.as_deref().is_some_and(|view| {
            view.len() > 1
                && MACHINE_CONTAINER_KEYS
                    .iter()
                    .any(|pattern| equals_pattern(view, pattern))
        })
    {
        return Err(DenyReason::ProtectedRegistryKey);
    }

    shallow_floor(components)
}

/// A user's root: `HKCU`, or `HKU\<SID>` with the SID removed.
fn evaluate_user_key(components: &[String]) -> Result<(), DenyReason> {
    if USER_CONTAINER_KEYS
        .iter()
        .any(|pattern| equals_pattern(components, pattern))
    {
        return Err(DenyReason::ProtectedRegistryKey);
    }
    shallow_floor(components)
}

/// A hive root or a single-level key is never a removal target.
fn shallow_floor(components: &[String]) -> Result<(), DenyReason> {
    if components.len() < 2 {
        return Err(DenyReason::RegistryKeyTooShallow);
    }
    Ok(())
}

/// What a key under a control set's `Services` container refers to.
enum ServiceKey<'a> {
    /// A service key exactly one level below the container.
    Named(&'a str),
    /// The container itself, or something nested below an individual service.
    Other,
}

/// Recognise `SYSTEM\{CurrentControlSet,ControlSetNNN}\Services[\<name>]`.
///
/// Returns `None` when the key is not a services key at all.
fn service_key_leaf(components: &[String]) -> Option<ServiceKey<'_>> {
    let [system, control_set, services, rest @ ..] = components else {
        return None;
    };
    if !system.eq_ignore_ascii_case("SYSTEM") || !services.eq_ignore_ascii_case("SERVICES") {
        return None;
    }
    let is_control_set = control_set.eq_ignore_ascii_case("CURRENTCONTROLSET")
        || (control_set.len() > 10
            && control_set[..10].eq_ignore_ascii_case("CONTROLSET")
            && control_set[10..].bytes().all(|b| b.is_ascii_digit()));
    if !is_control_set {
        return None;
    }
    match rest {
        [name] => Some(ServiceKey::Named(name.as_str())),
        _ => Some(ServiceKey::Other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safety::paths::{
        canonicalise_reg_key, canonicalise_resolved, canonicalise_syntactic,
    };

    /// The adversarial spellings from `docs/12-TESTING-STRATEGY.md`.
    ///
    /// Every one of these names the same protected location. If any spelling
    /// survives the deny-list, the deny-list has a bypass.
    const ADVERSARIAL_SYSTEM32: &[&str] = &[
        r"C:\Windows\System32",
        r"C:\WINDOWS\system32",
        r"\\?\C:\Windows\System32",
        r"C:\Windows\..\Windows\System32",
        r"\\localhost\C$\Windows",
        r"\\.\GLOBALROOT\Device\HarddiskVolume3\Windows",
        r"C:/Windows/System32",
        r"c:\windows\system32\config",
    ];

    fn syntactic(path: &str) -> CanonicalPath {
        canonicalise_syntactic(path).expect("test path should canonicalise")
    }

    fn catalog_exceptions() -> Exceptions {
        Exceptions::new(["vgk.sys", "EasyAntiCheat.sys"], ["vgk", "EasyAntiCheat"])
    }

    #[test]
    fn denylist_blocks_system32_paths() {
        for spelling in ADVERSARIAL_SYSTEM32 {
            let path = syntactic(spelling);
            assert!(
                check_path(&path, &Exceptions::none(), Stage::CatalogLoad).is_err(),
                "deny-list let {spelling} through"
            );
        }

        // The 8.3 alias from the same table, kept separate because it is denied
        // for a different and more specific reason.
        let alias = syntactic(r"C:\PROGRA~1");
        assert_eq!(
            check_path(&alias, &Exceptions::none(), Stage::CatalogLoad),
            Err(DenyReason::EightDotThreeUnresolved)
        );
    }

    #[test]
    fn spellings_win32_resolves_to_protected_paths_are_refused() {
        // Each of these was checked with GetFullPathNameW on Windows 11, and
        // each opens a protected location. Before canonicalisation learned the
        // rules, every one of them reached `check_path` as a path it allowed.
        for spelling in [
            r"C:\ProgramData\Microsoft .",
            r"C:\ProgramData\Microsoft. .",
            r"C:\ProgramData\MICROS~1 .",
        ] {
            let path = syntactic(spelling);
            assert!(
                check_path(&path, &catalog_exceptions(), Stage::CatalogLoad).is_err(),
                "deny-list let {spelling} through"
            );
        }
        // These no longer canonicalise at all, so nothing can hand them to the
        // deny-list: `...` opens C:\ProgramData itself, and the stream form is
        // the Microsoft directory reached through its index.
        for spelling in [
            r"C:\ProgramData\...",
            r"C:\ProgramData\Microsoft::$INDEX_ALLOCATION",
        ] {
            assert!(
                canonicalise_syntactic(spelling).is_err(),
                "{spelling} must not canonicalise"
            );
        }
    }

    #[test]
    fn denylist_blocks_8dot3_alias_of_protected_path() {
        // WINDOW~1 is a plausible alias for the Windows directory. We cannot
        // know that without the filesystem, which is exactly why it is refused.
        for alias in [r"C:\WINDOW~1\System32", r"C:\PROGRA~1", r"C:\PROGRA~2\Foo"] {
            assert_eq!(
                check_path(&syntactic(alias), &catalog_exceptions(), Stage::CatalogLoad),
                Err(DenyReason::EightDotThreeUnresolved),
                "alias {alias} should be refused until it is expanded"
            );
        }
    }

    #[test]
    fn denylist_blocks_unc_and_device_path_forms() {
        for form in [
            r"\\localhost\C$\Windows\System32",
            r"\\127.0.0.1\ADMIN$\System32",
            r"\\.\GLOBALROOT\Device\HarddiskVolume3\Windows\System32",
            r"\\?\GLOBALROOT\Device\HarddiskVolume3\Program Files\EasyAntiCheat",
            r"\\.\C:\Windows",
        ] {
            let path = syntactic(form);
            let reason = check_path(&path, &catalog_exceptions(), Stage::CatalogLoad)
                .expect_err("UNC and device forms must be refused");
            assert_eq!(reason, DenyReason::NonLocalNamespace, "for {form}");
        }
    }

    #[test]
    fn denylist_cannot_be_widened_by_catalog_entry() {
        let generous = catalog_exceptions();

        // The only thing a catalog unlocks is one named driver file.
        assert!(
            check_path(
                &syntactic(r"C:\Windows\System32\drivers\vgk.sys"),
                &generous,
                Stage::CatalogLoad
            )
            .is_ok(),
            "a catalog-named driver file is the one permitted carve-out"
        );

        // Everything around it stays denied, however the catalog is written.
        for still_denied in [
            r"C:\Windows\System32\drivers",
            r"C:\Windows\System32\drivers\etc\hosts",
            r"C:\Windows\System32\drivers\notinthecatalog.sys",
            r"C:\Windows\System32",
            r"C:\Windows",
            r"C:\Windows\Temp\vgk.sys",
        ] {
            assert!(
                check_path(&syntactic(still_denied), &generous, Stage::CatalogLoad).is_err(),
                "catalog exceptions widened the deny-list to {still_denied}"
            );
        }

        // A catalog that tries to smuggle a directory in through the driver
        // field gets only the base filename out of it.
        let smuggled = Exceptions::new([r"..\..\..\Windows\System32\config\SAM"], ["vgk"]);
        assert!(
            check_path(
                &syntactic(r"C:\Windows\System32\config\SAM"),
                &smuggled,
                Stage::CatalogLoad
            )
            .is_err()
        );
    }

    #[test]
    fn denylist_blocks_volume_roots_and_shallow_paths() {
        assert_eq!(
            check_path(&syntactic(r"C:\"), &Exceptions::none(), Stage::CatalogLoad),
            Err(DenyReason::VolumeRoot)
        );
        assert_eq!(
            check_path(&syntactic(r"D:"), &Exceptions::none(), Stage::CatalogLoad),
            Err(DenyReason::VolumeRoot)
        );
        for container in [r"C:\Users", r"C:\ProgramData", r"C:\Program Files (x86)"] {
            assert_eq!(
                check_path(
                    &syntactic(container),
                    &Exceptions::none(),
                    Stage::CatalogLoad
                ),
                Err(DenyReason::ProtectedTopLevelDirectory),
                "for {container}"
            );
        }
        assert_eq!(
            check_path(
                &syntactic(r"D:\Games"),
                &Exceptions::none(),
                Stage::CatalogLoad
            ),
            Err(DenyReason::TooShallow)
        );
    }

    #[test]
    fn denylist_blocks_user_hives_and_microsoft_programdata() {
        for hive in [
            r"C:\Users\anon\NTUSER.DAT",
            r"C:\Users\anon\NTUSER.DAT.LOG1",
            r"C:\Users\Default\ntuser.dat",
        ] {
            assert_eq!(
                check_path(&syntactic(hive), &Exceptions::none(), Stage::CatalogLoad),
                Err(DenyReason::ProtectedUserHive),
                "for {hive}"
            );
        }
        assert_eq!(
            check_path(
                &syntactic(r"C:\ProgramData\Microsoft\Windows\Start Menu"),
                &Exceptions::none(),
                Stage::CatalogLoad
            ),
            Err(DenyReason::ProtectedProgramData)
        );
    }

    #[test]
    fn ordinary_anticheat_paths_are_allowed() {
        // The whole point: `docs/02-SAFETY-GATE.md` lists these as explicitly
        // permitted, so a deny-list that refuses them is broken in the other
        // direction.
        for allowed in [
            r"C:\Program Files (x86)\EasyAntiCheat",
            r"C:\ProgramData\EasyAntiCheat\logs",
            r"C:\Users\anon\AppData\Local\ExampleShooter\Cache",
            r"D:\SteamLibrary\steamapps\common\Example Shooter",
        ] {
            assert_eq!(
                check_path(
                    &syntactic(allowed),
                    &catalog_exceptions(),
                    Stage::CatalogLoad
                ),
                Ok(()),
                "deny-list wrongly refused {allowed}"
            );
        }
    }

    #[test]
    fn execution_stage_demands_handle_resolution_and_refuses_reparse_points() {
        let allowed = r"C:\Program Files (x86)\EasyAntiCheat";

        // Syntactic canonicalisation is not enough once we are writing.
        assert_eq!(
            check_path(
                &syntactic(allowed),
                &Exceptions::none(),
                Stage::OnDisk {
                    traverses_reparse_point: false
                }
            ),
            Err(DenyReason::UnresolvedAtExecution)
        );

        let resolved = canonicalise_resolved(&format!(r"\\?\{allowed}")).expect("valid path");
        assert_eq!(
            check_path(
                &resolved,
                &Exceptions::none(),
                Stage::OnDisk {
                    traverses_reparse_point: false
                }
            ),
            Ok(())
        );
        assert_eq!(
            check_path(
                &resolved,
                &Exceptions::none(),
                Stage::OnDisk {
                    traverses_reparse_point: true
                }
            ),
            Err(DenyReason::ReparsePointInPath)
        );
    }

    #[test]
    fn a_folder_that_holds_other_software_is_refused_as_a_whole() {
        for container in [
            r"C:\Users\anon",
            r"C:\Users\Public",
            r"C:\Users\anon\AppData",
            r"C:\Users\anon\AppData\Local",
            r"C:\Users\anon\AppData\LocalLow",
            r"C:\Users\anon\AppData\Roaming",
            r"C:\Users\anon\AppData\Local\Temp",
            r"C:\Users\anon\Documents",
            r"C:\Users\anon\Documents\My Games",
            r"C:\Users\anon\Saved Games",
            r"C:\Users\Public\Documents",
            r"C:\Program Files\Common Files",
            r"C:\Program Files (x86)\Common Files",
            r"C:\ProgramData\Package Cache",
            r"C:\Program Files (x86)\Steam",
            r"C:\Program Files (x86)\Steam\steamapps",
            r"C:\Program Files (x86)\Steam\steamapps\common",
            r"D:\SteamLibrary\steamapps\common",
            r"D:\SteamLibrary\steamapps\workshop",
            r"D:\Games\SteamLibrary",
            r"C:\Program Files\Epic Games",
            r"E:\Games\Epic Games",
        ] {
            assert_eq!(
                check_path(
                    &syntactic(container),
                    &catalog_exceptions(),
                    Stage::CatalogLoad
                ),
                Err(DenyReason::ProtectedContainer),
                "for {container}"
            );
        }
    }

    #[test]
    fn data_windows_owns_is_refused_at_any_depth() {
        for owned in [
            r"C:\Users\anon\AppData\Roaming\Microsoft\Protect",
            r"C:\Users\anon\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Example",
            r"C:\Users\anon\AppData\Local\Microsoft\Windows\INetCache",
            r"C:\Program Files\WindowsApps\Example_1.0_x64__abc",
            r"C:\Program Files\Windows Defender\MsMpEng.exe",
        ] {
            assert_eq!(
                check_path(&syntactic(owned), &catalog_exceptions(), Stage::CatalogLoad),
                Err(DenyReason::ProtectedWindowsData),
                "for {owned}"
            );
        }
    }

    #[test]
    fn a_user_hive_is_refused_wherever_it_is() {
        for hive in [
            r"C:\Users\anon\AppData\Local\Microsoft\Windows\UsrClass.dat",
            r"C:\Documents and Settings\anon\NTUSER.DAT",
            r"D:\Profiles\anon\ntuser.dat.LOG2",
        ] {
            assert_eq!(
                check_path(&syntactic(hive), &catalog_exceptions(), Stage::CatalogLoad),
                Err(DenyReason::ProtectedUserHive),
                "for {hive}"
            );
        }
    }

    #[test]
    fn footprint_inside_a_container_stays_allowed() {
        // The other direction, which matters as much: everything here is
        // footprint docs/02 permits removing, and every one sits inside a
        // container that is now refused as a whole.
        for allowed in [
            r"C:\Users\anon\AppData\Local\Riot Games\Riot Vanguard",
            r"C:\Users\anon\AppData\LocalLow\Example Studio\Example Shooter",
            r"C:\Users\anon\Documents\My Games\Example Shooter",
            r"C:\Users\Public\Desktop\Example Shooter.lnk",
            r"C:\Program Files (x86)\Steam\steamapps\common\Example Shooter",
            r"D:\SteamLibrary\steamapps\common\Example Shooter",
            r"C:\Program Files\Epic Games\ExampleShooter",
            r"C:\Program Files\Riot Vanguard",
            r"C:\ProgramData\AntiCheatExpert",
        ] {
            assert_eq!(
                check_path(
                    &syntactic(allowed),
                    &catalog_exceptions(),
                    Stage::CatalogLoad
                ),
                Ok(()),
                "deny-list wrongly refused {allowed}"
            );
        }
    }

    #[test]
    fn windows_drivers_and_services_cannot_be_unlocked() {
        let exceptions = Exceptions::new(
            ["ntfs.sys", "vgk.sys", "NTFS.SYS"],
            ["Tcpip", "vgk", " WinDefend "],
        );
        assert!(exceptions.allows_driver_file("vgk.sys"));
        assert!(!exceptions.allows_driver_file("ntfs.sys"));
        assert!(exceptions.allows_service("vgk"));
        assert!(!exceptions.allows_service("Tcpip"));
        assert!(!exceptions.allows_service("WinDefend"));
        assert!(
            check_path(
                &syntactic(r"C:\Windows\System32\drivers\ntfs.sys"),
                &exceptions,
                Stage::CatalogLoad
            )
            .is_err()
        );
        let tcpip = canonicalise_reg_key(r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip")
            .expect("valid key");
        assert_eq!(
            check_registry_key(&tcpip, &exceptions),
            Err(DenyReason::UnknownServiceKey)
        );
    }

    #[test]
    fn keys_that_hold_other_software_or_belong_to_windows_are_refused() {
        for (key, reason) in [
            (r"HKLM\SOFTWARE\Microsoft", DenyReason::ProtectedRegistryKey),
            (
                r"HKLM\SOFTWARE\WOW6432Node",
                DenyReason::ProtectedRegistryKey,
            ),
            (r"HKLM\SOFTWARE\Classes", DenyReason::ProtectedRegistryKey),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                DenyReason::ProtectedRegistryKey,
            ),
            (
                r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                DenyReason::ProtectedRegistryKey,
            ),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\x",
                DenyReason::ProtectedRegistryKey,
            ),
            (
                r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Cryptography\x",
                DenyReason::ProtectedRegistryKey,
            ),
            (
                r"HKLM\SYSTEM\CurrentControlSet",
                DenyReason::ProtectedSystemKey,
            ),
            (
                r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
                DenyReason::ProtectedSystemKey,
            ),
            (r"HKLM\SYSTEM\Setup", DenyReason::ProtectedSystemKey),
            (
                r"HKLM\HARDWARE\DESCRIPTION",
                DenyReason::ProtectedRegistryHive,
            ),
            (r"HKLM\COMPONENTS\x", DenyReason::ProtectedRegistryHive),
            (
                r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                DenyReason::ProtectedRegistryKey,
            ),
            (
                r"HKU\S-1-5-21-1-2-3-1001\SOFTWARE",
                DenyReason::RegistryKeyTooShallow,
            ),
            (
                r"HKU\S-1-5-21-1-2-3-1001\SOFTWARE\Microsoft",
                DenyReason::ProtectedRegistryKey,
            ),
            (
                r"HKU\S-1-5-21-1-2-3-1001_Classes\CLSID",
                DenyReason::ProtectedRegistryKey,
            ),
            (r"HKCC\Software\Fonts", DenyReason::ProtectedSystemKey),
        ] {
            let canonical = canonicalise_reg_key(key).expect("valid key");
            assert_eq!(
                check_registry_key(&canonical, &catalog_exceptions()),
                Err(reason),
                "for {key}"
            );
        }
    }

    #[test]
    fn registry_footprint_inside_a_container_stays_allowed() {
        for key in [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Riot Vanguard",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\EasyAntiCheat",
            r"HKLM\SOFTWARE\EasyAntiCheat",
            r"HKLM\SOFTWARE\WOW6432Node\EasyAntiCheat",
            r"HKLM\SYSTEM\CurrentControlSet\Services\vgk",
            r"HKCU\SOFTWARE\appdatalow\AntiCheatExpert\{4324E6D9-BA90-499E-9B3A-A7DAB216C94E}",
            r"HKU\S-1-5-21-1-2-3-1001\SOFTWARE\Riot Games",
            r"HKCR\CLSID\{4324E6D9-BA90-499E-9B3A-A7DAB216C94E}",
        ] {
            let canonical = canonicalise_reg_key(key).expect("valid key");
            assert_eq!(
                check_registry_key(&canonical, &catalog_exceptions()),
                Ok(()),
                "deny-list wrongly refused {key}"
            );
        }
    }

    #[test]
    fn denylist_blocks_protected_registry_hives() {
        for key in [
            r"HKLM\SAM",
            r"HKLM\SAM\SAM\Domains",
            r"HKLM\SECURITY\Policy",
            r"HKLM\BCD00000000",
        ] {
            let canonical = canonicalise_reg_key(key).expect("valid key");
            assert_eq!(
                check_registry_key(&canonical, &catalog_exceptions()),
                Err(DenyReason::ProtectedRegistryHive),
                "for {key}"
            );
        }
    }

    #[test]
    fn service_keys_are_allowed_only_when_the_catalog_names_them() {
        let exceptions = catalog_exceptions();
        let allowed =
            canonicalise_reg_key(r"HKLM\SYSTEM\CurrentControlSet\Services\vgk").expect("valid key");
        assert_eq!(check_registry_key(&allowed, &exceptions), Ok(()));

        for denied in [
            r"HKLM\SYSTEM\CurrentControlSet\Services",
            r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip",
            r"HKLM\SYSTEM\ControlSet001\Services\Tcpip",
            r"HKLM\SYSTEM\CurrentControlSet\Services\vgk\Parameters",
        ] {
            let canonical = canonicalise_reg_key(denied).expect("valid key");
            assert_eq!(
                check_registry_key(&canonical, &exceptions),
                Err(DenyReason::UnknownServiceKey),
                "for {denied}"
            );
        }
    }

    #[test]
    fn shallow_registry_keys_are_refused_but_ordinary_ones_are_not() {
        let shallow = canonicalise_reg_key(r"HKLM\SOFTWARE").expect("valid key");
        assert_eq!(
            check_registry_key(&shallow, &Exceptions::none()),
            Err(DenyReason::RegistryKeyTooShallow)
        );

        let ordinary = canonicalise_reg_key(r"HKLM\SOFTWARE\EasyAntiCheat").expect("valid key");
        assert_eq!(check_registry_key(&ordinary, &Exceptions::none()), Ok(()));
    }
}
