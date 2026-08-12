//! The compiled-in deny-list.
//!
//! `docs/05-DETECTION-ENGINE.md` specifies a fixed set of paths and registry
//! keys that WardSweep may never modify. Three properties matter more than the
//! list itself:
//!
//! 1. **It is compiled in.** No catalog, config file, flag or environment
//!    variable can add to it. [`Exceptions`] is the only thing a catalog
//!    contributes, and it can only unlock the two narrow carve-outs the
//!    deny-list already defines — it cannot introduce new ones.
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
    /// `HKLM\SAM`, `HKLM\SECURITY`, or `HKLM\BCD*`.
    #[error("registry key is inside a protected hive")]
    ProtectedRegistryHive,
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

    /// Build the carve-outs from driver filenames and service names that a
    /// verified catalog declared.
    ///
    /// Only the base filename of a driver is retained; a catalog cannot smuggle
    /// a directory in through this field.
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
                .collect(),
            service_names: service_names
                .into_iter()
                .map(|name| name.as_ref().to_ascii_uppercase())
                .filter(|name| !name.is_empty())
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

    // C:\Users\**\NTUSER.DAT*
    if top.eq_ignore_ascii_case("USERS")
        && components
            .last()
            .is_some_and(|leaf| leaf.starts_with("NTUSER.DAT"))
    {
        return Err(DenyReason::ProtectedUserHive);
    }

    // C:\ProgramData\Microsoft\**
    if path.starts_with(&["ProgramData", "Microsoft"]) {
        return Err(DenyReason::ProtectedProgramData);
    }

    if components.len() < MIN_COMPONENTS_UNDER_DRIVE_ROOT {
        return Err(DenyReason::TooShallow);
    }

    Ok(())
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

    if key.hive() == Hive::Hklm {
        if let Some(first) = components.first()
            && (first.eq_ignore_ascii_case("SAM")
                || first.eq_ignore_ascii_case("SECURITY")
                || first.starts_with("BCD"))
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
    }

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
