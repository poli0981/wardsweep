//! Canonical path and registry-key forms.
//!
//! `docs/05-DETECTION-ENGINE.md` is explicit that the deny-list is enforced on
//! the *canonicalised* path, and that "checking the pre-canonical string is a
//! bug class, not a shortcut". This module exists so that rule is enforced by
//! the type system rather than by remembering: [`super::denylist`] accepts only
//! [`CanonicalPath`] and [`CanonicalRegKey`], neither of which can be built
//! from a raw string without going through canonicalisation first.
//!
//! Everything here is pure string logic and contains no Win32 calls, so it
//! compiles and is tested on Linux CI as well as Windows. Resolving a path
//! through an open handle (`GetFinalPathNameByHandleW`) is a separate,
//! Windows-only step that produces the same type — see `canonicalise_resolved`.

use std::fmt;

/// Path forms WardSweep has to recognise before it can judge them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// Rooted at a drive letter: `C:\Windows\System32`.
    DriveRooted,
    /// A UNC share, including admin shares: `\\localhost\C$\Windows`.
    Unc,
    /// The device namespace: `\\.\GLOBALROOT\Device\HarddiskVolume3\Windows`.
    Device,
}

/// Why a string could not be reduced to a canonical path.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// The input was empty or only separators.
    #[error("path is empty")]
    Empty,
    /// The input contained an interior NUL, which no Win32 API accepts.
    #[error("path contains an embedded NUL")]
    EmbeddedNul,
    /// The input was relative. WardSweep never acts on relative paths.
    #[error("path is not absolute: {0}")]
    NotAbsolute(String),
    /// More `..` segments than there were components to consume.
    #[error("path escapes its root: {0}")]
    EscapesRoot(String),
    /// A UNC path without both a host and a share.
    #[error("malformed UNC path: {0}")]
    MalformedUnc(String),
}

/// A path reduced to one unambiguous form.
///
/// Two spellings of the same location — different case, forward slashes, an
/// extended-length prefix, redundant `.` and `..` segments — produce equal
/// values. An 8.3 alias does *not*: it is recorded as unresolved, because
/// expanding it requires the filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPath {
    text: String,
    kind: PathKind,
    drive: Option<char>,
    components: Vec<String>,
    short_name: bool,
    resolved_via_handle: bool,
}

impl CanonicalPath {
    /// Which namespace this path lives in.
    #[must_use]
    pub fn kind(&self) -> PathKind {
        self.kind
    }

    /// The uppercase drive letter, when the path is drive-rooted.
    #[must_use]
    pub fn drive(&self) -> Option<char> {
        self.drive
    }

    /// Uppercased path components below the root, root prefix excluded.
    ///
    /// For `C:\Windows\System32` this is `["WINDOWS", "SYSTEM32"]`. For
    /// `\\host\C$\Windows` it is `["WINDOWS"]`, with host and share held
    /// separately in the rendered text.
    #[must_use]
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// Whether any component is an 8.3 alias such as `PROGRA~1`.
    ///
    /// An alias cannot be expanded without touching the filesystem, so the
    /// deny-list treats an unresolved alias as denied rather than guessing.
    #[must_use]
    pub fn contains_short_name(&self) -> bool {
        self.short_name
    }

    /// Whether this path came from an actual open handle rather than from
    /// string rewriting alone.
    #[must_use]
    pub fn is_handle_resolved(&self) -> bool {
        self.resolved_via_handle
    }

    /// The canonical rendering, preserving the original casing for display.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether the components below the root begin with `prefix`.
    ///
    /// `prefix` entries are compared case-insensitively.
    #[must_use]
    pub fn starts_with(&self, prefix: &[&str]) -> bool {
        prefix.len() <= self.components.len()
            && prefix
                .iter()
                .zip(&self.components)
                .all(|(want, have)| have.eq_ignore_ascii_case(want))
    }

    /// Whether the components below the root are exactly `whole`.
    #[must_use]
    pub fn equals(&self, whole: &[&str]) -> bool {
        whole.len() == self.components.len() && self.starts_with(whole)
    }
}

impl fmt::Display for CanonicalPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Reduce a path to canonical form using string rewriting only.
///
/// This is the form available before a handle can be opened — during catalog
/// validation, on Linux CI, and for paths that no longer exist on disk. It
/// deliberately does **not** resolve reparse points or 8.3 aliases; those are
/// recorded so the deny-list can refuse rather than assume.
///
/// # Errors
///
/// Returns [`PathError`] when the input is empty, relative, contains a NUL,
/// escapes its own root through `..`, or is a malformed UNC path.
pub fn canonicalise_syntactic(input: &str) -> Result<CanonicalPath, PathError> {
    if input.contains('\0') {
        return Err(PathError::EmbeddedNul);
    }
    let unified = input.replace('/', "\\");
    let trimmed = unified.trim();
    if trimmed.is_empty() {
        return Err(PathError::Empty);
    }

    let (kind, root, rest) = split_root(trimmed)?;
    let (components, short_name) = normalise_components(rest, trimmed)?;

    let text = render(kind, &root, &components);
    let drive = match kind {
        PathKind::DriveRooted => root.chars().next().map(|c| c.to_ascii_uppercase()),
        _ => None,
    };

    Ok(CanonicalPath {
        text,
        kind,
        drive,
        components,
        short_name,
        resolved_via_handle: false,
    })
}

/// Wrap a path that Windows itself has already resolved through an open handle.
///
/// The caller is asserting that `final_path` came from `GetFinalPathNameByHandleW`
/// on a handle opened with `FILE_FLAG_OPEN_REPARSE_POINT`, so reparse points and
/// 8.3 aliases are already gone. The string is still canonicalised here, because
/// the returned form keeps its `\\?\` prefix and arbitrary casing.
///
/// # Errors
///
/// Returns [`PathError`] for the same reasons as [`canonicalise_syntactic`].
pub fn canonicalise_resolved(final_path: &str) -> Result<CanonicalPath, PathError> {
    let mut path = canonicalise_syntactic(final_path)?;
    path.resolved_via_handle = true;
    // A handle-resolved path cannot still hold an alias; Windows expands them.
    path.short_name = false;
    Ok(path)
}

/// Split the root prefix from the remainder, identifying the namespace.
fn split_root(path: &str) -> Result<(PathKind, String, &str), PathError> {
    // `\\?\UNC\host\share\...` — extended-length UNC.
    if let Some(rest) = strip_prefix_ci(path, r"\\?\UNC\") {
        return unc_root(rest, path);
    }
    // `\\?\C:\...` — extended-length drive path. Also `\\?\GLOBALROOT\...`.
    if let Some(rest) = strip_prefix_ci(path, r"\\?\") {
        if starts_with_globalroot(rest) {
            return Ok((PathKind::Device, r"\\?\".to_owned(), rest));
        }
        return drive_root(rest, path);
    }
    // `\\.\...` — device namespace.
    if let Some(rest) = strip_prefix_ci(path, r"\\.\") {
        return Ok((PathKind::Device, r"\\.\".to_owned(), rest));
    }
    // `\??\...` — the NT object namespace. Rarely typed by hand, accepted by
    // enough APIs to be worth naming rather than falling through to "not
    // absolute", so that it is refused for the right reason.
    if let Some(rest) = path.strip_prefix(r"\??\") {
        return Ok((PathKind::Device, r"\??\".to_owned(), rest));
    }
    // `\\host\share\...` — plain UNC.
    if let Some(rest) = path.strip_prefix(r"\\") {
        return unc_root(rest, path);
    }
    drive_root(path, path)
}

fn strip_prefix_ci<'a>(haystack: &'a str, prefix: &str) -> Option<&'a str> {
    (haystack.len() >= prefix.len() && haystack[..prefix.len()].eq_ignore_ascii_case(prefix))
        .then(|| &haystack[prefix.len()..])
}

fn starts_with_globalroot(rest: &str) -> bool {
    strip_prefix_ci(rest, "GLOBALROOT\\").is_some() || rest.eq_ignore_ascii_case("GLOBALROOT")
}

fn drive_root<'a>(
    candidate: &'a str,
    original: &str,
) -> Result<(PathKind, String, &'a str), PathError> {
    let bytes = candidate.as_bytes();
    let looks_rooted =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    // `C:` on its own is the drive root with nothing after it.
    let bare_drive = bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if !looks_rooted && !bare_drive {
        return Err(PathError::NotAbsolute(original.to_owned()));
    }
    let letter = candidate.as_bytes()[0].to_ascii_uppercase() as char;
    let rest = if bare_drive { "" } else { &candidate[3..] };
    Ok((PathKind::DriveRooted, format!("{letter}:"), rest))
}

fn unc_root<'a>(rest: &'a str, original: &str) -> Result<(PathKind, String, &'a str), PathError> {
    let mut parts = rest.splitn(3, '\\');
    let host = parts.next().unwrap_or_default();
    let share = parts.next().unwrap_or_default();
    if host.is_empty() || share.is_empty() {
        return Err(PathError::MalformedUnc(original.to_owned()));
    }
    let tail = parts.next().unwrap_or("");
    Ok((PathKind::Unc, format!(r"\\{host}\{share}"), tail))
}

/// Drop `.`, apply `..`, uppercase for comparison, and flag 8.3 aliases.
fn normalise_components(rest: &str, original: &str) -> Result<(Vec<String>, bool), PathError> {
    let mut out: Vec<String> = Vec::new();
    let mut short_name = false;
    for raw in rest.split('\\') {
        // Trailing separators and doubled separators produce empty segments.
        let segment = raw.trim_end_matches(' ').trim_end_matches('.');
        // A segment that was only dots is `.` or `..`; recover that first.
        match raw.trim() {
            // Empty segments come from doubled or trailing separators; `.` is
            // the current directory. Both are noise.
            "" | "." => continue,
            ".." => {
                if out.pop().is_none() {
                    return Err(PathError::EscapesRoot(original.to_owned()));
                }
                continue;
            }
            _ => {}
        }
        let segment = if segment.is_empty() {
            raw.trim()
        } else {
            segment
        };
        if is_short_name(segment) {
            short_name = true;
        }
        out.push(segment.to_ascii_uppercase());
    }
    Ok((out, short_name))
}

/// An 8.3 alias is `NAME~N` with an optional short extension: `PROGRA~1`.
///
/// Detection is deliberately loose. A false positive costs one refusal that the
/// handle-resolved path would have allowed; a false negative lets an alias of a
/// protected directory through the deny-list, which is the bug this exists to
/// prevent.
fn is_short_name(segment: &str) -> bool {
    let stem = segment.split('.').next().unwrap_or(segment);
    let Some(tilde) = stem.rfind('~') else {
        return false;
    };
    let suffix = &stem[tilde + 1..];
    !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
}

fn render(kind: PathKind, root: &str, components: &[String]) -> String {
    let mut text = String::with_capacity(root.len() + components.len() * 12);
    text.push_str(root);
    if kind == PathKind::DriveRooted && components.is_empty() {
        text.push('\\');
    }
    for component in components {
        text.push('\\');
        text.push_str(component);
    }
    text
}

/// The registry hives WardSweep is willing to name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    /// `HKEY_LOCAL_MACHINE`.
    Hklm,
    /// `HKEY_CURRENT_USER`.
    Hkcu,
    /// `HKEY_USERS`.
    Hku,
    /// `HKEY_CLASSES_ROOT`.
    Hkcr,
    /// `HKEY_CURRENT_CONFIG`.
    Hkcc,
}

impl Hive {
    /// The short form used throughout the catalog and the documentation.
    #[must_use]
    pub fn short(self) -> &'static str {
        match self {
            Self::Hklm => "HKLM",
            Self::Hkcu => "HKCU",
            Self::Hku => "HKU",
            Self::Hkcr => "HKCR",
            Self::Hkcc => "HKCC",
        }
    }
}

/// Why a string could not be reduced to a canonical registry key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegKeyError {
    /// The key did not begin with a hive this project recognises.
    #[error("unknown or unsupported registry hive: {0}")]
    UnknownHive(String),
    /// The input was empty.
    #[error("registry key is empty")]
    Empty,
}

/// A registry key reduced to hive plus uppercased subkey components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRegKey {
    hive: Hive,
    components: Vec<String>,
    text: String,
}

impl CanonicalRegKey {
    /// Which hive the key lives in.
    #[must_use]
    pub fn hive(&self) -> Hive {
        self.hive
    }

    /// Uppercased subkey components below the hive.
    #[must_use]
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// The canonical rendering.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether the subkey components begin with `prefix`, case-insensitively.
    #[must_use]
    pub fn starts_with(&self, prefix: &[&str]) -> bool {
        prefix.len() <= self.components.len()
            && prefix
                .iter()
                .zip(&self.components)
                .all(|(want, have)| have.eq_ignore_ascii_case(want))
    }
}

impl fmt::Display for CanonicalRegKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Reduce a registry key string to canonical form.
///
/// Accepts both the short (`HKLM\...`) and long (`HKEY_LOCAL_MACHINE\...`)
/// hive spellings, any separator run, and any casing.
///
/// # Errors
///
/// Returns [`RegKeyError`] when the string is empty or does not start with a
/// hive WardSweep recognises.
pub fn canonicalise_reg_key(input: &str) -> Result<CanonicalRegKey, RegKeyError> {
    let unified = input.replace('/', "\\");
    let trimmed = unified.trim().trim_matches('\\');
    if trimmed.is_empty() {
        return Err(RegKeyError::Empty);
    }

    let mut parts = trimmed.split('\\');
    let head = parts.next().unwrap_or_default();
    let hive = match head.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => Hive::Hklm,
        "HKCU" | "HKEY_CURRENT_USER" => Hive::Hkcu,
        "HKU" | "HKEY_USERS" => Hive::Hku,
        "HKCR" | "HKEY_CLASSES_ROOT" => Hive::Hkcr,
        "HKCC" | "HKEY_CURRENT_CONFIG" => Hive::Hkcc,
        _ => return Err(RegKeyError::UnknownHive(input.to_owned())),
    };

    let components: Vec<String> = parts
        .filter(|segment| !segment.trim().is_empty())
        .map(|segment| segment.trim().to_ascii_uppercase())
        .collect();

    let mut text = String::from(hive.short());
    for component in &components {
        text.push('\\');
        text.push_str(component);
    }

    Ok(CanonicalRegKey {
        hive,
        components,
        text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spellings_of_system32_all_collapse_to_one_form() {
        let forms = [
            r"C:\Windows\System32",
            r"C:\WINDOWS\system32",
            r"c:/windows/system32",
            r"\\?\C:\Windows\System32",
            r"C:\Windows\..\Windows\System32",
            "C:\\Windows\\\\System32\\",
        ];
        let canonical: Vec<_> = forms
            .iter()
            .map(|f| canonicalise_syntactic(f).expect("valid path"))
            .collect();
        for path in &canonical {
            assert_eq!(path.components(), ["WINDOWS", "SYSTEM32"]);
            assert_eq!(path.drive(), Some('C'));
            assert_eq!(path.kind(), PathKind::DriveRooted);
        }
        assert!(canonical.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn unc_and_device_forms_keep_their_kind() {
        let unc = canonicalise_syntactic(r"\\localhost\C$\Windows").expect("valid unc");
        assert_eq!(unc.kind(), PathKind::Unc);
        assert_eq!(unc.components(), ["WINDOWS"]);
        assert_eq!(unc.drive(), None);

        let device = canonicalise_syntactic(r"\\.\GLOBALROOT\Device\HarddiskVolume3\Windows")
            .expect("valid device path");
        assert_eq!(device.kind(), PathKind::Device);

        let extended_globalroot =
            canonicalise_syntactic(r"\\?\GLOBALROOT\Device\HarddiskVolume3\Windows")
                .expect("valid device path");
        assert_eq!(extended_globalroot.kind(), PathKind::Device);
    }

    #[test]
    fn eight_dot_three_aliases_are_flagged_not_expanded() {
        let alias = canonicalise_syntactic(r"C:\PROGRA~1").expect("valid path");
        assert!(alias.contains_short_name());
        assert!(!alias.is_handle_resolved());

        let ordinary = canonicalise_syntactic(r"C:\Program Files").expect("valid path");
        assert!(!ordinary.contains_short_name());

        // A tilde that is not an 8.3 marker must not trip the check.
        let tilde_name = canonicalise_syntactic(r"C:\Games\my~backup").expect("valid path");
        assert!(!tilde_name.contains_short_name());
    }

    #[test]
    fn handle_resolved_paths_are_marked_and_alias_free() {
        let resolved = canonicalise_resolved(r"\\?\C:\PROGRA~1").expect("valid path");
        assert!(resolved.is_handle_resolved());
        assert!(!resolved.contains_short_name());
    }

    #[test]
    fn nt_object_paths_are_recognised_as_device_paths() {
        let nt = canonicalise_syntactic(r"\??\C:\Windows\System32").expect("valid path");
        assert_eq!(nt.kind(), PathKind::Device);
    }

    #[test]
    fn relative_and_malformed_inputs_are_rejected() {
        assert!(matches!(
            canonicalise_syntactic(r"Windows\System32"),
            Err(PathError::NotAbsolute(_))
        ));
        // Drive-relative (`C:Windows`) and rooted-without-drive (`\Windows`)
        // both resolve against ambient state Win32 keeps per process. Neither
        // is something WardSweep may act on.
        assert!(matches!(
            canonicalise_syntactic(r"C:Windows\System32"),
            Err(PathError::NotAbsolute(_))
        ));
        assert!(matches!(
            canonicalise_syntactic(r"\Windows\System32"),
            Err(PathError::NotAbsolute(_))
        ));
        assert!(matches!(
            canonicalise_syntactic("   "),
            Err(PathError::Empty)
        ));
        assert!(matches!(
            canonicalise_syntactic("C:\\Win\0dows"),
            Err(PathError::EmbeddedNul)
        ));
        assert!(matches!(
            canonicalise_syntactic(r"C:\..\.."),
            Err(PathError::EscapesRoot(_))
        ));
        assert!(matches!(
            canonicalise_syntactic(r"\\host"),
            Err(PathError::MalformedUnc(_))
        ));
    }

    #[test]
    fn trailing_dots_and_spaces_are_stripped_like_win32_does() {
        // Win32 silently strips these, so `C:\Windows.` and `C:\Windows` are the
        // same directory. Treating them as different would be a deny-list bypass.
        let dotted = canonicalise_syntactic(r"C:\Windows.\System32 ").expect("valid path");
        assert_eq!(dotted.components(), ["WINDOWS", "SYSTEM32"]);
    }

    #[test]
    fn registry_keys_accept_both_hive_spellings() {
        let short = canonicalise_reg_key(r"HKLM\SOFTWARE\EasyAntiCheat").expect("valid key");
        let long =
            canonicalise_reg_key(r"hkey_local_machine\software\easyanticheat").expect("valid key");
        assert_eq!(short, long);
        assert_eq!(short.hive(), Hive::Hklm);
        assert_eq!(short.components(), ["SOFTWARE", "EASYANTICHEAT"]);
        assert!(short.starts_with(&["software"]));
    }

    #[test]
    fn registry_keys_with_unknown_hives_are_rejected() {
        assert!(matches!(
            canonicalise_reg_key(r"HKEY_PERFORMANCE_DATA\Foo"),
            Err(RegKeyError::UnknownHive(_))
        ));
    }
}
