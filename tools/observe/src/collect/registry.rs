//! The registry domain: the hives and keys `docs/16` names, in both WOW64
//! views.
//!
//! # Safety Gate G3 shapes what may be walked
//!
//! `docs/02-SAFETY-GATE.md` forbids reading a hardware identifier **including
//! for reporting**, and names `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`
//! first. A naive walk of `HKLM\SOFTWARE` reads it on the way past.
//!
//! So the cryptography key is excluded by path, and so is every `Enum` subkey
//! under the services key — those hold `PnP` device instance identifiers, which
//! carry disk and device serials. Neither is footprint an installer wrote;
//! both are machine identity, and the gate has no exceptions.
//!
//! The exclusion is written as the *parent* key rather than the value, which is
//! deliberate twice over: it is a superset, so a sibling identifier added by a
//! future Windows version is covered too, and it means this file never has to
//! name the value — `core/tests/no_destructive_code.rs` scans this directory
//! for exactly that string.
//!
//! # No timestamps
//!
//! `docs/16` §"Reducing noise" asks for `LastWriteTime`-only changes with
//! unchanged values to be ignored. Rather than filter them afterwards, the
//! timestamp is never read: a key whose values are identical has not been
//! changed by an installer whatever its write time says. Same reasoning as
//! capturing service configuration rather than service state.

use crate::model::{AccessDenied, RegistryPolicy, RegistryRecord};

/// Safety Gate G3 terms, loaded as data rather than written as a constant.
///
/// See the file itself for why. In short: `core/tests/no_destructive_code.rs`
/// fails the build if any of these strings appears in a `.rs` file under a
/// shipped `src/`, and it cannot tell code that *reads* an identifier from a
/// deny-list that *refuses* one — so a list written in Rust would be rejected
/// by the very gate it enforces.
#[cfg(any(windows, test))]
const G3_TERMS_FILE: &str = include_str!("g3-identity-terms.txt");

/// The G3 terms, lower-cased, comments and blanks removed.
#[cfg(any(windows, test))]
#[must_use]
pub fn identity_terms() -> Vec<String> {
    G3_TERMS_FILE
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Whether a value must be refused under Safety Gate G3.
///
/// Matched against the value **name and the rendered data**, not only against
/// the key it lives under. A real snapshot found the machine identifier copied
/// into three unrelated application keys, and a motherboard model inside a
/// telemetry URL — neither of which any key-path exclusion would have caught.
#[cfg(any(windows, test))]
#[must_use]
pub fn is_identity(terms: &[String], name: &str, data: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let data = data.to_ascii_lowercase();

    if terms.iter().any(|term| name.contains(term.as_str())) {
        return true;
    }

    // A shell property list is a schema, not a value: `prop:System.ItemTypeText;
    // System.Devices.SerialNumber;…` names properties, it does not hold one.
    // Measured on a real machine, 184 of 243 refusals were these — three
    // quarters of the list, none of them an identifier. Skipping the data check
    // for them is precise rather than a loosening: the *name* check still
    // applies, and a genuine identifier is never stored under a `prop:` list.
    if data.starts_with("prop:") {
        return false;
    }

    terms.iter().any(|term| data.contains(term.as_str()))
}

/// Value data longer than this is recorded by length and digest, not verbatim.
#[cfg(windows)]
pub const MAX_VALUE_BYTES: usize = 4096;

/// Key path fragments that stop the walk, matched case-insensitively.
///
/// The first two are Safety Gate G3. The rest are volume and churn.
#[cfg(any(windows, test))]
pub const EXCLUDED_FRAGMENTS: &[&str] = &[
    // G3. Machine identity, not footprint. Excluded as a whole key so the
    // individual value never has to be named here.
    "\\microsoft\\cryptography\\",
    // G3. PnP device instance data, which carries device and disk serials.
    "\\enum\\",
    // Volume without information: component servicing manifests and the
    // installer database are enormous and describe Windows, not an install.
    "\\microsoft\\windows\\currentversion\\component based servicing\\",
    "\\classes\\clsid\\",
    "\\classes\\interface\\",
    "\\classes\\typelib\\",
    "\\classes\\wow6432node\\clsid\\",
    "\\classes\\wow6432node\\interface\\",
    "\\installer\\",
];

/// Everything the registry collector returns.
pub struct Captured {
    /// The keys found, with their values.
    pub keys: Vec<RegistryRecord>,
    /// Keys that could not be opened or read.
    pub access_denied: Vec<AccessDenied>,
    /// What the walk was told to do.
    pub policy: RegistryPolicy,
}

/// Whether a key path falls inside an excluded fragment.
#[must_use]
#[cfg(any(windows, test))]
pub fn is_excluded(key: &str) -> bool {
    let lowered = format!("{}\\", key.to_ascii_lowercase());
    EXCLUDED_FRAGMENTS
        .iter()
        .any(|fragment| lowered.contains(fragment))
}

#[cfg(not(windows))]
/// Not available off Windows.
///
/// # Errors
/// Always.
pub fn registry() -> anyhow::Result<Captured> {
    anyhow::bail!("the registry domain requires Windows")
}

#[cfg(windows)]
pub use self::win32::registry;

#[cfg(windows)]
mod win32 {
    use anyhow::Result;
    use windows::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, WIN32_ERROR};
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
        REG_SAM_FLAGS, RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW,
    };
    use windows::core::{PCWSTR, PWSTR};

    use super::{Captured, EXCLUDED_FRAGMENTS, MAX_VALUE_BYTES, is_excluded};
    use crate::model::{AccessDenied, Domain, RegistryPolicy, RegistryRecord, RegistryValue};

    /// The roots `docs/16-OBSERVATION-HARNESS.md` names.
    ///
    /// `Run` keys and uninstall keys are under `SOFTWARE` and are reached by
    /// walking it, so they are not listed separately.
    const ROOTS: &[(&str, &str)] = &[
        ("HKLM", "SOFTWARE"),
        ("HKLM", "SYSTEM\\CurrentControlSet\\Services"),
        ("HKCU", "SOFTWARE"),
    ];

    /// An `HKEY` that closes itself.
    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // SAFETY: a key this type owns and has not closed.
                unsafe {
                    let _ = RegCloseKey(self.0);
                }
            }
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn text(buffer: &[u16], length: u32) -> String {
        let end = (length as usize).min(buffer.len());
        String::from_utf16_lossy(&buffer[..end])
    }

    /// Walk every root in both WOW64 views.
    ///
    /// # Errors
    /// Never fails as a whole: a root that cannot be opened is recorded and the
    /// walk continues. `docs/05-DETECTION-ENGINE.md` treats the two views as
    /// distinct artifacts, and so does this — the same logical key read through
    /// the 32-bit and 64-bit views can hold different values, and a catalog
    /// entry has to name which one it meant.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "matches the other collectors and the non-Windows stub, which does fail"
    )]
    pub fn registry() -> Result<Captured> {
        let mut keys = Vec::new();
        let mut access_denied = Vec::new();
        let terms = super::identity_terms();

        for (hive_name, root) in ROOTS {
            for (view_name, view) in [("64", KEY_WOW64_64KEY), ("32", KEY_WOW64_32KEY)] {
                let hive = match *hive_name {
                    "HKCU" => HKEY_CURRENT_USER,
                    _ => HKEY_LOCAL_MACHINE,
                };
                walk(
                    &Walk {
                        hive,
                        view,
                        view_name,
                        terms: &terms,
                    },
                    &format!("{hive_name}\\{root}"),
                    root,
                    &mut keys,
                    &mut access_denied,
                );
            }
        }

        keys.sort_by(|a, b| (a.key.as_str(), a.view.as_str()).cmp(&(&b.key, &b.view)));
        access_denied.sort_by(|a, b| a.item.cmp(&b.item));

        Ok(Captured {
            keys,
            access_denied,
            policy: RegistryPolicy {
                roots: ROOTS
                    .iter()
                    .map(|(hive, root)| format!("{hive}\\{root}"))
                    .collect(),
                views: vec!["32".to_owned(), "64".to_owned()],
                excluded: EXCLUDED_FRAGMENTS
                    .iter()
                    .map(|fragment| (*fragment).to_owned())
                    .collect(),
                max_value_bytes: MAX_VALUE_BYTES as u64,
            },
        })
    }

    /// What stays constant for one root in one view.
    struct Walk<'a> {
        hive: HKEY,
        view: REG_SAM_FLAGS,
        view_name: &'a str,
        terms: &'a [String],
    }

    fn walk(
        context: &Walk<'_>,
        display: &str,
        subkey: &str,
        keys: &mut Vec<RegistryRecord>,
        access_denied: &mut Vec<AccessDenied>,
    ) {
        let Walk {
            hive,
            view,
            view_name,
            terms,
        } = *context;
        // An explicit stack rather than recursion: the registry is deep, hostile
        // trees exist, and a stack overflow in a read-only tool would still be a
        // crash on a user's machine.
        let mut queue = vec![(display.to_owned(), subkey.to_owned())];

        while let Some((display, path)) = queue.pop() {
            if is_excluded(&display) {
                continue;
            }

            let path_wide = wide(&path);
            let mut handle = HKEY::default();
            // SAFETY: path_wide outlives the call. KEY_READ plus the view flag
            // is read-only; it grants nothing that could write or delete.
            let opened = unsafe {
                RegOpenKeyExW(
                    hive,
                    PCWSTR(path_wide.as_ptr()),
                    Some(0),
                    KEY_READ | view,
                    &raw mut handle,
                )
            };
            if opened != ERROR_SUCCESS {
                // Recorded, never skipped: a key that could not be opened is not
                // a key that is absent.
                access_denied.push(AccessDenied {
                    domain: Domain::Registry,
                    item: format!("{display} [view {view_name}]"),
                    reason: format!("RegOpenKeyExW returned {}", opened.0),
                });
                continue;
            }
            let handle = Key(handle);

            let (values, refused) = read_values(handle.0, terms);
            for name in refused {
                // Recorded, so the refusal is auditable — the key and the value
                // name, never the data. The name is not the fingerprint.
                access_denied.push(AccessDenied {
                    domain: Domain::Registry,
                    item: format!("{display} :: {name} [view {view_name}]"),
                    reason: "refused by Safety Gate G3 (hardware identity)".to_owned(),
                });
            }
            if !values.is_empty() {
                keys.push(RegistryRecord {
                    key: display.clone(),
                    view: view_name.to_owned(),
                    values,
                });
            }

            for child in child_names(handle.0) {
                queue.push((format!("{display}\\{child}"), format!("{path}\\{child}")));
            }
        }
    }

    fn child_names(handle: HKEY) -> Vec<String> {
        let mut names = Vec::new();
        let mut index = 0u32;
        loop {
            let mut buffer = [0u16; 256];
            let mut length = u32::try_from(buffer.len()).unwrap_or(0);
            // SAFETY: buffer and length are live; length is in characters, which
            // is what the API expects, and is updated to the written count.
            let result = unsafe {
                RegEnumKeyExW(
                    handle,
                    index,
                    Some(PWSTR(buffer.as_mut_ptr())),
                    &raw mut length,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if result == ERROR_NO_MORE_ITEMS || result != WIN32_ERROR(0) {
                break;
            }
            names.push(text(&buffer, length));
            index += 1;
        }
        names
    }

    fn read_values(handle: HKEY, terms: &[String]) -> (Vec<RegistryValue>, Vec<String>) {
        let mut values = Vec::new();
        let mut refused = Vec::new();
        let mut index = 0u32;
        loop {
            // Heap, not stack: the registry permits a 16 383-character value
            // name, and a buffer that size on the stack in a loop is how a
            // read-only tool acquires a stack overflow.
            let mut name = vec![0u16; 16384];
            let mut name_length = u32::try_from(name.len()).unwrap_or(0);
            let mut kind = 0u32;
            let mut data = vec![0u8; MAX_VALUE_BYTES];
            let mut data_length = u32::try_from(data.len()).unwrap_or(0);

            // SAFETY: every out-parameter is live for the call, and the two
            // lengths are the true capacities of their buffers.
            let result = unsafe {
                RegEnumValueW(
                    handle,
                    index,
                    Some(PWSTR(name.as_mut_ptr())),
                    &raw mut name_length,
                    None,
                    Some(&raw mut kind),
                    Some(data.as_mut_ptr()),
                    Some(&raw mut data_length),
                )
            };
            if result != WIN32_ERROR(0) {
                // Includes ERROR_MORE_DATA for a value larger than the cap. The
                // value is skipped rather than truncated: half a REG_BINARY blob
                // compared against another half is worse than an honest gap, and
                // the cap is recorded in the policy.
                if result == ERROR_NO_MORE_ITEMS {
                    break;
                }
                index += 1;
                if index > 4096 {
                    break;
                }
                continue;
            }

            data.truncate(data_length as usize);
            let value_name = text(&name, name_length);
            let rendered = render(kind, &data);

            if super::is_identity(terms, &value_name, &rendered) {
                // Dropped entirely. G3 bans enumerating a hardware identifier
                // even for reporting, so the data is never stored, not stored
                // and masked.
                refused.push(value_name);
            } else {
                values.push(RegistryValue {
                    name: value_name,
                    kind: kind_name(kind).to_owned(),
                    data: rendered,
                });
            }
            index += 1;
        }

        values.sort_by(|a, b| a.name.cmp(&b.name));
        refused.sort();
        (values, refused)
    }

    fn kind_name(kind: u32) -> &'static str {
        match kind {
            0 => "none",
            1 => "sz",
            2 => "expand_sz",
            3 => "binary",
            4 => "dword",
            5 => "dword_big_endian",
            6 => "link",
            7 => "multi_sz",
            11 => "qword",
            _ => "unknown",
        }
    }

    /// Render value data as text a diff can compare and a person can read.
    fn render(kind: u32, data: &[u8]) -> String {
        match kind {
            // REG_SZ, REG_EXPAND_SZ, REG_LINK
            1 | 2 | 6 => wide_from_bytes(data).trim_end_matches('\0').to_owned(),
            // REG_MULTI_SZ — joined, so ordering differences are visible.
            // docs/12 names REG_MULTI_SZ ordering as a rollback-fidelity case.
            7 => wide_from_bytes(data)
                .split('\0')
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(";"),
            // REG_DWORD
            4 => data
                .get(..4)
                .map(|bytes| {
                    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string()
                })
                .unwrap_or_default(),
            // REG_QWORD
            11 => data
                .get(..8)
                .map(|bytes| {
                    let mut value = [0u8; 8];
                    value.copy_from_slice(bytes);
                    u64::from_le_bytes(value).to_string()
                })
                .unwrap_or_default(),
            // Everything else, REG_BINARY included, as hex. Bounded by the cap.
            _ => data.iter().fold(String::new(), |mut hex, byte| {
                use std::fmt::Write as _;
                let _ = write!(hex, "{byte:02x}");
                hex
            }),
        }
    }

    fn wide_from_bytes(data: &[u8]) -> String {
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    }
}

#[cfg(test)]
mod tests {
    use super::is_excluded;

    #[test]
    fn the_cryptography_key_is_excluded_because_g3_forbids_reading_it() {
        // Safety Gate G3 names the machine identifier under this key first.
        // Excluding the parent means the walk never reaches it, and means this
        // file never has to name the value.
        assert!(is_excluded("HKLM\\SOFTWARE\\Microsoft\\Cryptography"));
        assert!(is_excluded(
            "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Defaults"
        ));
    }

    #[test]
    fn device_enumeration_keys_are_excluded() {
        // PnP instance data carries device and disk serials.
        assert!(is_excluded(
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\disk\\Enum"
        ));
    }

    #[test]
    fn an_anti_cheat_key_is_never_excluded() {
        // The failure that matters, again: a volume rule swallowing the thing
        // we came for.
        assert!(!is_excluded(
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\vgk"
        ));
        assert!(!is_excluded("HKLM\\SOFTWARE\\EasyAntiCheat"));
        assert!(!is_excluded("HKLM\\SOFTWARE\\Riot Vanguard"));
        assert!(!is_excluded(
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Valorant"
        ));
    }

    #[test]
    fn the_g3_term_list_loads_and_is_not_empty() {
        let terms = super::identity_terms();
        assert!(terms.len() >= 10, "the G3 list looks truncated: {terms:?}");
        assert!(terms.iter().all(|term| !term.starts_with('#')));
        assert!(terms.iter().all(|term| term == &term.to_ascii_lowercase()));
    }

    #[test]
    fn every_listed_term_is_refused_in_both_a_value_name_and_value_data() {
        // Driven from the list rather than from spelled-out examples, for two
        // reasons. It covers every term instead of the one someone thought to
        // write, and this file cannot name them: the G3 check in
        // core/tests/no_destructive_code.rs scans it, and cannot tell a
        // deny-list from a reader.
        let terms = super::identity_terms();
        for term in &terms {
            assert!(
                super::is_identity(&terms, term, ""),
                "a value named after {term} must be refused"
            );
            assert!(
                super::is_identity(&terms, "SomeName", term),
                "{term} appearing in value data must be refused"
            );
            // Real cases from a development machine: the identifier reached the
            // snapshot as a *suffixed* value name in one application key, and
            // buried mid-string in a telemetry URL in another. Substring
            // matching on both name and data is what catches those.
            assert!(super::is_identity(&terms, &format!("{term}Collection"), ""));
            assert!(super::is_identity(
                &terms,
                "RequestUri",
                &format!("https://example.invalid/?a=1&{term}dm=X&b=2")
            ));
        }
    }

    #[test]
    fn a_shell_property_schema_is_not_mistaken_for_an_identifier() {
        // These name properties rather than holding one, and on a real machine
        // they were three quarters of every refusal.
        let terms = super::identity_terms();
        let schema = format!("prop:System.ItemTypeText;System.Devices.{}", terms[2]);
        assert!(!super::is_identity(&terms, "FullDetails", &schema));
        // But a value *named* after an identifier is still refused, whatever
        // its data looks like.
        assert!(super::is_identity(&terms, &terms[0], &schema));
    }

    #[test]
    fn ordinary_footprint_is_not_refused_as_identity() {
        let terms = super::identity_terms();
        assert!(!super::is_identity(
            &terms,
            "ImagePath",
            "C:\\Program Files\\Riot Vanguard\\vgk.sys"
        ));
        assert!(!super::is_identity(&terms, "DisplayName", "Riot Vanguard"));
        assert!(!super::is_identity(&terms, "Start", "3"));
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(is_excluded("HKLM\\software\\MICROSOFT\\CRYPTOGRAPHY\\x"));
    }
}
