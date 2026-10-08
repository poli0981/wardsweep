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
//! The same walk also refuses personal identity and activity history. What is
//! refused, and why, lives in [`crate::policy`], because the differ applies the
//! same rules again to snapshots an older build took.
//!
//! # No timestamps
//!
//! `docs/16` §"Reducing noise" asks for `LastWriteTime`-only changes with
//! unchanged values to be ignored. Rather than filter them afterwards, the
//! timestamp is never read: a key whose values are identical has not been
//! changed by an installer whatever its write time says. Same reasoning as
//! capturing service configuration rather than service state.

use crate::model::{AccessDenied, RegistryPolicy, RegistryRecord};

/// Value data longer than this is skipped rather than recorded.
///
/// Skipped, not truncated: half a `REG_BINARY` blob compared against another
/// half is worse than an honest gap. The cap is recorded in
/// [`RegistryPolicy::max_value_bytes`].
#[cfg(windows)]
pub const MAX_VALUE_BYTES: usize = 4096;

/// Everything the registry collector returns.
pub struct Captured {
    /// The keys found, with their values.
    pub keys: Vec<RegistryRecord>,
    /// Keys that could not be opened or read.
    pub access_denied: Vec<AccessDenied>,
    /// What the walk was told to do.
    pub policy: RegistryPolicy,
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

    use super::{Captured, MAX_VALUE_BYTES};
    use crate::model::{AccessDenied, Domain, RegistryPolicy, RegistryRecord, RegistryValue};
    use crate::policy::{EXCLUDED_FRAGMENTS, Policy, Refusal, is_excluded};

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
        let policy = Policy::current();

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
                        policy: &policy,
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
        policy: &'a Policy,
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
            policy,
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

            let (values, refused) = read_values(handle.0, policy);
            for (name, refusal) in refused {
                // Recorded, so the refusal is auditable — the key and the value
                // name, never the data. The name is not the fingerprint.
                access_denied.push(AccessDenied {
                    domain: Domain::Registry,
                    item: format!("{display} :: {name} [view {view_name}]"),
                    reason: reason(refusal).to_owned(),
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

    /// The reason recorded in `access_denied`, so a refusal is auditable.
    ///
    /// Here rather than on [`Refusal`] because the collector is the only thing
    /// that writes one, and it only exists on Windows.
    fn reason(refusal: Refusal) -> &'static str {
        match refusal {
            Refusal::HardwareIdentity => "refused by Safety Gate G3 (hardware identity)",
            Refusal::PersonalIdentity => "refused: personal identity",
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

    fn read_values(handle: HKEY, policy: &Policy) -> (Vec<RegistryValue>, Vec<(String, Refusal)>) {
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

            if let Some(refusal) = policy.refusal(&value_name, &rendered) {
                // Dropped entirely. G3 bans enumerating a hardware identifier
                // even for reporting, and personal identity has no business in
                // a file meant for a public repository, so the data is never
                // stored — not stored and masked.
                refused.push((value_name, refusal));
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
        refused.sort_by(|a, b| a.0.cmp(&b.0));
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
