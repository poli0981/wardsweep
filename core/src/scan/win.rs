//! The machine, read through Win32.
//!
//! [`Machine`] is the [`MachineView`] `wardsweep scan` audits with. Every call
//! here reads: services are opened for query only, keys with `KEY_READ`, paths
//! without following a reparse point, and signatures through `WinVerifyTrust`.
//! `core/tests/no_destructive_code.rs` holds this file to that, as it does
//! every other.
//!
//! What cannot be read is unreadable, never absent: a service key an
//! anti-cheat denies the scanning user, a listing that stops part-way, a
//! library list that will not parse. Each reaches the report and makes the
//! scan partial.
//!
//! # Signatures, offline
//!
//! `docs/05` names `WTD_REVOKE_WHOLECHAIN`, and WardSweep makes no network
//! call (`docs/19`, "Zero-network is a feature"). Both hold: revocation is
//! checked against what this machine has cached, and nothing is fetched. A
//! revocation the cache cannot answer does not fail a signature that verifies;
//! one the cache does know is [`Signature::Invalid`]. An expired certificate is
//! not a downgrade either, as `docs/05` asks of old anti-cheat builds.

use std::io::ErrorKind;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA,
    ERROR_NO_MORE_ITEMS, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SUCCESS, HANDLE, HWND, WIN32_ERROR,
};
use windows::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_FIND_SUBJECT_CERT, CERT_INFO, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_ENCODING_TYPE,
    CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO,
    CMSG_SIGNER_INFO_PARAM, CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
    CertGetNameStringW, CryptMsgClose, CryptMsgGetParam, CryptQueryObject, HCERTSTORE,
};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
};
use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    HKEY_USERS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_ROUTINE_FLAGS, REG_SAM_FLAGS,
    RRF_NOEXPAND, RRF_RT_REG_DWORD, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6432KEY,
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW,
    SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_QUERY_CONFIG,
};
use windows::core::{GUID, PCWSTR, PWSTR};

use super::engine::Environment;
use super::libraries::{self, Launcher};
use super::model::RegView;
use super::view::{
    DriverKeys, Lookup, MachineView, PathKind, ServiceKey, ServiceStatus, Signature,
};
use crate::catalog::expand::KNOWN_VARIABLES;
use crate::safety::paths::{Hive, canonicalise_reg_key};

/// `HKLM\SYSTEM\CurrentControlSet\Services`, below the hive.
const SERVICES: &str = "SYSTEM\\CurrentControlSet\\Services";

/// This machine, read through Win32.
#[derive(Debug, Default, Clone, Copy)]
pub struct Machine;

impl MachineView for Machine {
    fn service(&self, name: &str) -> Lookup<ServiceStatus> {
        query_service(name)
    }

    fn service_key(&self, name: &str) -> Lookup<ServiceKey> {
        match open(
            HKEY_LOCAL_MACHINE,
            &format!("{SERVICES}\\{name}"),
            KEY_WOW64_64KEY,
        ) {
            Ok(key) => Lookup::Found(read_service_key(&key, name)),
            Err(error) => absent_or_unreadable(error),
        }
    }

    fn driver_keys(&self) -> Lookup<DriverKeys> {
        let services = match open(HKEY_LOCAL_MACHINE, SERVICES, KEY_WOW64_64KEY) {
            Ok(key) => key,
            Err(error) => return absent_or_unreadable(error),
        };
        let names = match subkeys(&services) {
            Ok(names) => names,
            Err(error) => {
                return Lookup::Unreadable(format!(
                    "listing its keys stopped part-way: {}",
                    describe(error)
                ));
            }
        };
        let mut found = DriverKeys::default();
        for name in names {
            match open(services.0, &name, KEY_WOW64_64KEY) {
                Ok(key) => {
                    let entry = read_service_key(&key, &name);
                    if entry.is_driver() {
                        found.drivers.push(entry);
                    }
                }
                // Deleted between the listing and the open: gone, not hidden.
                Err(error) if error == ERROR_FILE_NOT_FOUND => {}
                Err(error) => found.unreadable.push((name, describe(error))),
            }
        }
        Lookup::Found(found)
    }

    fn registry_key(&self, key: &str, view: RegView) -> Lookup<()> {
        let canonical = match canonicalise_reg_key(key) {
            Ok(canonical) => canonical,
            Err(error) => return Lookup::Unreadable(error.to_string()),
        };
        let root = match canonical.hive() {
            Hive::Hklm => HKEY_LOCAL_MACHINE,
            Hive::Hkcu => HKEY_CURRENT_USER,
            Hive::Hku => HKEY_USERS,
            Hive::Hkcr => HKEY_CLASSES_ROOT,
            Hive::Hkcc => HKEY_CURRENT_CONFIG,
        };
        let flag = match view {
            RegView::Bits64 => KEY_WOW64_64KEY,
            RegView::Bits32 => KEY_WOW64_32KEY,
        };
        match open(root, &canonical.components().join("\\"), flag) {
            Ok(_) => Lookup::Found(()),
            Err(error) => absent_or_unreadable(error),
        }
    }

    fn path(&self, path: &str) -> Lookup<PathKind> {
        // `symlink_metadata` opens with FILE_FLAG_OPEN_REPARSE_POINT: a link is
        // described, never followed.
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 => {
                Lookup::Found(PathKind::ReparsePoint)
            }
            Ok(metadata) if metadata.is_dir() => Lookup::Found(PathKind::Directory),
            Ok(_) => Lookup::Found(PathKind::File),
            Err(error) if error.kind() == ErrorKind::NotFound => Lookup::Absent,
            Err(error) => Lookup::Unreadable(error.to_string()),
        }
    }

    fn signature(&self, path: &str) -> Signature {
        signature(Path::new(path))
    }
}

/// The values this machine gives a catalog's placeholders: the folders Windows
/// names in its environment, and one value per game library the launchers
/// name. A library list that cannot be read is recorded in the environment, so
/// an audit with it is partial rather than blind.
#[must_use]
pub fn environment() -> Environment {
    let found = libraries::discover(
        steam_install().as_deref(),
        libraries::epic_manifests().as_deref(),
    );
    let mut environment = Environment::new();
    for &name in KNOWN_VARIABLES {
        let launcher = match name {
            "STEAM_LIBRARY" => Some(Launcher::Steam),
            "EPIC_LIBRARY" => Some(Launcher::Epic),
            _ => None,
        };
        let values: Vec<String> = match launcher {
            Some(launcher) => found
                .libraries
                .iter()
                .filter(|library| library.launcher == launcher)
                .map(|library| library.path.clone())
                .collect(),
            None => std::env::var_os(name)
                .map(|value| value.to_string_lossy().into_owned())
                .into_iter()
                .collect(),
        };
        environment = environment.with(name, values);
    }
    for manifest in &found.unreadable {
        environment = environment.with_unreadable(&manifest.path, &manifest.reason);
    }
    environment
}

/// Steam's own directory, the one holding `steamapps\libraryfolders.vdf`.
///
/// The machine-wide `InstallPath` first, from the 32-bit view the installer
/// writes, then the per-user `SteamPath`. `None` when neither names a
/// directory that exists.
#[must_use]
pub fn steam_install() -> Option<PathBuf> {
    [
        (
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Valve\\Steam",
            "InstallPath",
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6432KEY,
        ),
        (
            HKEY_CURRENT_USER,
            "Software\\Valve\\Steam",
            "SteamPath",
            RRF_RT_REG_SZ,
        ),
    ]
    .into_iter()
    .filter_map(|(root, key, value, flags)| read_string(root, key, value, flags))
    // `SteamPath` is written with forward slashes.
    .map(|text| PathBuf::from(text.replace('/', "\\")))
    .find(|path| path.is_dir())
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// A Win32 error in the report's words.
fn describe(error: WIN32_ERROR) -> String {
    if error == ERROR_ACCESS_DENIED {
        "access denied".to_owned()
    } else {
        format!("Win32 error {}", error.0)
    }
}

fn absent_or_unreadable<T>(error: WIN32_ERROR) -> Lookup<T> {
    if error == ERROR_FILE_NOT_FOUND {
        Lookup::Absent
    } else {
        Lookup::Unreadable(describe(error))
    }
}

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

fn open(root: HKEY, path: &str, view: REG_SAM_FLAGS) -> Result<Key, WIN32_ERROR> {
    let path = wide(path);
    let mut key = HKEY::default();
    // SAFETY: `path` is NUL-terminated and outlives the call. KEY_READ plus the
    // view flag is read-only; the call writes the opened handle into `key` and
    // nothing else.
    let status = unsafe {
        RegOpenKeyExW(
            root,
            PCWSTR(path.as_ptr()),
            Some(0),
            KEY_READ | view,
            &raw mut key,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(Key(key))
    } else {
        Err(status)
    }
}

/// The names of a key's subkeys, or the error that stopped the listing.
fn subkeys(key: &Key) -> Result<Vec<String>, WIN32_ERROR> {
    let mut names = Vec::new();
    // 256 is the registry's limit on a key name, terminator included.
    let mut buffer = [0_u16; 256];
    let mut index = 0_u32;
    loop {
        let mut length = u32::try_from(buffer.len()).unwrap_or(0);
        // SAFETY: `buffer` holds `length` units, the count the call is given;
        // it writes no more and sets `length` to the units written.
        let status = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                Some(PWSTR(buffer.as_mut_ptr())),
                &raw mut length,
                None,
                None,
                None,
                None,
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            return Ok(names);
        }
        if status != ERROR_SUCCESS {
            return Err(status);
        }
        let end = (length as usize).min(buffer.len());
        names.push(String::from_utf16_lossy(&buffer[..end]));
        index += 1;
    }
}

fn read_service_key(key: &Key, name: &str) -> ServiceKey {
    ServiceKey {
        name: name.to_owned(),
        // As written: `%SystemRoot%` stays for the engine to expand.
        image: read_string(
            key.0,
            "",
            "ImagePath",
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
        )
        .unwrap_or_default(),
        service_type: read_dword(key.0, "Type").unwrap_or(0),
    }
}

fn read_string(root: HKEY, key: &str, value: &str, flags: REG_ROUTINE_FLAGS) -> Option<String> {
    let key = wide(key);
    let value = wide(value);
    let mut bytes = 0_u32;
    // SAFETY: both names are NUL-terminated buffers that outlive the call, and
    // with no data buffer the call only writes the size it needs.
    let sized = unsafe {
        RegGetValueW(
            root,
            PCWSTR(key.as_ptr()),
            PCWSTR(value.as_ptr()),
            flags,
            None,
            None,
            Some(&raw mut bytes),
        )
    };
    if sized != ERROR_SUCCESS || bytes == 0 {
        return None;
    }
    let mut buffer = vec![0_u16; (bytes as usize).div_ceil(2)];
    // SAFETY: `buffer` holds at least `bytes` bytes, and `bytes` tells the call
    // so; it writes no more than that and updates the count.
    let read = unsafe {
        RegGetValueW(
            root,
            PCWSTR(key.as_ptr()),
            PCWSTR(value.as_ptr()),
            flags,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&raw mut bytes),
        )
    };
    if read != ERROR_SUCCESS {
        return None;
    }
    let units = (bytes as usize / 2).min(buffer.len());
    let text = String::from_utf16_lossy(&buffer[..units]);
    let text = text.trim_end_matches('\0').trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn read_dword(key: HKEY, value: &str) -> Option<u32> {
    let value = wide(value);
    let mut data = 0_u32;
    let mut bytes = u32::try_from(size_of::<u32>()).unwrap_or(0);
    // SAFETY: `data` is a DWORD and `bytes` says so; the value name is
    // NUL-terminated and outlives the call, and a null subkey reads `key`.
    let status = unsafe {
        RegGetValueW(
            key,
            PCWSTR::null(),
            PCWSTR(value.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some((&raw mut data).cast()),
            Some(&raw mut bytes),
        )
    };
    (status == ERROR_SUCCESS).then_some(data)
}

/// An `SC_HANDLE` that closes itself.
struct Service(SC_HANDLE);

impl Drop for Service {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: a handle this type owns and has not closed.
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

fn query_service(name: &str) -> Lookup<ServiceStatus> {
    // SAFETY: null machine and database names mean this machine's active
    // database; SC_MANAGER_CONNECT permits opening a service and nothing that
    // changes one.
    let connected = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) };
    let manager = match connected {
        Ok(handle) => Service(handle),
        Err(error) => {
            return Lookup::Unreadable(format!("the service control manager: {error}"));
        }
    };
    let name_wide = wide(name);
    // SAFETY: `name_wide` is NUL-terminated and outlives the call;
    // SERVICE_QUERY_CONFIG is read-only.
    let opened =
        unsafe { OpenServiceW(manager.0, PCWSTR(name_wide.as_ptr()), SERVICE_QUERY_CONFIG) };
    let service = match opened {
        Ok(handle) => Service(handle),
        Err(error) if error.code() == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult() => {
            return Lookup::Absent;
        }
        Err(error) if error.code() == ERROR_ACCESS_DENIED.to_hresult() => {
            return Lookup::Unreadable("access denied".to_owned());
        }
        Err(error) => return Lookup::Unreadable(error.to_string()),
    };
    let mut needed = 0_u32;
    // SAFETY: a null buffer asks for the size the configuration needs.
    let probe = unsafe { QueryServiceConfigW(service.0, None, 0, &raw mut needed) };
    if let Err(error) = probe {
        // SCM opened a service whose key is gone: what EA's uninstaller leaves
        // until the next boot, every query failing with "file not found".
        if error.code() == ERROR_FILE_NOT_FOUND.to_hresult() {
            return Lookup::Found(ServiceStatus {
                image: String::new(),
                stale: true,
            });
        }
        if error.code() != ERROR_INSUFFICIENT_BUFFER.to_hresult()
            && error.code() != ERROR_MORE_DATA.to_hresult()
        {
            return Lookup::Unreadable(error.to_string());
        }
    }
    // u64 elements keep the buffer aligned for QUERY_SERVICE_CONFIGW, which
    // holds pointers.
    let mut buffer = vec![0_u64; (needed as usize).div_ceil(size_of::<u64>()).max(1)];
    // SAFETY: the buffer is at least `needed` bytes, which is what the call is
    // told; it writes the structure at the head and its strings after it.
    let read = unsafe {
        QueryServiceConfigW(
            service.0,
            Some(buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>()),
            needed,
            &raw mut needed,
        )
    };
    if let Err(error) = read {
        return Lookup::Unreadable(error.to_string());
    }
    // SAFETY: the call above populated the structure at the buffer's head, and
    // its string pointers point into the same buffer, which is still alive.
    let image = unsafe {
        let config = &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        if config.lpBinaryPathName.is_null() {
            String::new()
        } else {
            config.lpBinaryPathName.to_string().unwrap_or_default()
        }
    };
    Lookup::Found(ServiceStatus {
        image,
        stale: false,
    })
}

/// A file's Authenticode signature, verified without the network.
///
/// A verification that fails for a reason other than the signature is tried
/// once more before it is reported unknown: on 2026-10-09 a disk saturated by
/// a snapshot failed two of EA AntiCheat's signed files, and both verified
/// with the disk idle (`docs/05`).
#[must_use]
pub fn signature(path: &Path) -> Signature {
    match verify(path) {
        Signature::Unknown(_) => verify(path),
        settled => settled,
    }
}

fn verify(path: &Path) -> Signature {
    // What WinVerifyTrust returns, as the bit patterns of its HRESULTs.
    const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;
    const CERT_E_EXPIRED: u32 = 0x800B_0101;
    // Why there is no signature, when the result is TRUST_E_NOSIGNATURE. Any
    // other reason there — the file could not be opened — is an error.
    const NOT_SIGNED: [u32; 3] = [
        TRUST_E_NOSIGNATURE,
        0x800B_0003, // TRUST_E_SUBJECT_FORM_UNKNOWN
        0x800B_0001, // TRUST_E_PROVIDER_UNKNOWN
    ];
    // A revocation this machine's cache cannot answer.
    const NOT_KNOWN_OFFLINE: [u32; 3] = [
        0x800B_010E, // CERT_E_REVOCATION_FAILURE
        0x8009_2012, // CRYPT_E_NO_REVOCATION_CHECK
        0x8009_2013, // CRYPT_E_REVOCATION_OFFLINE
    ];
    // A signature that is there and does not verify. A chain that cannot be
    // built (CERT_E_CHAINING) is not among them: offline, that is an error.
    const INVALID: [u32; 8] = [
        0x8009_6010, // TRUST_E_BAD_DIGEST
        0x8009_6004, // TRUST_E_CERT_SIGNATURE
        0x800B_0004, // TRUST_E_SUBJECT_NOT_TRUSTED
        0x800B_0109, // CERT_E_UNTRUSTEDROOT
        0x800B_010C, // CERT_E_REVOKED
        0x8009_2010, // CRYPT_E_REVOKED
        0x800B_0110, // CERT_E_WRONG_USAGE
        0x800B_0111, // TRUST_E_EXPLICIT_DISTRUST
    ];

    let path_wide = wide_path(path);
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: u32::try_from(size_of::<WINTRUST_FILE_INFO>()).unwrap_or(0),
        pcwszFilePath: PCWSTR(path_wide.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: u32::try_from(size_of::<WINTRUST_DATA>()).unwrap_or(0),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &raw mut file,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..WINTRUST_DATA::default()
    };
    let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data` and `file` describe one file by a NUL-terminated path that
    // outlives both calls; WTD_UI_NONE shows nothing, and the second call
    // releases the state the first allocated. The last error is read before
    // anything else can change it.
    let (result, last_error) = unsafe {
        let result = WinVerifyTrust(HWND::default(), &raw mut action, (&raw mut data).cast());
        let last_error = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(HWND::default(), &raw mut action, (&raw mut data).cast());
        (result, last_error)
    };
    let code = result.cast_unsigned();
    if code == 0 || code == CERT_E_EXPIRED || NOT_KNOWN_OFFLINE.contains(&code) {
        return signer_name(path).map_or_else(
            || Signature::Unknown("it verifies, and its signer could not be read".to_owned()),
            Signature::Verified,
        );
    }
    if code == TRUST_E_NOSIGNATURE {
        let reason = last_error.cast_unsigned();
        return if NOT_SIGNED.contains(&reason) {
            Signature::Unsigned
        } else {
            Signature::Unknown(format!("no signature could be read, error {reason:#010x}"))
        };
    }
    if INVALID.contains(&code) {
        return Signature::Invalid;
    }
    Signature::Unknown(format!("WinVerifyTrust returned {code:#010x}"))
}

/// The subject common name of the certificate that signed a file, read from
/// its **embedded** signature without verifying it.
///
/// `None` for anything without an embedded signature, and for any step of the
/// extraction that does not work. Most Windows binaries are signed through a
/// catalog file instead, which this does not follow; anti-cheat binaries are
/// embedded-signed in practice. The observation harness records this name as
/// evidence; [`signature`] asks for it only once the signature verified.
#[must_use]
pub fn signer_name(path: &Path) -> Option<String> {
    let wide = wide_path(path);
    let mut store = HCERTSTORE::default();
    let mut message: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut encoding = CERT_QUERY_ENCODING_TYPE::default();

    // SAFETY: `wide` is a NUL-terminated path that outlives the call. The
    // store and message handles become ours, and both are released below on
    // every path out of this function.
    let queried = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide.as_ptr().cast(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            Some(&raw mut encoding),
            None,
            None,
            Some(&raw mut store),
            Some(&raw mut message),
            None,
        )
    };
    if queried.is_err() {
        // No embedded signature: the most common outcome on Windows, and a
        // fact about the file rather than a failure.
        return None;
    }

    let name = signer_of_message(store, message, encoding);

    // SAFETY: releasing exactly what CryptQueryObject produced, once each.
    unsafe {
        if !message.is_null() {
            let _ = CryptMsgClose(Some(message));
        }
        if !store.is_invalid() {
            let _ = CertCloseStore(Some(store), 0);
        }
    }

    name
}

fn signer_of_message(
    store: HCERTSTORE,
    message: *mut core::ffi::c_void,
    encoding: CERT_QUERY_ENCODING_TYPE,
) -> Option<String> {
    let mut needed = 0_u32;
    // SAFETY: a null buffer asks for the size of the first signer's record.
    let sized =
        unsafe { CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, None, &raw mut needed) };
    if sized.is_err() || needed == 0 {
        return None;
    }

    // u64-backed so the allocation is aligned for CMSG_SIGNER_INFO, which
    // holds pointers.
    let mut buffer = vec![0_u64; (needed as usize).div_ceil(size_of::<u64>()).max(1)];
    // SAFETY: the buffer is at least `needed` bytes, as the call is told.
    let read = unsafe {
        CryptMsgGetParam(
            message,
            CMSG_SIGNER_INFO_PARAM,
            0,
            Some(buffer.as_mut_ptr().cast()),
            &raw mut needed,
        )
    };
    if read.is_err() {
        return None;
    }

    // SAFETY: the call above wrote a CMSG_SIGNER_INFO at the head of the
    // buffer, with its issuer and serial number pointing into the same
    // allocation, which outlives the search below.
    let signer = unsafe { &*buffer.as_ptr().cast::<CMSG_SIGNER_INFO>() };

    // A signer is identified by issuer and serial number, which is what
    // CERT_INFO carries and what the store is searched by.
    let criteria = CERT_INFO {
        Issuer: signer.Issuer,
        SerialNumber: signer.SerialNumber,
        ..Default::default()
    };

    // SAFETY: `criteria` and `buffer` both outlive the call; the context it
    // returns is freed below.
    let context: *mut CERT_CONTEXT = unsafe {
        CertFindCertificateInStore(
            store,
            encoding,
            0,
            CERT_FIND_SUBJECT_CERT,
            Some((&raw const criteria).cast()),
            None,
        )
    };
    if context.is_null() {
        return None;
    }

    let name = subject_name(context);

    // SAFETY: freeing exactly the context just obtained, once.
    unsafe {
        let _ = CertFreeCertificateContext(Some(context.cast_const()));
    }

    name.filter(|value| !value.is_empty())
}

/// The certificate's simple display name, which for a code-signing
/// certificate is the publisher.
fn subject_name(context: *mut CERT_CONTEXT) -> Option<String> {
    // SAFETY: `context` is a live certificate context; a null buffer asks for
    // the length in characters, terminator included.
    let length = unsafe {
        CertGetNameStringW(
            context.cast_const(),
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            None,
        )
    };
    if length <= 1 {
        return None;
    }

    let mut text = vec![0_u16; length as usize];
    // SAFETY: `text` is exactly the length the sizing call reported.
    unsafe {
        CertGetNameStringW(
            context.cast_const(),
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(text.as_mut_slice()),
        );
    }
    let end = text
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(text.len());
    Some(String::from_utf16_lossy(&text[..end]))
}
