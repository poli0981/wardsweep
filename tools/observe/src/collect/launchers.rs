//! Where the launchers keep their library manifests.
//!
//! The manifests themselves are read by `wardsweep_core::scan::libraries`,
//! which the scanner will share; this module only answers where they are on
//! this machine. Steam records its own directory in the registry, and the Epic
//! Games Launcher keeps its manifests under `%ProgramData%`.
//!
//! Read-only: one `RegGetValueW` per value, and no key is opened for writing.

use std::path::PathBuf;

/// Steam's own directory, the one holding `steamapps\libraryfolders.vdf`.
///
/// The machine-wide `InstallPath` first, from the 32-bit view the installer
/// writes, then the per-user `SteamPath`. `None` when neither names a
/// directory that exists.
#[must_use]
pub fn steam_install() -> Option<PathBuf> {
    win32::steam_install()
}

/// The Epic Games Launcher's `Data\Manifests` directory, whether or not it
/// exists.
#[must_use]
pub fn epic_manifests() -> Option<PathBuf> {
    std::env::var_os("ProgramData").map(|data| {
        PathBuf::from(data)
            .join("Epic")
            .join("EpicGamesLauncher")
            .join("Data")
            .join("Manifests")
    })
}

#[cfg(not(windows))]
mod win32 {
    pub fn steam_install() -> Option<std::path::PathBuf> {
        None
    }
}

#[cfg(windows)]
mod win32 {
    use std::path::PathBuf;

    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, REG_ROUTINE_FLAGS, RRF_RT_REG_SZ,
        RRF_SUBKEY_WOW6432KEY, RegGetValueW,
    };
    use windows::core::PCWSTR;

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

    fn read_string(root: HKEY, key: &str, value: &str, flags: REG_ROUTINE_FLAGS) -> Option<String> {
        let key = wide(key);
        let value = wide(value);
        let mut bytes = 0_u32;
        // SAFETY: both names are NUL-terminated buffers that outlive the call,
        // and with no data buffer the call only writes the size it needs.
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
        // SAFETY: `buffer` holds at least `bytes` bytes, and `bytes` tells the
        // call so; it writes no more than that and updates the count.
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
}
