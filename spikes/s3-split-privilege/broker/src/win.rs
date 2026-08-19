//! Small Win32 helpers shared by the rest of the spike.
//!
//! Nothing here touches SCM, the registry, or the filesystem beyond reading the
//! broker's own image path. Safety Gate G3 forbids reading a hardware
//! identifier even for reporting, so no identity of any kind is queried other
//! than the *token* user SID, which is the pipe DACL's whole purpose and is not
//! a hardware fingerprint.

use anyhow::{Context, Result, bail};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser,
};
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PWSTR;

/// A `HANDLE` that closes itself.
///
/// The spike leaks nothing on the error paths, which matters because several
/// tests deliberately drive the broker into error paths repeatedly.
pub struct OwnedHandle(pub HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: self.0 is a handle this type owns and has not closed. The
            // invalid sentinel is excluded above.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

// SAFETY: a Win32 HANDLE is a kernel object reference, valid in any thread of
// the process. The spike moves one into the job thread; nothing about the
// handle is thread-affine.
unsafe impl Send for OwnedHandle {}

/// Decode a NUL-terminated wide buffer into a `String`.
#[must_use]
pub fn wide_to_string(buffer: &[u16]) -> String {
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

/// Encode a `str` as a NUL-terminated wide buffer.
#[must_use]
pub fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Whether this process is running elevated.
///
/// This is the machine-checkable half of S3 criterion 1 ("unelevated audit
/// produces results with no UAC prompt"): the absence of a consent prompt can
/// only be observed by a human, but the resulting token can be asserted on.
///
/// # Errors
/// If the process token cannot be opened or queried.
pub fn is_elevated() -> Result<bool> {
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing.
    // OpenProcessToken writes a real handle we take ownership of below.
    let token = unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token)
            .context("OpenProcessToken(TOKEN_QUERY)")?;
        OwnedHandle(token)
    };

    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    // SAFETY: the out buffer is a TOKEN_ELEVATION and the size passed matches
    // it, which is what TokenElevation expects.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some((&raw mut elevation).cast()),
            u32::try_from(size_of::<TOKEN_ELEVATION>())?,
            &raw mut returned,
        )
        .context("GetTokenInformation(TokenElevation)")?;
    }

    Ok(elevation.TokenIsElevated != 0)
}

/// The SID of the user this process runs as, in string form.
///
/// Used to build the pipe DACL. `docs/08-IPC-PROTOCOL.md`: "SYSTEM and
/// Administrators full control, plus the launching user's SID. No Everyone."
///
/// # Errors
/// If the token cannot be queried or the SID cannot be converted.
pub fn current_user_sid() -> Result<String> {
    // SAFETY: as in is_elevated.
    let token = unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token)
            .context("OpenProcessToken(TOKEN_QUERY)")?;
        OwnedHandle(token)
    };

    // Two-call idiom: ask for the size, then allocate and ask again.
    let mut needed = 0u32;
    // SAFETY: a null buffer with size 0 is the documented way to learn the
    // required size; the call is expected to fail with ERROR_INSUFFICIENT_BUFFER.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &raw mut needed) };
    if needed == 0 {
        bail!("GetTokenInformation(TokenUser) reported a zero-byte requirement");
    }

    let mut buffer = vec![0u8; needed as usize];
    // SAFETY: buffer is `needed` bytes, which is the size the call just asked
    // for. TOKEN_USER's SID pointer points inside this buffer, so the buffer
    // must outlive the ConvertSidToStringSidW call below — it does.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            &raw mut needed,
        )
        .context("GetTokenInformation(TokenUser)")?;
    }

    // SAFETY: the buffer holds a TOKEN_USER as written by the call above.
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };

    let mut sid_string = PWSTR::null();
    // SAFETY: the SID points into `buffer`, which is still alive. The returned
    // string is allocated by the API and freed with LocalFree below.
    unsafe {
        ConvertSidToStringSidW(token_user.User.Sid, &raw mut sid_string)
            .context("ConvertSidToStringSidW")?;
    }

    // SAFETY: sid_string is a NUL-terminated wide string owned by the caller.
    let result = unsafe { sid_string.to_string() }.context("SID string was not valid UTF-16")?;
    // SAFETY: freeing exactly what ConvertSidToStringSidW allocated, once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sid_string.0.cast())));
    }

    Ok(result)
}

/// The full path of this process's own image.
///
/// The client-image check compares the connecting process against *this*
/// directory, so a broker copied elsewhere validates against its own location
/// rather than a compiled-in path.
///
/// # Errors
/// If the module file name cannot be read.
pub fn own_image_path() -> Result<String> {
    let mut buffer = [0u16; 32768];
    // SAFETY: None means "this process's executable"; the buffer length passed
    // is the true length of the array.
    let len = unsafe { GetModuleFileNameW(None, &mut buffer) };
    if len == 0 {
        bail!("GetModuleFileNameW returned 0");
    }
    Ok(wide_to_string(&buffer))
}
