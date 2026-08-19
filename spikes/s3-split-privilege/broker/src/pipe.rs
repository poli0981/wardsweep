//! The named pipe: creation with an explicit DACL, client acceptance, and the
//! framed transport.
//!
//! `docs/08-IPC-PROTOCOL.md` specifies the pipe as message mode, one client,
//! `PIPE_REJECT_REMOTE_CLIENTS`, and a DACL of SYSTEM + Administrators + the
//! launching user, with no `Everyone`. All of that is built here and then read
//! back off the live handle, because a DACL that was *intended* is not
//! evidence — S3 criterion 3a is the readback, not the construction.

use anyhow::{Context, Result, anyhow, bail};
use windows::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_MORE_DATA, ERROR_NO_DATA, ERROR_PIPE_CONNECTED, GetLastError, HANDLE,
    HLOCAL, INVALID_HANDLE_VALUE, LocalFree, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
use windows::core::{PCWSTR, PWSTR};

use crate::proto::{Envelope, FrameError, check_len, decode, encode};
use crate::win::{OwnedHandle, to_wide};

/// SDDL revision accepted by the conversion APIs.
const SDDL_REVISION_1: u32 = 1;

/// `docs/08-IPC-PROTOCOL.md` names the real pipe. The spike keeps its own
/// prefix so a stray spike process can never be mistaken for a real broker.
#[must_use]
pub fn pipe_name(session: &str) -> String {
    format!("\\\\.\\pipe\\wardsweep-s3-{session}")
}

/// The DACL the broker asks for, in SDDL.
///
/// - `D:P` — protected, so nothing is inherited in from the parent
/// - `(A;;GA;;;SY)` — SYSTEM, full
/// - `(A;;GA;;;BA)` — Administrators, full
/// - `(A;;GRGW;;;<user>)` — the launching user, read and write only
///
/// `GW` on a pipe expands to `FILE_GENERIC_WRITE`, which includes
/// `FILE_WRITE_ATTRIBUTES`. The client needs that: .NET's
/// `NamedPipeClientStream` calls `SetNamedPipeHandleState` to select message
/// read mode, and that call fails without it. Granting `GR` alone produces a
/// client that connects and then dies on its first read.
#[must_use]
pub fn requested_sddl(user_sid: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{user_sid})")
}

/// The same DACL as it comes *back* off the object.
///
/// The kernel does not store generic rights. `GENERIC_ALL` is mapped through
/// the object type's generic mapping at creation and stored as the specific
/// set, so a file-object ACE asking for `GA` reads back as `FA`
/// (`FILE_ALL_ACCESS`) and `GRGW` reads back as `0x12019F` —
/// `FILE_GENERIC_READ | FILE_GENERIC_WRITE`.
///
/// This matters more than it looks. An implementation that verifies its own
/// DACL by string-comparing the readback against the string it passed in will
/// find they never match, and the two ways out of that are both wrong: weaken
/// the check until it passes, or conclude the descriptor was not applied. The
/// assertion has to be made against the canonical form.
#[must_use]
pub fn canonical_sddl(user_sid: &str) -> String {
    format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019f;;;{user_sid})")
}

/// What the DACL on the live pipe actually says.
#[derive(Debug, Clone)]
pub struct DaclVerdict {
    /// The descriptor read back off the handle.
    pub observed: String,
    /// The canonical form the observed value is expected to equal.
    pub expected: String,
    pub matches_expected: bool,
    /// `D:P` — the DACL is protected, so nothing is inherited in.
    pub protected: bool,
    /// An ACE for `Everyone` (`WD`), which `docs/08` forbids.
    pub grants_everyone: bool,
    /// An ACE for `Authenticated Users` (`AU`) — every logged-on account.
    pub grants_authenticated_users: bool,
    /// An ACE naming the launching user.
    pub grants_launching_user: bool,
}

impl DaclVerdict {
    /// Whether the DACL is acceptable, on the substance rather than the spelling.
    #[must_use]
    pub fn acceptable(&self) -> bool {
        self.matches_expected
            && self.protected
            && !self.grants_everyone
            && !self.grants_authenticated_users
            && self.grants_launching_user
    }
}

/// Assess an observed SDDL against what `docs/08-IPC-PROTOCOL.md` requires.
#[must_use]
pub fn assess_dacl(observed: &str, user_sid: &str) -> DaclVerdict {
    let expected = canonical_sddl(user_sid);
    DaclVerdict {
        matches_expected: observed.eq_ignore_ascii_case(&expected),
        protected: observed.starts_with("D:P"),
        // The trailing `)` matters: `;;;WD)` cannot match a SID that merely
        // starts with those characters.
        grants_everyone: observed.contains(";;;WD)"),
        grants_authenticated_users: observed.contains(";;;AU)"),
        grants_launching_user: observed.contains(&format!(";;;{user_sid})")),
        observed: observed.to_owned(),
        expected,
    }
}

/// A created pipe instance, and what was observed about it at creation.
pub struct Pipe {
    handle: OwnedHandle,
    /// The DACL read back off the live handle, not the one that was requested.
    pub observed_sddl: String,
    pub name: String,
}

/// Create the pipe instance.
///
/// `FILE_FLAG_FIRST_PIPE_INSTANCE` is not optional. Without it a second process
/// that guesses the name creates another *instance* of the same pipe and
/// silently takes the next connection; with it, a name already in use is a hard
/// failure at startup. That is what closes the squatting window during the
/// unelevated-to-elevated handover, where the name is briefly unowned.
///
/// # Errors
/// If the security descriptor cannot be built, or the pipe cannot be created —
/// including because the name is already taken, which is a meaningful failure
/// rather than a bug.
pub fn create(session: &str, user_sid: &str) -> Result<Pipe> {
    let name = pipe_name(session);
    let sddl = requested_sddl(user_sid);

    let sddl_wide = to_wide(&sddl);
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: sddl_wide is a NUL-terminated wide string that outlives the call.
    // The descriptor is allocated by the API and freed with LocalFree below.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_wide.as_ptr()),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
        .with_context(|| format!("ConvertStringSecurityDescriptorToSecurityDescriptorW({sddl})"))?;
    }

    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())?,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };

    let name_wide = to_wide(&name);
    // SAFETY: name_wide and attributes both outlive the call. nMaxInstances is
    // 1 because docs/08 specifies one client: a second connect must be refused,
    // not queued, and the instance count is what enforces that in the kernel
    // rather than in our accept loop.
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(name_wide.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            64 * 1024,
            64 * 1024,
            0,
            Some(&raw const attributes),
        )
    };

    let created_error = if handle == INVALID_HANDLE_VALUE {
        // SAFETY: reading the calling thread's last error immediately after the
        // failed call, with nothing in between that could overwrite it.
        Some(unsafe { GetLastError() })
    } else {
        None
    };

    // SAFETY: freeing exactly what the conversion allocated, once, after
    // CreateNamedPipeW has copied what it needs out of it.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }

    if let Some(error) = created_error {
        bail!(
            "CreateNamedPipeW({name}) failed with Win32 error {}. ERROR_ACCESS_DENIED (5) here \
             means the name is already held by another instance and FILE_FLAG_FIRST_PIPE_INSTANCE \
             refused to join it.",
            error.0
        );
    }

    let handle = OwnedHandle(handle);
    let observed_sddl = read_dacl(handle.0)?;

    Ok(Pipe {
        handle,
        observed_sddl,
        name,
    })
}

/// Read the DACL back off a live handle and render it as SDDL.
///
/// # Errors
/// If `GetSecurityInfo` fails or the descriptor cannot be rendered.
fn read_dacl(handle: HANDLE) -> Result<String> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: handle is a live kernel object. The descriptor out-parameter is
    // allocated by the API and freed with LocalFree below.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&raw mut descriptor),
        )
    };
    if status != WIN32_ERROR(0) {
        bail!("GetSecurityInfo failed with Win32 error {}", status.0);
    }

    let mut text = PWSTR::null();
    // SAFETY: descriptor is what GetSecurityInfo just allocated. The string is
    // allocated by the API and freed below.
    let rendered = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &raw mut text,
            None,
        )
    };

    let result = if rendered.is_ok() {
        // SAFETY: text is a NUL-terminated wide string owned by the caller.
        unsafe { text.to_string() }.map_err(|e| anyhow!("SDDL was not valid UTF-16: {e}"))
    } else {
        Err(anyhow!(
            "ConvertSecurityDescriptorToStringSecurityDescriptorW failed"
        ))
    };

    // SAFETY: freeing each allocation exactly once. A null PWSTR is not freed.
    unsafe {
        if !text.is_null() {
            let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        }
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }

    result
}

impl Pipe {
    /// Block until a client connects.
    ///
    /// # Errors
    /// If `ConnectNamedPipe` fails for any reason other than the client having
    /// already connected in the window before the call.
    pub fn accept(&self) -> Result<()> {
        // SAFETY: the handle is live and this is a synchronous (non-overlapped)
        // pipe, so a null OVERLAPPED is correct.
        let connected = unsafe { ConnectNamedPipe(self.handle.0, None) };
        match connected {
            Ok(()) => Ok(()),
            Err(e) if win32_code(&e) == ERROR_PIPE_CONNECTED.0 => {
                // The client won the race between CreateNamedPipeW and
                // ConnectNamedPipe. This is success, and treating it as failure
                // is a classic named-pipe bug.
                Ok(())
            }
            Err(e) => Err(anyhow!("ConnectNamedPipe failed: {e}")),
        }
    }

    /// Release the current client so the next `accept` can take another.
    pub fn disconnect(&self) {
        // SAFETY: the handle is live. A failure here is not actionable — the
        // next accept reports the real problem.
        unsafe {
            let _ = DisconnectNamedPipe(self.handle.0);
        }
    }

    /// The process id at the other end.
    ///
    /// # Errors
    /// If the pipe has no client, or the call fails.
    pub fn client_process_id(&self) -> Result<u32> {
        let mut pid = 0u32;
        // SAFETY: the handle is a live server-end pipe with a client attached.
        unsafe {
            GetNamedPipeClientProcessId(self.handle.0, &raw mut pid)
                .context("GetNamedPipeClientProcessId")?;
        }
        Ok(pid)
    }

    /// Read one message and parse it as an envelope.
    ///
    /// # Errors
    /// [`FrameError::Closed`] when the client went away between frames, which
    /// is normal, and [`FrameError::Broken`] when it went away mid-frame.
    pub fn read_frame(&self) -> Result<Envelope, FrameError> {
        let mut message = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];

        loop {
            let mut read = 0u32;
            // SAFETY: chunk is a live buffer and read is a valid out-parameter.
            let outcome = unsafe {
                ReadFile(
                    self.handle.0,
                    Some(chunk.as_mut_slice()),
                    Some(&raw mut read),
                    None,
                )
            };

            match outcome {
                Ok(()) => {
                    message.extend_from_slice(&chunk[..read as usize]);
                    break;
                }
                Err(e) => {
                    let code = win32_code(&e);
                    if code == ERROR_MORE_DATA.0 {
                        // Message mode: this message is longer than the buffer.
                        // Keep reading; it is a continuation of the same one.
                        message.extend_from_slice(&chunk[..read as usize]);
                        if message.len() > crate::proto::MAX_FRAME {
                            return Err(FrameError::TooLarge(u32::MAX));
                        }
                        continue;
                    }
                    if code == ERROR_BROKEN_PIPE.0 || code == ERROR_NO_DATA.0 {
                        return Err(FrameError::Closed);
                    }
                    return Err(FrameError::Broken(std::io::Error::other(e)));
                }
            }
        }

        if message.is_empty() {
            return Err(FrameError::Closed);
        }
        if message.len() < 4 {
            return Err(FrameError::Malformed(format!(
                "{} byte message cannot hold a length prefix",
                message.len()
            )));
        }

        let declared = u32::from_le_bytes([message[0], message[1], message[2], message[3]]);
        let declared = check_len(declared)?;
        let body = &message[4..];
        if body.len() != declared {
            return Err(FrameError::Malformed(format!(
                "length prefix says {declared} bytes, message carried {}",
                body.len()
            )));
        }

        decode(body)
    }

    /// Write one envelope as a single message.
    ///
    /// Returns `Ok(false)` when the client has gone — which is not an error.
    /// `docs/08-IPC-PROTOCOL.md`: "If the pipe drops mid-job the broker
    /// **continues**." Detecting that here and carrying on is the whole of S3
    /// criterion 5 on the broker side.
    ///
    /// # Errors
    /// If the envelope cannot be encoded, or the write failed for a reason
    /// other than the client having disconnected.
    pub fn write_frame(&self, envelope: &Envelope) -> Result<bool> {
        let frame = encode(envelope).map_err(|e| anyhow!("{e}"))?;
        let mut written = 0u32;
        // SAFETY: frame outlives the call and written is a valid out-parameter.
        let outcome = unsafe {
            WriteFile(
                self.handle.0,
                Some(frame.as_slice()),
                Some(&raw mut written),
                None,
            )
        };

        match outcome {
            Ok(()) if written as usize == frame.len() => Ok(true),
            Ok(()) => bail!("short write: {written} of {} bytes", frame.len()),
            Err(e) => {
                let code = win32_code(&e);
                if code == ERROR_BROKEN_PIPE.0 || code == ERROR_NO_DATA.0 {
                    Ok(false)
                } else {
                    Err(anyhow!("WriteFile failed: {e}"))
                }
            }
        }
    }

    /// The raw handle. Used only by the duplex probe in `main`.
    #[must_use]
    pub fn raw(&self) -> HANDLE {
        self.handle.0
    }
}

/// Recover the Win32 error code from an `HRESULT`-wrapped error.
///
/// `windows::core::Error` reports `HRESULT_FROM_WIN32`, so the low 16 bits are
/// the original code. Comparing the `HRESULT` directly against `ERROR_*` is a
/// common way to write a comparison that is always false.
fn win32_code(error: &windows::core::Error) -> u32 {
    error.code().0 as u32 & 0xFFFF
}

#[cfg(test)]
mod tests {
    use super::{assess_dacl, canonical_sddl};

    const SID: &str = "S-1-5-21-1-2-3-1001";

    #[test]
    fn the_canonical_form_of_the_requested_dacl_is_accepted() {
        // Exactly what the kernel handed back during the spike run: GA became
        // FA, and GRGW became FILE_GENERIC_READ | FILE_GENERIC_WRITE.
        let verdict = assess_dacl(&canonical_sddl(SID), SID);
        assert!(verdict.acceptable(), "{verdict:?}");
        assert!(verdict.matches_expected);
        assert!(verdict.protected);
    }

    #[test]
    fn the_requested_form_does_not_match_the_readback() {
        // The trap this whole function exists for. Comparing the readback
        // against the string that was passed in never matches, and neither
        // obvious reaction to that is correct.
        let verdict = assess_dacl(&super::requested_sddl(SID), SID);
        assert!(!verdict.matches_expected);
    }

    #[test]
    fn an_everyone_ace_is_not_acceptable() {
        let widened = format!("{}(A;;GRGW;;;WD)", canonical_sddl(SID));
        let verdict = assess_dacl(&widened, SID);
        assert!(verdict.grants_everyone);
        assert!(!verdict.acceptable());
    }

    #[test]
    fn an_authenticated_users_ace_is_not_acceptable() {
        let widened = format!("{}(A;;GRGW;;;AU)", canonical_sddl(SID));
        let verdict = assess_dacl(&widened, SID);
        assert!(verdict.grants_authenticated_users);
        assert!(!verdict.acceptable());
    }

    #[test]
    fn an_unprotected_dacl_is_not_acceptable() {
        // Without D:P the object inherits ACEs from wherever it is created,
        // which is exactly the surprise an explicit descriptor exists to avoid.
        let inherited = canonical_sddl(SID).replacen("D:P", "D:", 1);
        let verdict = assess_dacl(&inherited, SID);
        assert!(!verdict.protected);
        assert!(!verdict.acceptable());
    }

    #[test]
    fn a_dacl_without_the_launching_user_is_not_acceptable() {
        let verdict = assess_dacl(&canonical_sddl("S-1-5-21-9-9-9-9999"), SID);
        assert!(!verdict.grants_launching_user);
        assert!(!verdict.acceptable());
    }
}
