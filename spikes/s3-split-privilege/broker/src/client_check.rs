//! Client identity verification.
//!
//! `docs/08-IPC-PROTOCOL.md`: "Broker calls `GetNamedPipeClientProcessId`,
//! resolves the image path, and verifies it matches the expected UI binary —
//! same directory as the broker, expected filename, and the session GUID it was
//! launched with — before accepting any command."
//!
//! This is the check that actually defends. The pipe DACL grants the launching
//! user, so *any* process that user runs passes the DACL; what stops a hostile
//! process is that its image is not the UI.
//!
//! Two things about the specified check are worth settling here rather than in
//! the real broker:
//!
//! 1. **TOCTOU.** A process id is only unique while the process lives. Between
//!    `GetNamedPipeClientProcessId` and `OpenProcess` the client can exit and
//!    the id be reused, so the image path resolved may belong to a different
//!    process. The mitigation is to capture the creation time and re-check it
//!    after the handle is open — if the process we opened started after we were
//!    told the id, it is not the process that connected.
//! 2. **The session GUID clause.** Verifying "the session GUID it was launched
//!    with" against the *client's command line* would need
//!    `NtQueryInformationProcess` or WMI. It buys nothing: the client already
//!    proved it knows the GUID by connecting to an unpredictable pipe name, and
//!    it echoes the GUID in `Hello` where it can be compared for free.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use windows::Win32::Foundation::{FILETIME, HANDLE};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

use crate::win::{OwnedHandle, wide_to_string};

/// What was learned about the process at the other end of the pipe.
#[derive(Debug, Clone)]
pub struct ClientIdentity {
    pub pid: u32,
    pub image_path: String,
    /// Process creation time, as Windows epoch ticks. Used only for the TOCTOU
    /// re-check, never as an identifier of the machine.
    pub created_ticks: u64,
}

/// Why a client was refused.
#[derive(Debug, Clone)]
pub enum Refusal {
    /// The image lives somewhere other than the broker's own directory.
    WrongDirectory { expected: String, actual: String },
    /// The image has the wrong file name.
    WrongFileName { expected: String, actual: String },
    /// The `Hello` did not carry the session GUID the broker was launched with.
    WrongSession { expected: String, actual: String },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongDirectory { expected, actual } => write!(
                f,
                "client image is in {actual}, expected the broker's own directory {expected}"
            ),
            Self::WrongFileName { expected, actual } => {
                write!(f, "client image is {actual}, expected {expected}")
            }
            Self::WrongSession { expected, actual } => {
                write!(f, "Hello carried session {actual}, expected {expected}")
            }
        }
    }
}

/// Resolve the identity of the process holding the client end.
///
/// # Errors
/// If the process cannot be opened or its image path cannot be read. A client
/// that exits between the two calls produces an error here, which is the
/// correct outcome: refuse, do not guess.
pub fn identify(pid: u32) -> Result<ClientIdentity> {
    // PROCESS_QUERY_LIMITED_INFORMATION is deliberately the weakest right that
    // answers the question. It works across integrity levels and does not grant
    // reading the process's memory, which the broker has no business doing.
    // SAFETY: pid is what the kernel just reported as the client.
    let process = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .with_context(|| format!("OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, {pid})"))?
    };
    let process = OwnedHandle(process);

    let mut buffer = [0u16; 32768];
    let mut size = u32::try_from(buffer.len())?;
    // SAFETY: buffer is live for the call and size is its true length in
    // characters, which is what the API expects.
    unsafe {
        QueryFullProcessImageNameW(
            process.0,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &raw mut size,
        )
        .context("QueryFullProcessImageNameW")?;
    }

    Ok(ClientIdentity {
        pid,
        image_path: wide_to_string(&buffer),
        created_ticks: creation_ticks(process.0)?,
    })
}

/// Process creation time in Windows epoch ticks.
fn creation_ticks(process: HANDLE) -> Result<u64> {
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all four out-parameters are live FILETIME values.
    unsafe {
        GetProcessTimes(
            process,
            &raw mut created,
            &raw mut exited,
            &raw mut kernel,
            &raw mut user,
        )
        .context("GetProcessTimes")?;
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

/// Whether the client process was already running when we were told its id.
///
/// If it started *after* that moment, the id was recycled and the process we
/// inspected is not the one that connected.
#[must_use]
pub fn predates(identity: &ClientIdentity, observed_at: SystemTime) -> bool {
    // Windows epoch is 1601-01-01; Unix epoch is 11644473600 seconds later.
    const EPOCH_DIFFERENCE_SECONDS: u64 = 11_644_473_600;
    let Ok(since_unix) = observed_at.duration_since(UNIX_EPOCH) else {
        return false;
    };
    let observed_ticks = (since_unix.as_secs() + EPOCH_DIFFERENCE_SECONDS) * 10_000_000
        + u64::from(since_unix.subsec_nanos()) / 100;
    identity.created_ticks <= observed_ticks
}

/// Verify a client image against the broker's own location and the expected
/// file name.
///
/// # Errors
/// Never — the result is a verdict, and a refusal is an ordinary outcome. The
/// signature returns `Result` only so a malformed broker path is reportable.
pub fn verify_image(
    identity: &ClientIdentity,
    broker_image: &str,
    expected_file_name: &str,
) -> Result<Option<Refusal>> {
    let broker_directory = parent_of(broker_image)
        .with_context(|| format!("broker image path has no directory: {broker_image}"))?;
    let client_directory = match parent_of(&identity.image_path) {
        Some(directory) => directory,
        None => bail!("client image path has no directory: {}", identity.image_path),
    };

    if !equal_ignoring_case(&broker_directory, &client_directory) {
        return Ok(Some(Refusal::WrongDirectory {
            expected: broker_directory,
            actual: client_directory,
        }));
    }

    let client_file_name = file_name_of(&identity.image_path);
    if !equal_ignoring_case(client_file_name, expected_file_name) {
        return Ok(Some(Refusal::WrongFileName {
            expected: expected_file_name.to_owned(),
            actual: client_file_name.to_owned(),
        }));
    }

    Ok(None)
}

/// Verify the session GUID a client echoed in `Hello`.
#[must_use]
pub fn verify_session(claimed: &str, expected: &str) -> Option<Refusal> {
    if equal_ignoring_case(claimed, expected) {
        None
    } else {
        Some(Refusal::WrongSession {
            expected: expected.to_owned(),
            actual: claimed.to_owned(),
        })
    }
}

fn parent_of(path: &str) -> Option<String> {
    std::path::Path::new(path)
        .parent()
        .map(|parent| parent.to_string_lossy().into_owned())
}

fn file_name_of(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Windows paths compare case-insensitively.
///
/// This is ASCII-only on purpose: a full Unicode case fold would be a different
/// comparison from the one the filesystem performs, and being subtly *more*
/// permissive than Windows is the wrong direction for a security check.
fn equal_ignoring_case(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .all(|(a, b)| a.eq_ignore_ascii_case(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(image: &str) -> ClientIdentity {
        ClientIdentity {
            pid: 1234,
            image_path: image.to_owned(),
            created_ticks: 0,
        }
    }

    #[test]
    fn same_directory_and_name_is_accepted() {
        let verdict = verify_image(
            &identity("C:\\app\\S3.Ui.exe"),
            "C:\\app\\s3-broker.exe",
            "S3.Ui.exe",
        )
        .unwrap();
        assert!(verdict.is_none());
    }

    #[test]
    fn a_different_directory_is_refused() {
        let verdict = verify_image(
            &identity("C:\\elsewhere\\S3.Ui.exe"),
            "C:\\app\\s3-broker.exe",
            "S3.Ui.exe",
        )
        .unwrap();
        assert!(matches!(verdict, Some(Refusal::WrongDirectory { .. })));
    }

    #[test]
    fn a_different_file_name_in_the_same_directory_is_refused() {
        // This is the intruder: same user, same directory, wrong image.
        let verdict = verify_image(
            &identity("C:\\app\\S3.Intruder.exe"),
            "C:\\app\\s3-broker.exe",
            "S3.Ui.exe",
        )
        .unwrap();
        assert!(matches!(verdict, Some(Refusal::WrongFileName { .. })));
    }

    #[test]
    fn case_differences_in_a_windows_path_are_not_a_refusal() {
        let verdict = verify_image(
            &identity("C:\\APP\\s3.ui.EXE"),
            "C:\\app\\s3-broker.exe",
            "S3.Ui.exe",
        )
        .unwrap();
        assert!(verdict.is_none());
    }

    #[test]
    fn a_mismatched_session_guid_is_refused() {
        assert!(verify_session("not-the-guid", "the-guid").is_some());
        assert!(verify_session("THE-GUID", "the-guid").is_none());
    }
}
