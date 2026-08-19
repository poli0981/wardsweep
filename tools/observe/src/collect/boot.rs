//! Which boot the snapshot belongs to.
//!
//! # Why a snapshot needs this
//!
//! A diff compares two files and reports what changed. It cannot report *why*,
//! and one cause changes more than any other: a restart. Drivers load and
//! unload, per-user service instances are recreated with fresh suffixes, and
//! `PendingFileRenameOperations` is executed and cleared. In a diff all of that
//! looks like ordinary churn unless the reader already knows the machine
//! rebooted.
//!
//! During the Riot Vanguard observation the reader did not know. The machine
//! restarted between two snapshots, neither file said so, and a driver's
//! start-type change was attributed to the wrong cause until the uptime was
//! checked by hand. The value that would have settled it in seconds was not
//! being recorded at all.
//!
//! # Not a hardware identifier
//!
//! Safety Gate G3 forbids reading hardware identity: `MachineGuid`, the SMBIOS
//! UUID, disk serials, MAC addresses, TPM state, volume GUIDs. A boot instant
//! is none of those. It changes every time the machine starts, it is the same
//! value on every machine started at that moment, and it distinguishes nothing.
//! `GetTickCount64` takes no arguments, opens no device and returns a duration.
//!
//! # Read-only, structurally
//!
//! `GetTickCount64` has no parameters, no out-parameters and no failure mode.

use crate::model::BootSession;

/// The boot session this process is running in.
///
/// `None` where the platform cannot say — which is everywhere but Windows, and
/// is why the field is optional all the way through the model.
#[must_use]
pub fn boot_session(now_unix_ms: u128) -> Option<BootSession> {
    uptime_ms().map(|uptime| from_uptime(now_unix_ms, uptime))
}

/// Milliseconds since the machine started, when the platform can say.
///
/// The only part of this module that differs by platform. Keeping the split
/// here rather than on [`boot_session`] means [`from_uptime`] is compiled and
/// exercised everywhere instead of becoming dead code off Windows.
#[cfg(not(windows))]
const fn uptime_ms() -> Option<u64> {
    None
}

/// Milliseconds since the machine started.
#[cfg(windows)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "the Option is shared with the non-Windows arm, which has no answer"
)]
fn uptime_ms() -> Option<u64> {
    // SAFETY: `GetTickCount64` takes no arguments, writes through no pointer,
    // and is documented to always succeed. There is nothing to get wrong.
    Some(unsafe { windows::Win32::System::SystemInformation::GetTickCount64() })
}

/// Build the record from a wall-clock instant and an uptime.
///
/// Split out from the Win32 call so the arithmetic is tested on Linux, where
/// the ubuntu lint job builds this crate.
#[must_use]
fn from_uptime(now_unix_ms: u128, uptime_ms: u64) -> BootSession {
    // Saturating rather than wrapping: a clock set behind the uptime would
    // otherwise produce a boot instant in the far future and read as a reboot
    // against every other snapshot.
    let started_unix_ms = now_unix_ms.saturating_sub(u128::from(uptime_ms));
    BootSession {
        started_utc: crate::clock::from_unix_millis(started_unix_ms),
        started_unix_ms: u64::try_from(started_unix_ms).unwrap_or(u64::MAX),
        uptime_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::from_uptime;

    #[test]
    fn the_boot_instant_is_now_minus_the_uptime() {
        // 2026-08-19T13:17:49.000Z, half an hour after a boot.
        let session = from_uptime(1_787_145_469_000 + 1_800_000, 1_800_000);
        assert_eq!(session.started_utc, "2026-08-19T13:17:49.000Z");
        assert_eq!(session.uptime_ms, 1_800_000);
    }

    #[test]
    fn an_uptime_longer_than_the_epoch_does_not_wrap() {
        let session = from_uptime(1_000, u64::MAX);
        assert_eq!(session.started_unix_ms, 0);
    }
}
