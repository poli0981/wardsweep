//! ISO-8601 UTC timestamps without a date crate.
//!
//! Snapshots and diffs are read by people and committed to the repository, so
//! `2026-08-19T09:41:04.312Z` beats an epoch count. A calendar dependency would
//! have to earn its way past `cargo deny` and into `THIRD-PARTY-NOTICES.md` for
//! a job the civil-calendar conversion does in twenty lines.

use std::time::{SystemTime, UNIX_EPOCH};

/// The current time as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
#[must_use]
pub fn now_utc() -> String {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    from_unix_millis(since_epoch.as_millis())
}

/// Render Unix milliseconds as an ISO-8601 UTC timestamp.
#[must_use]
#[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
pub fn from_unix_millis(millis: u128) -> String {
    let total_seconds = (millis / 1000) as i64;
    let sub_millis = (millis % 1000) as u32;

    let days = total_seconds.div_euclid(86_400);
    let seconds_of_day = total_seconds.rem_euclid(86_400);

    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{sub_millis:03}Z")
}

/// Days since the Unix epoch to a civil (year, month, day).
///
/// Howard Hinnant's `civil_from_days`, which is exact for the whole range and
/// needs no lookup tables.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Shift the epoch to 0000-03-01, which makes the leap day the last day of
    // the year and removes every special case from the arithmetic below.
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64; // [0, 146096]
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era.cast_signed() + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153; // [0, 11], March is 0
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;

    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::from_unix_millis;

    #[test]
    fn the_epoch_renders_as_the_epoch() {
        assert_eq!(from_unix_millis(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn a_known_instant_round_trips() {
        // 2026-08-19T12:34:56.789Z
        assert_eq!(
            from_unix_millis(1_787_142_896_789),
            "2026-08-19T12:34:56.789Z"
        );
    }

    #[test]
    fn a_leap_day_is_not_off_by_one() {
        // 2024-02-29T00:00:00Z
        assert_eq!(
            from_unix_millis(1_709_164_800_000),
            "2024-02-29T00:00:00.000Z"
        );
    }
}
