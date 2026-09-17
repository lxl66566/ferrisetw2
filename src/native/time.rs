//! Implements wrappers for various Windows time structures.
use std::convert::TryInto;

use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};

/// Wrapper for [FILETIME](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime)
#[derive(Copy, Clone, Default)]
#[repr(transparent)]
pub struct FileTime(pub(crate) FILETIME);

const SECONDS_BETWEEN_1601_AND_1970: i64 = 11_644_473_600;
const NS_IN_SECOND: i64 = 1_000_000_000;
const MS_IN_SECOND: i64 = 1_000;

/// Converts a unix timestamp in nanoseconds to an `OffsetDateTime`, saturating
/// to the nearest representable instant.
///
/// Malformed events (e.g. a replayed ETL file with corrupted timestamps) must
/// not panic the conversion: it runs in the ETW callback thread, where a panic
/// would abort the whole process. With the current i64-based quads and the
/// `large-dates` range (±999,999 years) the conversion cannot actually fail,
/// so the clamp is a cheap safety net against future range changes
#[cfg(feature = "time_rs")]
fn saturating_date_time(nanos: i128) -> time::OffsetDateTime {
    /// Bounds of what `time::OffsetDateTime` can represent (`large-dates`)
    const MIN_NANOS: i128 = time::Date::MIN
        .midnight()
        .assume_utc()
        .unix_timestamp_nanos();
    const MAX_NANOS: i128 = time::Date::MAX
        .midnight()
        .assume_utc()
        .unix_timestamp_nanos()
        + 999_999_999;

    time::OffsetDateTime::from_unix_timestamp_nanos(nanos.clamp(MIN_NANOS, MAX_NANOS))
        .expect("clamped timestamp is representable")
}

/// Days between 1970-01-01 and the given (proleptic Gregorian) civil date
///
/// Howard Hinnant's `days_from_civil` algorithm
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = y - i64::from(m <= 2);
    let era = if y >= 0 {
        y
    } else {
        y - 399
    } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (m + 9) % 12; // [0, 11], March-aligned
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

impl FileTime {
    /// Converts to a unix timestamp with millisecond granularity.
    #[must_use]
    pub fn as_unix_timestamp(&self) -> i64 {
        self.as_quad() / 10_000 - (SECONDS_BETWEEN_1601_AND_1970 * MS_IN_SECOND)
    }

    /// Converts to a unix timestamp with nanosecond granularity.
    #[must_use]
    pub fn as_unix_timestamp_nanos(&self) -> i128 {
        i128::from(self.as_quad()) * 100
            - (i128::from(SECONDS_BETWEEN_1601_AND_1970) * i128::from(NS_IN_SECOND))
    }

    /// Converts to OffsetDateTime
    #[cfg(feature = "time_rs")]
    #[must_use]
    pub fn as_date_time(&self) -> time::OffsetDateTime {
        saturating_date_time(self.as_unix_timestamp_nanos())
    }

    fn as_quad(self) -> i64 {
        let mut quad = i64::from(self.0.dwHighDateTime);
        quad <<= 32;
        quad |= i64::from(self.0.dwLowDateTime);
        quad
    }

    #[cfg(any(feature = "time_rs", feature = "serde"))]
    // The i64 timestamp is split into its two DWORD halves: bit-pattern split,
    // the sign bit of the quad never matters here
    #[allow(clippy::cast_sign_loss)]
    pub(crate) fn from_quad(quad: i64) -> Self {
        let mut file_time = FileTime::default();
        file_time.0.dwHighDateTime = (quad >> 32) as u32;
        file_time.0.dwLowDateTime = (quad & 0xffff_ffff) as u32;
        file_time
    }

    pub(crate) fn from_slice(slice: [u8; size_of::<FileTime>()]) -> Self {
        // ETW user data is packed: it is not guaranteed to be aligned for a
        // FILETIME, so copy the fields one by one instead of dereferencing
        let mut file_time = FileTime::default();
        file_time.0.dwLowDateTime = u32::from_ne_bytes(slice[0..4].try_into().unwrap());
        file_time.0.dwHighDateTime = u32::from_ne_bytes(slice[4..8].try_into().unwrap());
        file_time
    }
}

#[cfg(feature = "time_rs")]
impl From<FileTime> for time::OffsetDateTime {
    fn from(file_time: FileTime) -> Self {
        file_time.as_date_time()
    }
}

#[cfg(feature = "serde")]
impl serde::ser::Serialize for FileTime {
    #[cfg(feature = "time_rs")]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_date_time().serialize(serializer)
    }

    #[cfg(not(feature = "time_rs"))]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_unix_timestamp().serialize(serializer)
    }
}

/// Wrapper for [SYSTEMTIME](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-systemtime)
#[derive(Copy, Clone, Default)]
#[repr(transparent)]
pub struct SystemTime(pub(crate) SYSTEMTIME);

impl SystemTime {
    /// Converts to the FILETIME quad value (100ns intervals since 1601-01-01)
    ///
    /// Pure arithmetic instead of an FFI call to `SystemTimeToFileTime`:
    /// this conversion runs for every converted SystemTime property, and the
    /// FFI call also had its failure silently ignored
    fn as_filetime_quad(&self) -> i64 {
        let st = &self.0;
        let days = days_from_civil(
            i64::from(st.wYear),
            i64::from(st.wMonth),
            i64::from(st.wDay),
        );
        let secs_since_1601 = (days + SECONDS_BETWEEN_1601_AND_1970 / 86_400) * 86_400
            + i64::from(st.wHour) * 3_600
            + i64::from(st.wMinute) * 60
            + i64::from(st.wSecond);
        // A malformed SYSTEMTIME (e.g. wYear = u16::MAX) overflows i64 when
        // scaled to 100ns intervals: saturate instead of panicking in debug
        // builds (the release build would silently wrap into a wrong date)
        secs_since_1601
            .saturating_mul(10_000_000)
            .saturating_add(i64::from(st.wMilliseconds) * 10_000)
    }

    /// Converts to a unix timestamp with millisecond granularity.
    #[must_use]
    pub fn as_unix_timestamp(&self) -> i64 {
        self.as_filetime_quad() / 10_000 - (SECONDS_BETWEEN_1601_AND_1970 * MS_IN_SECOND)
    }

    /// Converts to a unix timestamp with nanosecond granularity.
    #[must_use]
    pub fn as_unix_timestamp_nanos(&self) -> i128 {
        i128::from(self.as_filetime_quad()) * 100
            - (i128::from(SECONDS_BETWEEN_1601_AND_1970) * i128::from(NS_IN_SECOND))
    }

    /// Converts to OffsetDateTime
    #[cfg(feature = "time_rs")]
    #[must_use]
    pub fn as_date_time(&self) -> time::OffsetDateTime {
        saturating_date_time(self.as_unix_timestamp_nanos())
    }

    pub(crate) fn from_slice(slice: [u8; size_of::<SystemTime>()]) -> Self {
        // ETW user data is packed: it is not guaranteed to be aligned for a
        // SYSTEMTIME, so copy the fields one by one instead of dereferencing
        let read_u16 = |offset: usize| -> u16 {
            u16::from_ne_bytes(slice[offset..offset + 2].try_into().unwrap())
        };
        SystemTime(SYSTEMTIME {
            wYear: read_u16(0),
            wMonth: read_u16(2),
            wDayOfWeek: read_u16(4),
            wDay: read_u16(6),
            wHour: read_u16(8),
            wMinute: read_u16(10),
            wSecond: read_u16(12),
            wMilliseconds: read_u16(14),
        })
    }
}

#[cfg(feature = "time_rs")]
impl From<SystemTime> for time::OffsetDateTime {
    fn from(file_time: SystemTime) -> Self {
        file_time.as_date_time()
    }
}

#[cfg(feature = "serde")]
impl serde::ser::Serialize for SystemTime {
    #[cfg(feature = "time_rs")]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_date_time().serialize(serializer)
    }

    #[cfg(not(feature = "time_rs"))]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_unix_timestamp().serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_time_from_slice_copies_both_dwords() {
        // 0x0102030405060708 as it would be laid out in (packed) ETW user data
        let bytes = [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        let file_time = FileTime::from_slice(bytes);
        assert_eq!(file_time.0.dwLowDateTime, 0x0506_0708);
        assert_eq!(file_time.0.dwHighDateTime, 0x0102_0304);
    }

    #[test]
    fn system_time_from_slice_copies_all_fields() {
        // 2026-01-02 03:04:05.006, packed little-endian
        let bytes: [u8; 16] = [
            0xea, 0x07, // wYear = 2026
            0x01, 0x00, // wMonth = 1
            0x05, 0x00, // wDayOfWeek = 5
            0x02, 0x00, // wDay = 2
            0x03, 0x00, // wHour = 3
            0x04, 0x00, // wMinute = 4
            0x05, 0x00, // wSecond = 5 (was silently dropped before the fix)
            0x06, 0x00, // wMilliseconds = 6
        ];
        let system_time = SystemTime::from_slice(bytes);
        assert_eq!(system_time.0.wYear, 2026);
        assert_eq!(system_time.0.wMonth, 1);
        assert_eq!(system_time.0.wDayOfWeek, 5);
        assert_eq!(system_time.0.wDay, 2);
        assert_eq!(system_time.0.wHour, 3);
        assert_eq!(system_time.0.wMinute, 4);
        assert_eq!(system_time.0.wSecond, 5);
        assert_eq!(system_time.0.wMilliseconds, 6);
    }

    #[test]
    fn system_time_unix_timestamp_matches_known_dates() {
        // The conversion no longer goes through the SystemTimeToFileTime FFI
        // call: check it against independently known unix timestamps
        let to_unix_ms = |y, mo, d, h, mi, s, ms| {
            SystemTime(SYSTEMTIME {
                wYear: y,
                wMonth: mo,
                wDayOfWeek: 0, // redundant field, ignored by the conversion
                wDay: d,
                wHour: h,
                wMinute: mi,
                wSecond: s,
                wMilliseconds: ms,
            })
            .as_unix_timestamp()
        };

        assert_eq!(to_unix_ms(1970, 1, 1, 0, 0, 0, 0), 0);
        // Leap day
        assert_eq!(to_unix_ms(2024, 2, 29, 12, 0, 0, 0), 1_709_208_000_000);
        // Start of the FILETIME epoch
        assert_eq!(to_unix_ms(1601, 1, 1, 0, 0, 0, 0), -11_644_473_600_000);
        // Non-leap century year (1900-02-28 is followed by 1900-03-01)
        assert_eq!(to_unix_ms(1900, 3, 1, 0, 0, 0, 0), -2_203_891_200_000);
    }

    #[test]
    fn system_time_unix_timestamp_nanos_matches_known_dates() {
        let st = SystemTime(SYSTEMTIME {
            wYear: 1970,
            wMonth: 1,
            wDay: 1,
            wSecond: 1,
            wMilliseconds: 1,
            ..Default::default()
        });
        assert_eq!(st.as_unix_timestamp_nanos(), 1_001_000_000);

        let st = SystemTime(SYSTEMTIME {
            wYear: 1601,
            wMonth: 1,
            wDay: 1,
            ..Default::default()
        });
        assert_eq!(st.as_unix_timestamp_nanos(), -11_644_473_600_000_000_000);
    }

    #[test]
    fn system_time_unix_timestamp_keeps_seconds() {
        // 2026-01-02 03:04:05.006 UTC == unix timestamp 1767323045006 (ms).
        // Before the wSecond fix this would come out as 1767323040006.
        let bytes: [u8; 16] = [
            0xea, 0x07, 0x01, 0x00, 0x05, 0x00, 0x02, 0x00, //
            0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00,
        ];
        let system_time = SystemTime::from_slice(bytes);
        assert_eq!(system_time.as_unix_timestamp(), 1_767_323_045_006);
    }

    #[cfg(feature = "time_rs")]
    #[test]
    fn valid_timestamps_convert_exactly() {
        let st = SystemTime(SYSTEMTIME {
            wYear: 1970,
            wMonth: 1,
            wDay: 1,
            wSecond: 1,
            wMilliseconds: 1,
            ..Default::default()
        });
        assert_eq!(st.as_date_time().unix_timestamp_nanos(), 1_001_000_000);

        // FILETIME of 1970-01-01T00:00:01.0000001 (one 100ns tick past 1s)
        let file_time =
            FileTime::from_quad(10_000_001 + SECONDS_BETWEEN_1601_AND_1970 * 10_000_000);
        assert_eq!(
            file_time.as_date_time().unix_timestamp_nanos(),
            1_000_000_100
        );
    }

    #[cfg(feature = "time_rs")]
    #[test]
    fn absurd_file_times_saturate_instead_of_panicking() {
        // Out-of-range quads (as found in corrupted ETL files) must not panic:
        // the conversion runs in the ETW callback thread. The clamped i64 quad
        // stays within `time`'s representable range (large-dates), so it
        // converts exactly, into a huge year
        let far_future = FileTime::from_quad(i64::MAX);
        assert_eq!(far_future.as_date_time().year(), 30_828);

        let far_past = FileTime::from_quad(i64::MIN);
        assert_eq!(far_past.as_date_time().year(), -27_627);
    }

    #[cfg(feature = "time_rs")]
    #[test]
    fn absurd_system_times_saturate_instead_of_panicking() {
        // wYear = u16::MAX overflows the 100ns scaling in debug builds: the
        // saturating arithmetic must keep the conversion panic-free
        let st = SystemTime(SYSTEMTIME {
            wYear: u16::MAX,
            wMonth: 12,
            wDay: 31,
            ..Default::default()
        });
        // Saturated to the i64 maximum quad, same as the absurd FILETIME above
        assert_eq!(st.as_date_time().year(), 30_828);
    }
}
