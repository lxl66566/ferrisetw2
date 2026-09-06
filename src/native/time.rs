//! Implements wrappers for various Windows time structures.
use std::convert::TryInto;
use windows::Win32::{
    Foundation::{FILETIME, SYSTEMTIME},
    System::Time::SystemTimeToFileTime,
};

/// Wrapper for [FILETIME](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime)
#[derive(Copy, Clone, Default)]
#[repr(transparent)]
pub struct FileTime(pub(crate) FILETIME);

const SECONDS_BETWEEN_1601_AND_1970: i64 = 11_644_473_600;
const NS_IN_SECOND: i64 = 1_000_000_000;
const MS_IN_SECOND: i64 = 1_000;

impl FileTime {
    /// Converts to a unix timestamp with millisecond granularity.
    pub fn as_unix_timestamp(&self) -> i64 {
        self.as_quad() / 10_000 - (SECONDS_BETWEEN_1601_AND_1970 * MS_IN_SECOND)
    }

    /// Converts to a unix timestamp with nanosecond granularity.
    pub fn as_unix_timestamp_nanos(&self) -> i128 {
        self.as_quad() as i128 * 100
            - (SECONDS_BETWEEN_1601_AND_1970 as i128 * NS_IN_SECOND as i128)
    }

    /// Converts to OffsetDateTime
    #[cfg(feature = "time_rs")]
    pub fn as_date_time(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp_nanos(self.as_unix_timestamp_nanos()).unwrap()
    }

    fn as_quad(&self) -> i64 {
        let mut quad = self.0.dwHighDateTime as i64;
        quad <<= 32;
        quad |= self.0.dwLowDateTime as i64;
        quad
    }

    #[cfg(any(feature = "time_rs", feature = "serde"))]
    pub(crate) fn from_quad(quad: i64) -> Self {
        let mut file_time: FileTime = Default::default();
        file_time.0.dwHighDateTime = (quad >> 32) as u32;
        file_time.0.dwLowDateTime = (quad & 0xffffffff) as u32;
        file_time
    }

    pub(crate) fn from_slice(slice: &[u8; std::mem::size_of::<FileTime>()]) -> Self {
        // ETW user data is packed: it is not guaranteed to be aligned for a
        // FILETIME, so copy the fields one by one instead of dereferencing
        let mut file_time: FileTime = Default::default();
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
    /// Converts to a unix timestamp with millisecond granularity.
    pub fn as_unix_timestamp(&self) -> i64 {
        let file_time: FileTime = Default::default();
        unsafe {
            _ = SystemTimeToFileTime(&self.0 as *const _, &file_time.0 as *const _ as *mut _);
        }
        file_time.as_unix_timestamp()
    }

    /// Converts to a unix timestamp with nanosecond granularity.
    pub fn as_unix_timestamp_nanos(&self) -> i128 {
        let file_time: FileTime = Default::default();
        unsafe {
            _ = SystemTimeToFileTime(&self.0 as *const _, &file_time.0 as *const _ as *mut _);
        }
        file_time.as_unix_timestamp_nanos()
    }

    /// Converts to OffsetDateTime
    #[cfg(feature = "time_rs")]
    pub fn as_date_time(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp_nanos(self.as_unix_timestamp_nanos()).unwrap()
    }

    pub(crate) fn from_slice(slice: &[u8; std::mem::size_of::<SystemTime>()]) -> Self {
        // ETW user data is packed: it is not guaranteed to be aligned for a
        // SYSTEMTIME, so copy the fields one by one instead of dereferencing
        let read_u16 = |offset: usize| -> u16 {
            u16::from_ne_bytes(slice[offset..offset + 2].try_into().unwrap())
        };
        let mut system_time = SYSTEMTIME::default();
        system_time.wYear = read_u16(0);
        system_time.wMonth = read_u16(2);
        system_time.wDayOfWeek = read_u16(4);
        system_time.wDay = read_u16(6);
        system_time.wHour = read_u16(8);
        system_time.wMinute = read_u16(10);
        system_time.wSecond = read_u16(12);
        system_time.wMilliseconds = read_u16(14);
        SystemTime(system_time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_time_from_slice_copies_both_dwords() {
        // 0x0102030405060708 as it would be laid out in (packed) ETW user data
        let bytes = [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
        let file_time = FileTime::from_slice(&bytes);
        assert_eq!(file_time.0.dwLowDateTime, 0x05060708);
        assert_eq!(file_time.0.dwHighDateTime, 0x01020304);
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
        let system_time = SystemTime::from_slice(&bytes);
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
    fn system_time_unix_timestamp_keeps_seconds() {
        // 2026-01-02 03:04:05.006 UTC == unix timestamp 1767323045006 (ms).
        // Before the wSecond fix this would come out as 1767323040006.
        let bytes: [u8; 16] = [
            0xea, 0x07, 0x01, 0x00, 0x05, 0x00, 0x02, 0x00, //
            0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00,
        ];
        let system_time = SystemTime::from_slice(&bytes);
        assert_eq!(system_time.as_unix_timestamp(), 1_767_323_045_006);
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
