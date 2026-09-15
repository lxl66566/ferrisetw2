//! ETW information classes wrapper

use windows::Win32::System::Diagnostics::Etw::{
    TRACE_PERIODIC_CAPTURE_STATE_INFO, TRACE_PROFILE_INTERVAL, TRACE_VERSION_INFO,
};
use zerocopy::IntoBytes;

use crate::{
    native::{etw_types::TraceInformation, evntrace},
    trace::TraceError,
};

type TraceResult<T> = Result<T, TraceError>;

/// A performance profiling source (a.k.a. PMC source)
///
/// Sources other than [`ProfileSource::ProfileTime`] are machine-specific:
/// enumerate them with [`SessionlessInfo::profile_sources`]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileSource {
    /// The CPU time sampler (the source behind sampled profile events)
    ProfileTime,
    /// A source id obtained from [`SessionlessInfo::profile_sources`]
    Id(u32),
}

impl ProfileSource {
    fn id(self) -> u32 {
        match self {
            Self::ProfileTime => 0,
            Self::Id(id) => id,
        }
    }
}

/// An available profiling source, as returned by [`SessionlessInfo::profile_sources`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSourceInfo {
    /// Machine-specific id of the source, usable as [`ProfileSource::Id`]
    pub id: u32,
    /// Smallest sampling interval the source accepts, in source-specific units
    pub min_interval: u32,
    /// Largest sampling interval the source accepts, in source-specific units
    pub max_interval: u32,
    /// Human-readable description of the source
    pub description: String,
}

/// Limits of the periodic capture state (a.k.a. rundown) feature
///
/// Returned by [`SessionlessInfo::periodic_capture_state_limits`]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeriodicCaptureStateLimits {
    /// Minimum delay, in seconds, between two capture state requests
    pub min_frequency_seconds: u32,
    /// Maximum number of providers a session may register for periodic capture state
    pub max_providers: u16,
}

/// System-wide ETW information that does not require an active session
///
/// Thin, type-safe wrappers over the
/// [`TraceQueryInformation`](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-tracequeryinformation)
/// API (the info classes documented as not using a session handle)
pub struct SessionlessInfo;

/// Queries a fixed-size, all-integer ETW structure (or plain scalar)
fn query_pod<T: Copy>(class: TraceInformation) -> TraceResult<T> {
    let mut buf = vec![0u8; size_of::<T>()];
    evntrace::query_info(class, &mut buf)?;
    Ok(unsafe {
        // SAFETY: `buf` holds exactly size_of::<T>() initialized bytes. Every `T` used
        // here is an all-integer POD ETW structure (or a scalar), so any bit pattern
        // is a valid value and no padding can be read
        std::ptr::read_unaligned(buf.as_ptr().cast::<T>())
    })
}

// On-the-wire size of the fixed part of PROFILE_SOURCE_INFO (everything before
// the variable-sized, NUL-terminated `Description` wide string)
const PROFILE_SOURCE_FIXED_LEN: usize = 24;

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(
        buf[offset..offset + 4]
            .try_into()
            .expect("4 readable bytes"),
    )
}

/// Decodes the NUL-terminated UTF-16 string of a PROFILE_SOURCE_INFO entry
fn decode_description(desc: &[u8]) -> String {
    let units = desc
        .chunks_exact(2)
        .take_while(|pair| pair != &[0, 0])
        .map(|pair| u16::from_ne_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    String::from_utf16_lossy(&units)
}

/// Parses the variable-sized array of PROFILE_SOURCE_INFO linked by `NextEntryOffset`
fn parse_profile_sources(buf: &[u8]) -> Vec<ProfileSourceInfo> {
    let mut sources = Vec::new();
    let mut offset = 0;

    while offset + PROFILE_SOURCE_FIXED_LEN <= buf.len() {
        let next = read_u32(buf, offset);
        let source = ProfileSourceInfo {
            id: read_u32(buf, offset + 4),
            min_interval: read_u32(buf, offset + 8),
            max_interval: read_u32(buf, offset + 12),
            description: decode_description(&buf[offset + PROFILE_SOURCE_FIXED_LEN..]),
        };
        sources.push(source);

        if next == 0 {
            break;
        }
        offset += next as usize;
    }

    sources
}

impl SessionlessInfo {
    /// Queries the sampling interval of a profiling source
    /// (info class `TraceSampledProfileIntervalInfo`)
    pub fn sample_interval(source: ProfileSource) -> TraceResult<u32> {
        let mut info = TRACE_PROFILE_INTERVAL {
            Source: source.id(),
            Interval: 0,
        };

        evntrace::query_info(
            TraceInformation::TraceSampledProfileIntervalInfo,
            // SAFETY: TRACE_PROFILE_INTERVAL is `#[repr(C)]` and uses only POD
            unsafe {
                std::slice::from_raw_parts_mut(
                    (&raw mut info).cast::<u8>(),
                    size_of::<TRACE_PROFILE_INTERVAL>(),
                )
            },
        )?;

        Ok(info.Interval)
    }

    /// Queries the maximum number of PMC counters that can be specified simultaneously
    /// (info class `TraceMaxPmcCounterQuery`)
    pub fn max_pmc() -> TraceResult<u32> {
        let mut max_pmc = 0u32;

        evntrace::query_info(
            TraceInformation::TraceMaxPmcCounterQuery,
            max_pmc.as_mut_bytes(),
        )?;

        Ok(max_pmc)
    }

    /// Queries the maximum number of ETW logging sessions the OS allows at a time
    /// (info class `TraceMaxLoggersQuery`)
    pub fn max_loggers() -> TraceResult<u32> {
        query_pod(TraceInformation::TraceMaxLoggersQuery)
    }

    /// Queries the version of the ETW trace processing code
    /// (info class `TraceVersionInfo`)
    pub fn trace_version() -> TraceResult<u32> {
        Ok(
            query_pod::<TRACE_VERSION_INFO>(TraceInformation::TraceVersionInfo)?
                .EtwTraceProcessingVersion,
        )
    }

    /// Queries the limits of the periodic capture state feature
    /// (info class `TracePeriodicCaptureStateInfo`)
    pub fn periodic_capture_state_limits() -> TraceResult<PeriodicCaptureStateLimits> {
        let info = query_pod::<TRACE_PERIODIC_CAPTURE_STATE_INFO>(
            TraceInformation::TracePeriodicCaptureStateInfo,
        )?;
        Ok(PeriodicCaptureStateLimits {
            min_frequency_seconds: info.CaptureStateFrequencyInSeconds,
            max_providers: info.ProviderCount,
        })
    }

    /// Queries the profiling (PMC) sources available on this system
    /// (info class `TraceProfileSourceListInfo`)
    pub fn profile_sources() -> TraceResult<Vec<ProfileSourceInfo>> {
        let buf = evntrace::query_array_info(TraceInformation::TraceProfileSourceListInfo, 4096)?;
        Ok(parse_profile_sources(&buf))
    }
}

#[cfg(test)]
mod tests {
    use windows::Win32::System::Diagnostics::Etw;

    use super::*;

    // The local enum must stay in sync with the windows-rs bindings (which come
    // from the Windows SDK) for every class this crate wraps
    #[test]
    fn info_classes_match_windows_rs() {
        let cases = [
            (
                TraceInformation::TraceStackTracingInfo,
                Etw::TraceStackTracingInfo.0,
            ),
            (
                TraceInformation::TraceSystemTraceEnableFlagsInfo,
                Etw::TraceSystemTraceEnableFlagsInfo.0,
            ),
            (
                TraceInformation::TraceSampledProfileIntervalInfo,
                Etw::TraceSampledProfileIntervalInfo.0,
            ),
            (
                TraceInformation::TraceProfileSourceListInfo,
                Etw::TraceProfileSourceListInfo.0,
            ),
            (TraceInformation::TraceVersionInfo, Etw::TraceVersionInfo.0),
            (
                TraceInformation::TracePeriodicCaptureStateInfo,
                Etw::TracePeriodicCaptureStateInfo.0,
            ),
            (
                TraceInformation::TraceMaxLoggersQuery,
                Etw::TraceMaxLoggersQuery.0,
            ),
            (
                TraceInformation::TraceMaxPmcCounterQuery,
                Etw::TraceMaxPmcCounterQuery.0,
            ),
        ];
        for (class, expected) in cases {
            assert_eq!(class as i32, expected);
        }
    }

    fn profile_source_entry(id: u32, next_entry_offset: u32, description: &str) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.extend_from_slice(&next_entry_offset.to_ne_bytes());
        entry.extend_from_slice(&id.to_ne_bytes());
        entry.extend_from_slice(&1u32.to_ne_bytes()); // MinInterval
        entry.extend_from_slice(&10_000u32.to_ne_bytes()); // MaxInterval
        entry.extend_from_slice(&0u64.to_ne_bytes()); // Reserved
        let mut wide: Vec<u8> = description
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_ne_bytes)
            .collect();
        entry.append(&mut wide);
        entry
    }

    #[test]
    fn profile_sources_are_parsed() {
        let mut buf = profile_source_entry(2, 0, "");
        let second = profile_source_entry(5, 0, "Timer");
        // Point the first entry to the second one, two bytes further (the OS packs
        // entries tighter than sizeof(PROFILE_SOURCE_INFO))
        let first_len = u32::try_from(buf.len()).unwrap();
        buf[0..4].copy_from_slice(&(first_len + 2).to_ne_bytes());
        buf.extend_from_slice(b"\0\0"); // padding between the two entries
        buf.extend_from_slice(&second);

        let sources = parse_profile_sources(&buf);
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].id, 2);
        assert_eq!(sources[0].description, "");
        assert_eq!(sources[1].id, 5);
        assert_eq!(sources[1].min_interval, 1);
        assert_eq!(sources[1].max_interval, 10_000);
        assert_eq!(sources[1].description, "Timer");
    }

    #[test]
    fn truncated_profile_source_entries_are_dropped() {
        let buf = profile_source_entry(7, 0, "unterminated");
        let truncated = &buf[..buf.len() - 3]; // cut in the middle of the description

        let sources = parse_profile_sources(truncated);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].description, "unterminate");
    }

    #[test]
    fn profile_source_ids_round_trip() {
        assert_eq!(ProfileSource::ProfileTime.id(), 0);
        assert_eq!(ProfileSource::Id(42).id(), 42);
    }
}
