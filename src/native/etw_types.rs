//! Basic ETW types
//!
//! The `etw_types` module provides an abstraction over the basic ETW types needed to control and
//! parse a trace session. Most of the types in this module are wrappers over the windows bindings
//! using the newtype pattern to extend their implementations
//!
//! In most cases a user of the crate won't have to deal with this and can directly obtain the data
//! needed by using the functions exposed by the modules at the crate level
#![allow(clippy::bad_bit_mask)]

use std::{
    ffi::{OsString, c_void},
    fmt::Formatter,
    marker::PhantomData,
    sync::Arc,
};

use widestring::{U16CStr, U16CString};
use windows::{
    Win32::System::Diagnostics::{Etw, Etw::EVENT_FILTER_DESCRIPTOR},
    core::{GUID, PWSTR},
};

use crate::{
    provider::{TraceFlags, event_filter::EventFilterDescriptor},
    trace::{RealTimeTraceTrait, TraceProperties, callback_data::CallbackData},
};

pub(crate) mod event_record;
pub(crate) mod extended_data;

pub const TRACE_NAME_MAX_CHARS: usize = 200; // Microsoft documentation says the limit is 1024, but do not trust us. Experience shows that traces with names longer than ~240 character silently fail.

/// This enum is <https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ne-evntrace-trace_query_info_class>
///
/// Re-defining it here, because all these values are not defined in windows-rs (yet?)
#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
#[non_exhaustive]
#[repr(i32)]
pub enum TraceInformation {
    TraceGuidQueryList,
    TraceGuidQueryInfo,
    TraceGuidQueryProcess,
    TraceStackTracingInfo,
    TraceSystemTraceEnableFlagsInfo,
    TraceSampledProfileIntervalInfo,
    TraceProfileSourceConfigInfo,
    TraceProfileSourceListInfo,
    TracePmcEventListInfo,
    TracePmcCounterListInfo,
    TraceSetDisallowList,
    TraceVersionInfo,
    TraceGroupQueryList,
    TraceGroupQueryInfo,
    TraceDisallowListQuery,
    TraceInfoReserved15,
    TracePeriodicCaptureStateListInfo,
    TracePeriodicCaptureStateInfo,
    TraceProviderBinaryTracking,
    TraceMaxLoggersQuery,
    TraceLbrConfigurationInfo,
    TraceLbrEventListInfo,
    /// Query the maximum PMC counters that can be specified simultaneously.
    /// May be queried without an active ETW session.
    ///
    /// Output: u32
    TraceMaxPmcCounterQuery,
    TraceStreamCount,
    TraceStackCachingInfo,
    TracePmcCounterOwners,
    TraceUnifiedStackCachingInfo,
    TracePmcSessionInformation,
    MaxTraceSetInfoClass,
}

#[allow(dead_code)]
pub(crate) enum ControlValues {
    Query = 0,
    Stop = 1,
    Update = 2,
}

/// The kernel logger's group mask, payload of the `TraceSystemTraceEnableFlagsInfo` info class
///
/// `evntrace.h` documents that info class as taking a `PERFINFO_GROUPMASK`, but that struct is
/// not part of the public SDK (it lives in the kernel's `ntwmi.h`). Layout mirrored from
/// [krabsetw](https://github.com/microsoft/krabsetw/blob/master/krabs/krabs/perfinfo_groupmask.hpp):
/// an array of eight `ULONG` masks.
///
/// A group id (see [`crate::trace::ExtendedKernelGroup`]) encodes the index of its target mask
/// in its top 3 bits, and the groups to enable within that mask in the remaining 29 bits.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PerfinfoGroupmask {
    masks: [u32; Self::MASK_COUNT],
}

impl PerfinfoGroupmask {
    const MASK_COUNT: usize = 8;
    /// Top 3 bits of a group id: the index of the mask it applies to
    const MASK_INDEX: u32 = 0xe000_0000;

    /// Merges a raw group id into the mask
    pub(crate) fn set_group(&mut self, group: u32) {
        let index = ((group & Self::MASK_INDEX) >> 29) as usize;
        self.masks[index] |= group & !Self::MASK_INDEX;
    }

    /// Merges the given extended kernel groups into the mask
    pub(crate) fn set_groups(&mut self, groups: &[crate::trace::ExtendedKernelGroup]) {
        for group in groups {
            self.set_group(group.group_id());
        }
    }

    /// The eight masks, for tests asserting on the encoding
    #[cfg(test)]
    pub(crate) fn masks(&self) -> &[u32; Self::MASK_COUNT] {
        &self.masks
    }

    /// Byte view of the struct, as expected by the ETW APIs
    pub(crate) fn as_bytes(&self) -> &[u8] {
        // SAFETY: the struct is #[repr(C)] and only holds integers, so there is no padding,
        // and any bit pattern is a valid value
        unsafe { std::slice::from_raw_parts(std::ptr::from_ref(self).cast(), size_of::<Self>()) }
    }

    /// Rebuilds the struct from the byte view filled by a query
    pub(crate) fn from_bytes(buf: &[u8; size_of::<PerfinfoGroupmask>()]) -> Self {
        // SAFETY: `buf` holds exactly size_of::<Self>() initialized bytes, and the struct is
        // #[repr(C)] with only integer fields (no padding to read, any bit pattern is valid)
        unsafe { std::ptr::read_unaligned(buf.as_ptr().cast()) }
    }
}

bitflags! {
    /// Logging Mode constants that applies to a general trace
    ///
    /// This is a subset of <https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants>
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct LoggingMode: u32 {
        // Commented values only apply to DumpFileLoggingMod

        // EVENT_TRACE_FILE_MODE_NONE
        // EVENT_TRACE_FILE_MODE_SEQUENTIAL
        // EVENT_TRACE_FILE_MODE_CIRCULAR
        // EVENT_TRACE_FILE_MODE_APPEND
        // EVENT_TRACE_FILE_MODE_NEWFILE
        // EVENT_TRACE_FILE_MODE_PREALLOCATE
        const EVENT_TRACE_NONSTOPPABLE_MODE =          Etw::EVENT_TRACE_NONSTOPPABLE_MODE;
        const EVENT_TRACE_SECURE_MODE =                Etw::EVENT_TRACE_SECURE_MODE;
        const EVENT_TRACE_REAL_TIME_MODE =             Etw::EVENT_TRACE_REAL_TIME_MODE;
        // On Windows Vista or later, this mode is not applicable should not be used.
        // EVENT_TRACE_DELAY_OPEN_FILE_MODE
        const EVENT_TRACE_BUFFERING_MODE =             Etw::EVENT_TRACE_BUFFERING_MODE;
        const EVENT_TRACE_PRIVATE_LOGGER_MODE =        Etw::EVENT_TRACE_PRIVATE_LOGGER_MODE;
        // EVENT_TRACE_USE_KBYTES_FOR_SIZE
        // EVENT_TRACE_USE_GLOBAL_SEQUENCE
        // EVENT_TRACE_USE_LOCAL_SEQUENCE
        const EVENT_TRACE_PRIVATE_IN_PROC =            Etw::EVENT_TRACE_PRIVATE_IN_PROC;
        const EVENT_TRACE_MODE_RESERVED =              Etw::EVENT_TRACE_MODE_RESERVED;
        const EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN =    Etw::EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN;
        const EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN = Etw::EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN;
        const EVENT_TRACE_USE_PAGED_MEMORY =           Etw::EVENT_TRACE_USE_PAGED_MEMORY;
        const EVENT_TRACE_SYSTEM_LOGGER_MODE =         Etw::EVENT_TRACE_SYSTEM_LOGGER_MODE;
        const EVENT_TRACE_INDEPENDENT_SESSION_MODE =   Etw::EVENT_TRACE_INDEPENDENT_SESSION_MODE;
        const EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING = Etw::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
        const EVENT_TRACE_ADDTO_TRIAGE_DUMP =          Etw::EVENT_TRACE_ADDTO_TRIAGE_DUMP;
    }
}

bitflags! {
    /// Logging Mode constants that applies to a dump file.
    ///
    /// This is a subset of <https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants>
    ///
    /// See the documentation of [`crate::trace::TraceBuilder::set_etl_dump_file`] for more info.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct DumpFileLoggingMode: u32 {
        // Commented values only apply to LoggingMode

        /// > Same as EVENT_TRACE_FILE_MODE_SEQUENTIAL with no maximum file size specified.
        const EVENT_TRACE_FILE_MODE_NONE =             Etw::EVENT_TRACE_FILE_MODE_NONE;
        /// > Writes events to a log file sequentially; stops when the file reaches its maximum size.Do not use with EVENT_TRACE_FILE_MODE_CIRCULAR or EVENT_TRACE_FILE_MODE_NEWFILE.
        ///
        /// Note: "stop" here means "stop appending to the file", not "stop the trace"
        const EVENT_TRACE_FILE_MODE_SEQUENTIAL =       Etw::EVENT_TRACE_FILE_MODE_SEQUENTIAL;
        /// > Writes events to a log file. After the file reaches the maximum size, the oldest events are replaced with incoming events.Note that the contents of the circular log file may appear out of order on multiprocessor computers.<br/>
        /// > Do not use with EVENT_TRACE_FILE_MODE_APPEND, EVENT_TRACE_FILE_MODE_NEWFILE, or EVENT_TRACE_FILE_MODE_SEQUENTIAL.
        const EVENT_TRACE_FILE_MODE_CIRCULAR =         Etw::EVENT_TRACE_FILE_MODE_CIRCULAR;
        /// > Appends events to an existing sequential log file. If the file does not exist, it is created. Use only if you specify system time for the clock resolution, otherwise, ProcessTrace will return events with incorrect time stamps. When using EVENT_TRACE_FILE_MODE_APPEND, the values for BufferSize, NumberOfProcessors, and ClockType must be explicitly provided and must be the same in both the logger and the file being appended.<br/>
        /// > Do not use with EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_FILE_MODE_CIRCULAR, EVENT_TRACE_FILE_MODE_NEWFILE, or EVENT_TRACE_PRIVATE_LOGGER_MODE.
        const EVENT_TRACE_FILE_MODE_APPEND =           Etw::EVENT_TRACE_FILE_MODE_APPEND;
        /// > Automatically switches to a new log file when the file reaches the maximum size. The MaximumFileSize member of EVENT_TRACE_PROPERTIES must be set.The specified file name must be a formatted string (for example, the string contains a %d, such as c:\test%d.etl). Each time a new file is created, a counter is incremented and its value is used, the formatted string is updated, and the resulting string is used as the file name.<br/>
        /// > This option is not allowed for private event tracing sessions and should not be used for NT kernel logger sessions.<br/>
        /// > Do not use with EVENT_TRACE_FILE_MODE_CIRCULAR, EVENT_TRACE_FILE_MODE_APPEND or EVENT_TRACE_FILE_MODE_SEQUENTIAL.
        const EVENT_TRACE_FILE_MODE_NEWFILE =          Etw::EVENT_TRACE_FILE_MODE_NEWFILE;
        /// > Reserves EVENT_TRACE_PROPERTIES.MaximumFileSize bytes of disk space for the log file in advance. The file occupies the entire space during logging, for both circular and sequential log files. When you stop the session, the log file is reduced to the size needed. You must set EVENT_TRACE_PROPERTIES.MaximumFileSize.<br/>
        /// > You cannot use the mode for private event tracing sessions.
        const EVENT_TRACE_FILE_MODE_PREALLOCATE =      Etw::EVENT_TRACE_FILE_MODE_PREALLOCATE;
        // EVENT_TRACE_NONSTOPPABLE_MODE
        // EVENT_TRACE_SECURE_MODE
        // EVENT_TRACE_REAL_TIME_MODE
        // On Windows Vista or later, this mode is not applicable should not be used.
        // EVENT_TRACE_DELAY_OPEN_FILE_MODE
        // EVENT_TRACE_BUFFERING_MODE
        // EVENT_TRACE_PRIVATE_LOGGER_MODE
        /// > Use kilobytes as the unit of measure for specifying the size of a file. The default unit of measure is megabytes. This mode applies to the MaxFileSize registry value for an AutoLogger session and the MaximumFileSize member of EVENT_TRACE_PROPERTIES.
        const EVENT_TRACE_USE_KBYTES_FOR_SIZE =        Etw::EVENT_TRACE_USE_KBYTES_FOR_SIZE;
        /// > Uses sequence numbers that are unique across event tracing sessions. This mode only applies to events logged using the TraceMessage function. For more information, see TraceMessage for usage details.<br/>
        /// > EVENT_TRACE_USE_GLOBAL_SEQUENCE and EVENT_TRACE_USE_LOCAL_SEQUENCE are mutually exclusive.
        const EVENT_TRACE_USE_GLOBAL_SEQUENCE =        Etw::EVENT_TRACE_USE_GLOBAL_SEQUENCE;
        /// > Uses sequence numbers that are unique only for an individual event tracing session. This mode only applies to events logged using the TraceMessage function. For more information, see TraceMessage for usage details.<br/>
        /// > EVENT_TRACE_USE_GLOBAL_SEQUENCE and EVENT_TRACE_USE_LOCAL_SEQUENCE are mutually exclusive.
        const EVENT_TRACE_USE_LOCAL_SEQUENCE =         Etw::EVENT_TRACE_USE_LOCAL_SEQUENCE;
        // EVENT_TRACE_PRIVATE_IN_PROC
        // EVENT_TRACE_MODE_RESERVED
        // EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN
        // EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN
        // EVENT_TRACE_USE_PAGED_MEMORY
        // EVENT_TRACE_SYSTEM_LOGGER_MODE
        // EVENT_TRACE_INDEPENDENT_SESSION_MODE
        // EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING
        // EVENT_TRACE_ADDTO_TRIAGE_DUMP
    }
}

/// The clock resolution used to timestamp the events of a session
///
/// Maps to the `Wnode.ClientContext` field of [EVENT_TRACE_PROPERTIES](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)
/// (see the [WNODE_HEADER clock types](https://learn.microsoft.com/en-us/windows/win32/etw/wnode-header)).
///
/// The third Windows clock type, the CPU cycle counter, is deliberately not
/// exposed: Microsoft deems it unreliable on modern CPUs (frequency scaling,
/// idle states) and unsupported hardware silently falls back to system time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClockType {
    /// Query performance counter: high-resolution and unaffected by system
    /// clock adjustments. Best for high event rates, or when ordering events
    /// coming from different buffers. This is the Windows default.
    #[default]
    Qpc = 1,
    /// System time: tracks system clock adjustments (e.g. an NTP
    /// synchronization jumping the clock forward). Required when appending to
    /// an existing sequential dump file
    /// (see [`DumpFileLoggingMode::EVENT_TRACE_FILE_MODE_APPEND`]).
    SystemTime = 2,
}

impl Default for DumpFileLoggingMode {
    fn default() -> Self {
        Self::EVENT_TRACE_FILE_MODE_NONE
    }
}

/// The data source the trace is subscribed to
#[derive(Clone, Debug)]
pub enum SubscriptionSource {
    /// Subscribe to a real-time session
    RealTimeSession(U16CString),
    /// Open an ETL file
    FromFile(U16CString),
}

/// Wrapper over an [EVENT_TRACE_PROPERTIES](https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties), and its allocated companion members
///
/// The [EventTraceProperties] struct contains the information about a tracing session, this struct
/// also needs two buffers right after it to hold the log file name and the session name. This
/// struct provides the full definition of the properties plus the the allocation for both names
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventTraceProperties {
    etw_trace_properties: Etw::EVENT_TRACE_PROPERTIES,
    /// The trace name to subscribe to
    wide_trace_name: [u16; TRACE_NAME_MAX_CHARS + 1], /* The +1 leaves space for the final null
                                                       * widechar. */
    /// The file name (if any) we store our events to
    wide_etl_dump_file_path: [u16; TRACE_NAME_MAX_CHARS + 1], /* The +1 leaves space for the
                                                               * final null widechar. */
}

impl std::fmt::Debug for EventTraceProperties {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let name = U16CString::from_vec_truncate(self.wide_trace_name).to_string_lossy();
        f.debug_struct("EventTraceProperties")
            .field("name", &name)
            .finish_non_exhaustive()
    }
}

impl EventTraceProperties {
    /// Create a new instance
    ///
    /// # Notes
    /// `trace_name` is limited to 200 characters.<br/>
    /// The path to the dump file is limited to 200 characters.
    pub(crate) fn new<T>(
        trace_name: &U16CStr,
        etl_dump_file: Option<(&U16CStr, DumpFileLoggingMode, Option<u32>)>,
        trace_properties: &TraceProperties,
        enable_flags: Etw::EVENT_TRACE_FLAG,
    ) -> Self
    where
        T: RealTimeTraceTrait,
    {
        let mut etw_trace_properties = Etw::EVENT_TRACE_PROPERTIES::default();

        // BufferSize is expressed in bytes over at most a few buffers: it cannot overflow a u32
        #[allow(clippy::cast_possible_truncation)]
        let buffer_size = size_of::<EventTraceProperties>() as u32;
        etw_trace_properties.Wnode.BufferSize = buffer_size;
        etw_trace_properties.Wnode.Guid = T::trace_guid();
        etw_trace_properties.Wnode.Flags = Etw::WNODE_FLAG_TRACED_GUID;
        etw_trace_properties.Wnode.ClientContext = trace_properties.clock_type as u32;
        etw_trace_properties.BufferSize = trace_properties.buffer_size;
        etw_trace_properties.MinimumBuffers = trace_properties.min_buffer;
        etw_trace_properties.MaximumBuffers = trace_properties.max_buffer;
        etw_trace_properties.FlushTimer = {
            // Round to the closest second (FlushTimer is expressed in seconds),
            // and clamp to at least 1s as documented on TraceProperties
            let rounded_seconds = (trace_properties.flush_timer.as_millis() + 500) / 1_000;
            let rounded_seconds = u32::try_from(rounded_seconds).unwrap_or(u32::MAX);
            rounded_seconds.clamp(1, u32::MAX)
        };

        if trace_properties.log_file_mode.is_empty() {
            etw_trace_properties.LogFileMode = (LoggingMode::EVENT_TRACE_REAL_TIME_MODE
                | LoggingMode::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING)
                .bits();
        } else {
            etw_trace_properties.LogFileMode = trace_properties.log_file_mode.bits();
        }

        etw_trace_properties.LogFileMode |= T::augmented_file_mode();
        etw_trace_properties.EnableFlags = enable_flags;

        let mut s = Self {
            etw_trace_properties,
            wide_trace_name: [0u16; TRACE_NAME_MAX_CHARS + 1],
            wide_etl_dump_file_path: [0u16; TRACE_NAME_MAX_CHARS + 1],
        };

        // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties#remarks
        // > You do not copy the session name to the offset. The StartTrace function copies the name
        // > for you.
        //
        // Let's do it anyway, even though that's not required
        let name_len = trace_name.len().min(TRACE_NAME_MAX_CHARS);
        s.wide_trace_name[..name_len].copy_from_slice(&trace_name.as_slice()[..name_len]);
        // Offsets within this fixed-size struct: cannot overflow a u32
        #[allow(clippy::cast_possible_truncation)]
        let logger_name_offset = offset_of!(EventTraceProperties, wide_trace_name) as u32;
        s.etw_trace_properties.LoggerNameOffset = logger_name_offset;

        // Also populate the file name, if any
        match etl_dump_file {
            None => {
                // Here, we do not want to dump events to a file
                // > If you do not want to log events to a log file (for example, if you specify EVENT_TRACE_REAL_TIME_MODE only), set LogFileNameOffset to 0.
                // (https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)
                s.etw_trace_properties.LogFileNameOffset = 0;
            },
            Some((path, file_mode, max_size)) => {
                // Set the file path, and set the dump-file-related flags
                let path_len = path.len().min(TRACE_NAME_MAX_CHARS);
                s.wide_etl_dump_file_path[..path_len].copy_from_slice(&path.as_slice()[..path_len]);
                // Offsets within this fixed-size struct: cannot overflow a u32
                #[allow(clippy::cast_possible_truncation)]
                let log_file_name_offset =
                    offset_of!(EventTraceProperties, wide_etl_dump_file_path) as u32;
                s.etw_trace_properties.LogFileNameOffset = log_file_name_offset;

                s.etw_trace_properties.LogFileMode |= file_mode.bits();
                if let Some(max_file_size) = max_size {
                    s.etw_trace_properties.MaximumFileSize = max_file_size;
                }
            },
        }

        s
    }

    /// Gets a pointer to the wrapped [Etw::EVENT_TRACE_PROPERTIES]
    ///
    /// # Safety
    ///
    /// The API enforces this points to an allocated, valid `EVENT_TRACE_PROPERTIES` instance.
    /// As evey other mutable raw pointer, you should not use it in case someone else is keeping a
    /// reference to this object.
    ///
    /// Note that `OpenTraceA` **will** modify its content on output.
    pub unsafe fn as_mut_ptr(&mut self) -> *mut Etw::EVENT_TRACE_PROPERTIES {
        &raw mut self.etw_trace_properties
    }

    pub fn trace_name_array(&self) -> &[u16] {
        &self.wide_trace_name
    }

    pub fn name(&self) -> OsString {
        U16CStr::from_slice_truncate(&self.wide_trace_name)
            .map_or_else(|_| OsString::from("<invalid name>"), U16CStr::to_os_string)
    }
}

/// Newtype wrapper over an [EVENT_TRACE_LOGFILEW]
///
/// Its lifetime is tied a to [`CallbackData`] because it contains raw pointers to it.
///
/// [EVENT_TRACE_LOGFILEW]: https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Diagnostics/Etw/struct.EVENT_TRACE_LOGFILEW.html
#[repr(C)]
#[derive(Clone)]
pub struct EventTraceLogfile<'callbackdata> {
    native: Etw::EVENT_TRACE_LOGFILEW,
    owned_subscription_source: SubscriptionSource,
    lifetime: PhantomData<&'callbackdata CallbackData>,
}

impl<'callbackdata> EventTraceLogfile<'callbackdata> {
    /// Create a new instance
    #[allow(clippy::borrowed_box)] // Being Boxed is really important, let's keep the Box<...> in the function signature to make the intent clearer (see https://github.com/n4r1b/ferrisetw/issues/72)
    pub fn create(
        callback_data: &'callbackdata Box<Arc<CallbackData>>,
        subscription_source: SubscriptionSource,
        callback: unsafe extern "system" fn(*mut Etw::EVENT_RECORD),
    ) -> Self {
        // That's kind-of fine because the user context is _not supposed_ to be changed by Windows
        // APIs
        let not_really_mut_ptr = std::ptr::from_ref(callback_data.as_ref())
            .cast_mut()
            .cast::<c_void>();

        let native = Etw::EVENT_TRACE_LOGFILEW {
            Anonymous2: Etw::EVENT_TRACE_LOGFILEW_1 {
                EventRecordCallback: Some(callback),
            },
            Context: not_really_mut_ptr,
            ..Default::default()
        };

        let mut log_file = Self {
            native,
            owned_subscription_source: subscription_source,
            lifetime: PhantomData,
        };

        // What should we subscribe to?
        match &mut log_file.owned_subscription_source {
            SubscriptionSource::RealTimeSession(wide_logger_name) => {
                log_file.native.LoggerName = PWSTR(wide_logger_name.as_mut_ptr());

                log_file.native.Anonymous1 = Etw::EVENT_TRACE_LOGFILEW_0 {
                    ProcessTraceMode: Etw::PROCESS_TRACE_MODE_REAL_TIME
                        | Etw::PROCESS_TRACE_MODE_EVENT_RECORD, /* In case you really want to use
                                                                 * PROCESS_TRACE_MODE_RAW_TIMESTAMP,
                                                                 * please review
                                                                 * EventRecord::timestamp(),
                                                                 * which could not be valid
                                                                 * anymore */
                };
            },
            SubscriptionSource::FromFile(wide_file_name) => {
                log_file.native.LogFileName = PWSTR(wide_file_name.as_mut_ptr());

                log_file.native.Anonymous1 = Etw::EVENT_TRACE_LOGFILEW_0 {
                    ProcessTraceMode: Etw::PROCESS_TRACE_MODE_EVENT_RECORD, /* In case you really want to use PROCESS_TRACE_MODE_RAW_TIMESTAMP, please review EventRecord::timestamp(), which could not be valid anymore */
                };
            },
        }

        log_file
    }

    /// Retrieve the windows-rs compatible pointer to the contained `EVENT_TRACE_LOGFILEA`
    ///
    /// # Safety
    ///
    /// This pointer is valid as long as [`Self`] is alive (and not modified elsewhere)<br/>
    /// Note that `OpenTraceW` **will** modify its content on output, and thus you should make sure
    /// to be the only user of this instance.
    pub(crate) unsafe fn as_mut_ptr(&mut self) -> *mut Etw::EVENT_TRACE_LOGFILEW {
        &raw mut self.native
    }

    /// The current Context pointer.
    pub fn context_ptr(&self) -> *const c_void {
        self.native.Context
    }
}

/// Newtype wrapper over an [ENABLE_TRACE_PARAMETERS]
///
/// [ENABLE_TRACE_PARAMETERS]: https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Diagnostics/Etw/struct.ENABLE_TRACE_PARAMETERS.html
#[repr(C)]
#[derive(Clone, Default)]
pub struct EnableTraceParameters<'filters> {
    native: Etw::ENABLE_TRACE_PARAMETERS,
    /// `native` has pointers to an array of EVENT_FILTER_DESCRIPTOR, let's store it here
    array_of_event_filter_descriptor: Vec<EVENT_FILTER_DESCRIPTOR>,
    /// `array_of_event_filter_descriptor` points to data somewhere else. Let's bind it to their
    /// lifetime
    lifetime: PhantomData<&'filters EventFilterDescriptor>,
}

impl<'filters> EnableTraceParameters<'filters> {
    pub fn create(
        guid: GUID,
        trace_flags: TraceFlags,
        filters: &'filters [EventFilterDescriptor],
    ) -> Self {
        let mut params = EnableTraceParameters::default();
        params.native.ControlFlags = 0;
        params.native.Version = Etw::ENABLE_TRACE_PARAMETERS_VERSION_2;
        params.native.SourceId = guid;
        params.native.EnableProperty = trace_flags.bits();

        // Note: > Each type of filter (a specific Type member) may only appear once in a call to
        // the EnableTraceEx2 function.       https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks
        //       > The maximum number of filters that can be included in a call to EnableTraceEx2 is
        //       > set by MAX_EVENT_FILTERS_COUNT
        params.array_of_event_filter_descriptor = filters
            .iter()
            .map(EventFilterDescriptor::as_event_filter_descriptor)
            .collect();
        // (let's assume we won't try to fit more than 4 billion filters)
        #[allow(clippy::cast_possible_truncation)]
        let filter_desc_count = params.array_of_event_filter_descriptor.len() as u32;
        params.native.FilterDescCount = filter_desc_count;
        if filters.is_empty() {
            params.native.EnableFilterDesc = std::ptr::null_mut();
        } else {
            params.native.EnableFilterDesc = params.array_of_event_filter_descriptor.as_mut_ptr();
        }

        params
    }

    /// Returns an unsafe pointer over the wrapped `ENABLE_TRACE_PARAMETERS`
    ///
    /// # Safety
    ///
    /// This pointer is valid as long `self` is valid (and not mutated)
    pub fn as_ptr(&self) -> *const Etw::ENABLE_TRACE_PARAMETERS {
        &raw const self.native
    }
}

/// Wrapper over the [DECODING_SOURCE] type
///
/// [DECODING_SOURCE]: https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-decoding_source
#[derive(Debug)]
pub enum DecodingSource {
    DecodingSourceXMLFile,
    DecodingSourceWbem,
    DecodingSourceWPP,
    DecodingSourceTlg,
    DecodingSourceMax,
}

impl From<Etw::DECODING_SOURCE> for DecodingSource {
    fn from(val: Etw::DECODING_SOURCE) -> Self {
        match val {
            Etw::DecodingSourceXMLFile => DecodingSource::DecodingSourceXMLFile,
            Etw::DecodingSourceWbem => DecodingSource::DecodingSourceWbem,
            Etw::DecodingSourceWPP => DecodingSource::DecodingSourceWPP,
            Etw::DecodingSourceTlg => DecodingSource::DecodingSourceTlg,
            _ => DecodingSource::DecodingSourceMax,
        }
    }
}

// Safe cast (EVENT_HEADER_FLAG_32_BIT_HEADER = 32)
#[doc(hidden)]
#[allow(clippy::cast_possible_truncation)]
pub const EVENT_HEADER_FLAG_32_BIT_HEADER: u16 = Etw::EVENT_HEADER_FLAG_32_BIT_HEADER as u16;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::trace::{TraceProperties, UserTrace};

    fn computed_flush_timer(flush_timer: Duration) -> u32 {
        let properties = TraceProperties {
            flush_timer,
            ..Default::default()
        };
        let etw_properties = EventTraceProperties::new::<UserTrace>(
            &U16CString::from_str("test-trace").unwrap(),
            None,
            &properties,
            Etw::EVENT_TRACE_FLAG::default(),
        );
        etw_properties.etw_trace_properties.FlushTimer
    }

    fn computed_client_context(clock_type: ClockType) -> u32 {
        let properties = TraceProperties {
            clock_type,
            ..Default::default()
        };
        let etw_properties = EventTraceProperties::new::<UserTrace>(
            &U16CString::from_str("test-trace").unwrap(),
            None,
            &properties,
            Etw::EVENT_TRACE_FLAG::default(),
        );
        etw_properties.etw_trace_properties.Wnode.ClientContext
    }

    #[test]
    fn clock_type_maps_to_its_native_value() {
        // WNODE_HEADER documentation: 1 = QPC, 2 = system time
        assert_eq!(computed_client_context(ClockType::Qpc), 1);
        assert_eq!(computed_client_context(ClockType::SystemTime), 2);
        // The Windows default (unset ClientContext behaves as QPC)
        assert_eq!(
            computed_client_context(TraceProperties::default().clock_type),
            1
        );
    }

    #[test]
    fn flush_timer_is_rounded_to_the_closest_second() {
        // 0 is translated as 1 second, as documented on TraceProperties
        assert_eq!(computed_flush_timer(Duration::from_secs(0)), 1);
        assert_eq!(computed_flush_timer(Duration::from_millis(400)), 1); // 0.4s
        assert_eq!(computed_flush_timer(Duration::from_secs(1)), 1);
        assert_eq!(computed_flush_timer(Duration::from_millis(1200)), 1); // 1.2s
        assert_eq!(computed_flush_timer(Duration::from_millis(1500)), 2); // 1.5s, rounds up
        assert_eq!(computed_flush_timer(Duration::from_secs(2)), 2);
        assert_eq!(computed_flush_timer(Duration::from_millis(2500)), 3); // 2.5s, rounds up
    }
}
