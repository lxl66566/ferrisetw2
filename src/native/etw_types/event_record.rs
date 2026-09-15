//! Safe wrappers over the EVENT_RECORD type

use windows::{Win32::System::Diagnostics::Etw::EVENT_RECORD, core::GUID};

use super::EVENT_HEADER_FLAG_32_BIT_HEADER;
use crate::native::{ExtendedDataItem, etw_types::extended_data::EventHeaderExtendedDataItem};

/// A read-only wrapper over an [EVENT_RECORD](https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record)
#[repr(transparent)]
pub struct EventRecord(pub(crate) EVENT_RECORD);

impl EventRecord {
    /// Create a `&self` from a Windows pointer.
    ///
    /// # Safety
    ///
    /// 1. Once an instance of `Self` is created, one should make sure the pointed data does not get
    ///    modified (or dealloc'ed).
    /// 2. The returned lifetime is arbitray. To restrict the use of the returned reference (and to
    ///    ensure the first safety guarantee), simply pass it to a sub-function whose signature has
    ///    no explicit lifetime. Thus, the sub-function will not be able to leak this reference.
    pub(crate) unsafe fn from_ptr<'a>(p: *const EVENT_RECORD) -> Option<&'a Self> {
        let s = p.cast::<Self>();
        // Safety: caller-guaranteed, see # Safety above
        unsafe { s.as_ref() }
    }

    /// Get the wrapped `EVENT_RECORD` (usually to feed Windows API functions)
    ///
    /// # Safety
    ///
    /// Obviously, the returned pointer is only valid as long `self` is valid and not modified.
    pub(crate) fn as_raw_ptr(&self) -> *const EVENT_RECORD {
        &raw const self.0
    }

    /// The `UserContext` field from the wrapped `EVENT_RECORD`
    ///
    /// In this crate, it is always populated to point to a valid
    /// [`CallbackData`](crate::trace::CallbackData)
    pub(crate) fn user_context(&self) -> *const std::ffi::c_void {
        self.0.UserContext.cast_const()
    }

    /// The `ProviderId` field from the wrapped `EVENT_RECORD`
    #[must_use]
    pub fn provider_id(&self) -> GUID {
        self.0.EventHeader.ProviderId
    }

    /// The `Id` field from the wrapped `EVENT_RECORD`
    #[must_use]
    pub fn event_id(&self) -> u16 {
        self.0.EventHeader.EventDescriptor.Id
    }

    /// The `Opcode` field from the wrapped `EVENT_RECORD`
    #[must_use]
    pub fn opcode(&self) -> u8 {
        self.0.EventHeader.EventDescriptor.Opcode
    }

    /// The `Version` field from the wrapped `EVENT_RECORD`
    #[must_use]
    pub fn version(&self) -> u8 {
        self.0.EventHeader.EventDescriptor.Version
    }

    /// The `Channel` field from the wrapped `EVENT_RECORD`
    ///
    /// Manifest-defined channel the event is written to (e.g. Admin, Operational, Analytic),
    /// see [ChannelType](https://docs.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-channeltype-complextype).
    /// `0` means the event is not written to any channel.
    #[must_use]
    pub fn channel(&self) -> u8 {
        self.0.EventHeader.EventDescriptor.Channel
    }

    /// The `Level` field from the wrapped `EVENT_RECORD`
    #[must_use]
    pub fn level(&self) -> u8 {
        self.0.EventHeader.EventDescriptor.Level
    }

    /// The `Task` field from the wrapped `EVENT_RECORD`
    ///
    /// Identifies the logical unit of work (manifest-defined) the event relates to,
    /// see [TaskType](https://docs.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-tasktype-complextype).
    /// `0` means the event does not specify a task.
    #[must_use]
    pub fn task(&self) -> u16 {
        self.0.EventHeader.EventDescriptor.Task
    }

    /// The `Keyword` field from the wrapped `EVENT_RECORD`
    #[must_use]
    pub fn keyword(&self) -> u64 {
        self.0.EventHeader.EventDescriptor.Keyword
    }

    /// The `Flags` field from the wrapped `EVENT_RECORD`
    #[must_use]
    pub fn event_flags(&self) -> u16 {
        self.0.EventHeader.Flags
    }

    /// The `ProcessId` field from the wrapped `EVENT_RECORD`
    #[must_use]
    pub fn process_id(&self) -> u32 {
        self.0.EventHeader.ProcessId
    }

    /// The `ThreadId` field from the wrapped `EVENT_RECORD`
    #[must_use]
    pub fn thread_id(&self) -> u32 {
        self.0.EventHeader.ThreadId
    }

    /// The `ActivityId` field from the wrapped `EVENT_RECORD`
    #[must_use]
    pub fn activity_id(&self) -> GUID {
        self.0.EventHeader.ActivityId
    }

    /// The `KernelTime` field from the wrapped `EVENT_RECORD`
    ///
    /// Elapsed execution time for kernel-mode instructions, in CPU time units, charged to the
    /// thread at the time of logging (compute deltas between consecutive events of a thread to
    /// measure CPU cost, see [Microsoft's remarks](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header#remarks)).
    ///
    /// Only meaningful when [`EventRecord::event_flags`] contains neither
    /// `EVENT_HEADER_FLAG_NO_CPUTIME` nor `EVENT_HEADER_FLAG_PRIVATE_SESSION`: the underlying
    /// union then holds a processor tick count instead, see [`EventRecord::processor_time`].
    #[must_use]
    pub fn kernel_time(&self) -> u32 {
        // Safety: union read of a plain u32, valid whatever the active union member
        unsafe { self.0.EventHeader.Anonymous.Anonymous.KernelTime }
    }

    /// The `UserTime` field from the wrapped `EVENT_RECORD`
    ///
    /// Elapsed execution time for user-mode instructions, in CPU time units. See
    /// [`EventRecord::kernel_time`] for the semantics and validity conditions.
    #[must_use]
    pub fn user_time(&self) -> u32 {
        // Safety: union read of a plain u32, valid whatever the active union member
        unsafe { self.0.EventHeader.Anonymous.Anonymous.UserTime }
    }

    /// The `ProcessorTime` member of the wrapped `EVENT_RECORD`'s union
    ///
    /// Elapsed execution time in CPU ticks. This is the active union member whenever
    /// [`EventRecord::event_flags`] contains `EVENT_HEADER_FLAG_NO_CPUTIME` or
    /// `EVENT_HEADER_FLAG_PRIVATE_SESSION`; for other events read
    /// [`EventRecord::kernel_time`]/[`EventRecord::user_time`] instead.
    #[must_use]
    pub fn processor_time(&self) -> u64 {
        // Safety: union read of a plain u64, valid whatever the active union member
        unsafe { self.0.EventHeader.Anonymous.ProcessorTime }
    }

    /// The `TimeStamp` field from the wrapped `EVENT_RECORD`
    ///
    /// As per [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header):
    /// > Contains the time that the event occurred.<br/>
    /// > The resolution is system time unless the `ProcessTraceMode member` of
    /// > `EVENT_TRACE_LOGFILE`
    /// > contains the `PROCESS_TRACE_MODE_RAW_TIMESTAMP` flag, in which case the resolution depends
    /// > on the value of the `Wnode.ClientContext` member of `EVENT_TRACE_PROPERTIES` at the time
    /// > the controller created the session.
    ///
    /// Note: the `time_rs` Cargo feature enables to convert this into strongly-typed values
    #[must_use]
    pub fn raw_timestamp(&self) -> i64 {
        self.0.EventHeader.TimeStamp
    }

    /// The `TimeStamp` field from the wrapped `EVENT_RECORD`, as a strongly-typed
    /// `time::OffsetDateTime`
    #[cfg(feature = "time_rs")]
    #[must_use]
    pub fn timestamp(&self) -> time::OffsetDateTime {
        crate::native::time::FileTime::from_quad(self.0.EventHeader.TimeStamp).into()
    }

    pub(crate) fn user_buffer(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0.UserData.cast(), self.0.UserDataLength.into()) }
    }

    pub(crate) fn pointer_size(&self) -> usize {
        if self.event_flags() & EVENT_HEADER_FLAG_32_BIT_HEADER != 0 {
            4
        } else {
            8
        }
    }

    /// Returns the `ExtendedData` from the ETW Event
    ///
    /// Their availability is mostly determined by the flags passed to
    /// [`Provider::trace_flags`](crate::provider::Provider::trace_flags)
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::EventRecord;
    /// # use ferrisetw::schema_locator::SchemaLocator;
    /// use windows::Win32::System::Diagnostics::Etw::EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID;
    ///
    /// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    ///     let activity_id = record
    ///         .extended_data()
    ///         .iter()
    ///         .find(|edata| edata.data_type() as u32 == EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID)
    ///         .map(|edata| edata.to_extended_data_item());
    /// };
    /// ```
    #[must_use]
    pub fn extended_data(&self) -> &[EventHeaderExtendedDataItem] {
        let n_extended_data = self.0.ExtendedDataCount;
        let p_ed_array = self.0.ExtendedData;
        if n_extended_data == 0 || p_ed_array.is_null() {
            return &[];
        }

        // Safety: * we're building a slice from an array pointer size given by Windows
        //         * the pointed data is not supposed to be mutated during the lifetime of `Self`
        unsafe {
            std::slice::from_raw_parts(
                p_ed_array as *const EventHeaderExtendedDataItem,
                n_extended_data as usize,
            )
        }
    }

    /// Returns the `eventName` for manifest-free events
    #[must_use]
    pub fn event_name(&self) -> String {
        if self.event_id() != 0 {
            return String::new();
        }

        if let Some(ExtendedDataItem::TraceLogging(name)) = self
            .extended_data()
            .iter()
            .find(|ext_data| ext_data.is_tlg())
            .map(EventHeaderExtendedDataItem::to_extended_data_item)
        {
            name
        } else {
            String::new()
        }
    }
}
