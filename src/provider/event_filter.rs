use std::{alloc::Layout, error::Error};

use windows::Win32::System::Diagnostics::Etw::{
    EVENT_FILTER_DESCRIPTOR, EVENT_FILTER_EVENT_ID, EVENT_FILTER_EVENT_NAME,
    EVENT_FILTER_TYPE_EVENT_ID, EVENT_FILTER_TYPE_EVENT_NAME, EVENT_FILTER_TYPE_EXECUTABLE_NAME,
    EVENT_FILTER_TYPE_PID, EVENT_FILTER_TYPE_STACKWALK, MAX_EVENT_FILTER_DATA_SIZE,
    MAX_EVENT_FILTER_EVENT_ID_COUNT, MAX_EVENT_FILTER_EVENT_NAME_SIZE, MAX_EVENT_FILTER_PID_COUNT,
};

/// Specifies how this provider will filter its events
///
/// Filters are enforced by ETW itself: filtered-out events are never delivered
/// to this process, which is much cheaper than filtering in callbacks.
///
/// Some filters are not effective prior to Windows 8.1 ([source](https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor#remarks))
#[derive(Debug)]
pub enum EventFilter {
    /// Filter by PID (a process identifier, i.e. a 32bit DWORD).
    /// This is only effective on kernel mode logger session.
    ByPids(Vec<u32>),
    /// Keep events with these ETW event IDs, drop the others.
    /// Ignored for TraceLogging providers (their events have no static IDs).
    ByEventIds(Vec<u16>),
    /// Drop events with these ETW event IDs, keep the others.
    /// Ignored for TraceLogging providers (their events have no static IDs).
    ExcludeEventIds(Vec<u16>),
    /// Keep events emitted from processes running one of these executable
    /// file names (e.g. `vec!["cmd.exe".into()]`), drop the others.
    ByExecutableNames(Vec<String>),
    /// Keep (or drop, see [`EventNamesFilter::exclude`]) TraceLogging events
    /// by name, optionally restricted by keyword and level.
    /// Ignored for non-TraceLogging providers (their events have no names).
    /// Not available prior to Windows 10 1709.
    ByEventNames(EventNamesFilter),
    /// Collect call stacks for events with these ETW event IDs.
    /// This crate automatically enables stack collection
    /// ([`TraceFlags::EVENT_ENABLE_PROPERTY_STACK_TRACE`](crate::provider::TraceFlags::EVENT_ENABLE_PROPERTY_STACK_TRACE))
    /// when this filter is present: without it, the filter would have no
    /// effect at all.
    /// Not available prior to Windows 10 1709.
    StackWalkByEventIds(Vec<u16>),
    /// Do not collect call stacks for events with these ETW event IDs, e.g. to
    /// silence a noisy event in an otherwise stack-traced provider. Stack
    /// collection is enabled automatically, see [`Self::StackWalkByEventIds`].
    /// Not available prior to Windows 10 1709.
    ExcludeStackWalkByEventIds(Vec<u16>),
}

impl EventFilter {
    /// Builds an EventFilterDescriptor (which can in turn generate an EVENT_FILTER_DESCRIPTOR)
    pub fn to_event_filter_descriptor(&self) -> Result<EventFilterDescriptor, Box<dyn Error>> {
        match self {
            EventFilter::ByPids(pids) => EventFilterDescriptor::try_new_by_process_ids(pids),
            EventFilter::ByEventIds(ids) => EventFilterDescriptor::try_new_by_event_id_list(
                ids,
                true,
                EVENT_FILTER_TYPE_EVENT_ID,
            ),
            EventFilter::ExcludeEventIds(ids) => EventFilterDescriptor::try_new_by_event_id_list(
                ids,
                false,
                EVENT_FILTER_TYPE_EVENT_ID,
            ),
            EventFilter::StackWalkByEventIds(ids) => {
                EventFilterDescriptor::try_new_by_event_id_list(
                    ids,
                    true,
                    EVENT_FILTER_TYPE_STACKWALK,
                )
            },
            EventFilter::ExcludeStackWalkByEventIds(ids) => {
                EventFilterDescriptor::try_new_by_event_id_list(
                    ids,
                    false,
                    EVENT_FILTER_TYPE_STACKWALK,
                )
            },
            EventFilter::ByExecutableNames(names) => {
                EventFilterDescriptor::try_new_by_executable_names(names)
            },
            EventFilter::ByEventNames(filter) => {
                EventFilterDescriptor::try_new_by_event_names(filter)
            },
        }
    }
}

/// Data for an event-name filter ([`EventFilter::ByEventNames`])
///
/// Describes the events the filter applies to: those whose name is one of
/// `names`, and — when the corresponding builder method is used — whose
/// keyword and level match. The matching events are kept by default, or
/// dropped after [`Self::exclude`].
///
/// # Example
/// ```
/// # use ferrisetw::provider::{EventFilter, EventNamesFilter, Provider};
/// let filter = EventFilter::ByEventNames(
///     EventNamesFilter::new(vec!["MyEventName".into()])
///         .any(0x1)    // only applies to events with keyword bit 0 set
///         .exclude(), // ... and drops them
/// );
/// Provider::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716")
///     .add_filter(filter)
///     .build();
/// ```
#[derive(Debug)]
pub struct EventNamesFilter {
    names: Vec<String>,
    match_any_keyword: u64,
    match_all_keyword: u64,
    level: u8,
    filter_in: bool,
}

impl EventNamesFilter {
    /// Filter on these event names
    #[must_use]
    pub fn new(names: Vec<String>) -> Self {
        Self {
            names,
            match_any_keyword: 0,
            match_all_keyword: 0,
            level: 0,
            filter_in: true,
        }
    }

    /// Restrict the filter to events with one of these keyword bits set.
    ///
    /// 0 (the default) means "regardless of keywords", like
    /// [`ProviderBuilder::any`](crate::provider::ProviderBuilder::any).
    #[must_use]
    pub fn any(mut self, any_keyword: u64) -> Self {
        self.match_any_keyword = any_keyword;
        self
    }

    /// Further restrict the filter to events with all of these keyword bits
    /// set (0, the default, means no extra restriction), like
    /// [`ProviderBuilder::all`](crate::provider::ProviderBuilder::all).
    #[must_use]
    pub fn all(mut self, all_keyword: u64) -> Self {
        self.match_all_keyword = all_keyword;
        self
    }

    /// Restrict the filter to events at this severity level or below, like
    /// [`ProviderBuilder::level`](crate::provider::ProviderBuilder::level).
    ///
    /// 0 (the default) means "regardless of level".
    #[must_use]
    pub fn level(mut self, level: u8) -> Self {
        self.level = level;
        self
    }

    /// Drop the matching events instead of keeping them
    #[must_use]
    pub fn exclude(mut self) -> Self {
        self.filter_in = false;
        self
    }
}

/// Similar to windows' `EVENT_FILTER_DESCRIPTOR`, but with owned data
///
/// See [`Self::as_event_filter_descriptor`] to get a Windows-rs-compatible type
#[derive(Debug)]
pub struct EventFilterDescriptor {
    data: *mut u8,
    layout: Layout,
    ty: u32,
}

impl EventFilterDescriptor {
    /// Allocates a new instance, where the included data is `data_size` bytes
    /// (no more than `max_size`: every filter type has its own size limit, see
    /// the `MAX_EVENT_FILTER_*` constants in evntprov.h), and is suitably
    /// aligned for type `T`
    fn try_new<T>(data_size: usize, max_size: u32) -> Result<Self, Box<dyn Error>> {
        if data_size == 0 {
            return Err("Filter must not be empty".into());
        }
        let Ok(size) = u32::try_from(data_size) else {
            return Err("Exceeded filter size limits".into());
        };
        if size > max_size {
            // See https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks
            return Err("Exceeded filter size limits".into());
        }

        let layout = Layout::from_size_align(size as usize, align_of::<T>())?;
        let data = unsafe {
            // Safety: layout size is non-zero
            std::alloc::alloc(layout)
        };
        if data.is_null() {
            return Err("Invalid allocation".into());
        }
        Ok(Self {
            data,
            layout,
            ty: 0,
        })
    }

    /// Build a new instance based on an `EVENT_FILTER_EVENT_ID` structure,
    /// which the event ID and stackwalk filter types share.
    ///
    /// `filter_in` selects whether the listed event IDs are kept or dropped
    /// (for stackwalk filters: whether their stacks are collected or not).
    ///
    /// Returns an `Err` in case the allocation failed, or if either zero or too
    /// many filter items were given
    fn try_new_by_event_id_list(
        eids: &[u16],
        filter_in: bool,
        ty: u32,
    ) -> Result<Self, Box<dyn Error>> {
        if eids.is_empty() {
            // Consistent with the other filters: an empty filter is a mistake
            return Err("Filter must not be empty".into());
        }
        if eids.len() > MAX_EVENT_FILTER_EVENT_ID_COUNT as usize {
            // See https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor
            return Err("Too many event IDs are filtered".into());
        }

        let data_size = size_of::<EVENT_FILTER_EVENT_ID>()
            + ((eids.len().saturating_sub(1)) * size_of::<u16>());
        let mut s = Self::try_new::<EVENT_FILTER_EVENT_ID>(data_size, MAX_EVENT_FILTER_DATA_SIZE)?;
        s.ty = ty;

        // Fill the data with an `EVENT_FILTER_EVENT_ID`
        // The allocation is aligned for EVENT_FILTER_EVENT_ID (see try_new)
        #[allow(clippy::cast_ptr_alignment)]
        let p = s.data.cast::<EVENT_FILTER_EVENT_ID>();
        // We've checked the array was less than 1024 items
        #[allow(clippy::cast_possible_truncation)]
        let count = eids.len() as u16;
        unsafe {
            (*p).FilterIn = filter_in;
            (*p).Reserved = 0;
            (*p).Count = count;
        }

        let evts = unsafe { std::slice::from_raw_parts_mut(&raw mut ((*p).Events[0]), eids.len()) };
        evts.copy_from_slice(eids);
        Ok(s)
    }

    /// Build a new instance that will filter by executable file name.
    ///
    /// Returns an `Err` in case the allocation failed, or if no name, an empty
    /// name, or too much data was given
    fn try_new_by_executable_names(names: &[String]) -> Result<Self, Box<dyn Error>> {
        if names.is_empty() {
            return Err("Filter must not be empty".into());
        }

        // Windows expects a single null-terminated UTF-16 string, where
        // several file names are separated by semicolons
        // (https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks)
        let mut wide_names = Vec::new();
        for (i, name) in names.iter().enumerate() {
            if name.is_empty() || name.contains(';') || name.contains('\0') {
                return Err("Executable names must not be empty, or contain ';' or NUL".into());
            }
            if i > 0 {
                wide_names.push(u16::from(b';'));
            }
            wide_names.extend(name.encode_utf16());
        }
        wide_names.push(0);

        // size_of_val on `&wide_names` would measure the Vec struct itself (3
        // pointers), not the string data: the copy below would then overflow
        // the allocation. Measure the slice instead.
        let data_size = size_of_val(wide_names.as_slice());
        let mut s = Self::try_new::<u16>(data_size, MAX_EVENT_FILTER_DATA_SIZE)?;
        s.ty = EVENT_FILTER_TYPE_EXECUTABLE_NAME;

        unsafe {
            // The allocation is aligned for u16 (see try_new)
            #[allow(clippy::cast_ptr_alignment)]
            let dst = s.data.cast::<u16>();
            std::ptr::copy_nonoverlapping(wide_names.as_ptr(), dst, wide_names.len());
        }
        Ok(s)
    }

    /// Build a new instance that will filter TraceLogging events by name.
    ///
    /// The data is an `EVENT_FILTER_EVENT_NAME` header followed by
    /// null-terminated UTF-8 names
    /// (https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_event_name)
    fn try_new_by_event_names(filter: &EventNamesFilter) -> Result<Self, Box<dyn Error>> {
        if filter.names.is_empty() {
            return Err("Filter must not be empty".into());
        }
        if filter
            .names
            .iter()
            .any(|name| name.is_empty() || name.contains('\0'))
        {
            return Err("Event names must not be empty, or contain NUL".into());
        }

        // Name-based filters are limited to MAX_EVENT_FILTER_EVENT_NAME_SIZE
        // bytes, as opposed to MAX_EVENT_FILTER_DATA_SIZE for most other types
        let header_size = std::mem::offset_of!(EVENT_FILTER_EVENT_NAME, Names);
        let names_size: usize = filter.names.iter().map(|name| name.len() + 1).sum();
        let mut s = Self::try_new::<EVENT_FILTER_EVENT_NAME>(
            header_size + names_size,
            MAX_EVENT_FILTER_EVENT_NAME_SIZE,
        )?;
        s.ty = EVENT_FILTER_TYPE_EVENT_NAME;

        // The allocation is aligned for EVENT_FILTER_EVENT_NAME (see try_new)
        #[allow(clippy::cast_ptr_alignment)]
        let p = s.data.cast::<EVENT_FILTER_EVENT_NAME>();
        // names_size is capped to 4096 bytes, and every name costs at least
        // 2 bytes, so the count always fits a u16
        #[allow(clippy::cast_possible_truncation)]
        let name_count = filter.names.len() as u16;
        unsafe {
            (*p).MatchAnyKeyword = filter.match_any_keyword;
            (*p).MatchAllKeyword = filter.match_all_keyword;
            (*p).Level = filter.level;
            (*p).FilterIn = filter.filter_in;
            (*p).NameCount = name_count;

            let mut dst = s.data.byte_add(header_size);
            for name in &filter.names {
                std::ptr::copy_nonoverlapping(name.as_ptr(), dst, name.len());
                dst = dst.add(name.len());
                *dst = 0; // names are null-terminated
                dst = dst.add(1);
            }
        }
        Ok(s)
    }

    /// Build a new instance that will filter by PIDs.
    ///
    /// Returns an `Err` in case the allocation failed, or if either zero or too many filter items
    /// were given
    fn try_new_by_process_ids(pids: &[u32]) -> Result<Self, Box<dyn Error>> {
        if pids.len() > MAX_EVENT_FILTER_PID_COUNT as usize {
            // See https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor
            return Err("Too many PIDs are filtered".into());
        }

        // PIDs are DWORDs (see EVENT_FILTER_DESCRIPTOR documentation: Ptr points
        // to "an array of process IDs", i.e. an array of DWORD)
        let data_size = size_of_val(pids);

        // try_new rejects data_size == 0, so pids cannot be empty here
        let mut s = Self::try_new::<u32>(data_size, MAX_EVENT_FILTER_DATA_SIZE)?;
        s.ty = EVENT_FILTER_TYPE_PID;

        // The allocation is aligned for u32 (see try_new)
        #[allow(clippy::cast_ptr_alignment)]
        let mut p = s.data.cast::<u32>();
        for pid in pids {
            unsafe {
                *p = *pid;
            };

            p = unsafe {
                // Safety:
                // * both the starting and resulting pointer are within the same allocated object
                //   (except for the very last item, but that will not be written to)
                // * thus, the offset is smaller than an isize
                p.add(1)
            };
        }

        Ok(s)
    }

    /// The `Type` of the EVENT_FILTER_DESCRIPTOR that will be generated
    ///
    /// Note that each filter type may only appear once per call to
    /// [EnableTraceEx2](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks)
    pub fn filter_type(&self) -> u32 {
        self.ty
    }

    /// Returns the EVENT_FILTER_DESCRIPTOR from this [`EventFilterDescriptor`]
    ///
    /// # Safety
    ///
    /// This will often be fed to an unsafe Windows function (e.g. [EnableTraceEx2](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2)).
    /// Note that this contains pointers to the current `EventFilterDescriptor`, that must remain
    /// valid until the called function is done.
    pub fn as_event_filter_descriptor(&self) -> EVENT_FILTER_DESCRIPTOR {
        EVENT_FILTER_DESCRIPTOR {
            Ptr: self.data as u64,
            // Filter sizes are capped at construction
            #[allow(clippy::cast_possible_truncation)]
            Size: self.layout.size() as u32,
            Type: self.ty,
        }
    }
}

impl Drop for EventFilterDescriptor {
    fn drop(&mut self) {
        unsafe {
            // Safety:
            // * ptr is a block of memory currently allocated via alloc::alloc
            // * layout is th one that was used to allocate that block of memory
            std::alloc::dealloc(self.data, self.layout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads back the EVENT_FILTER_EVENT_ID built from a filter
    fn event_id_list_parts(filter: &EventFilterDescriptor) -> (bool, u16, Vec<u16>) {
        let p = filter.as_event_filter_descriptor().Ptr as *const EVENT_FILTER_EVENT_ID;
        // Safety: `filter` owns an EVENT_FILTER_EVENT_ID-shaped allocation
        let header = unsafe { *p };
        let events = unsafe {
            std::slice::from_raw_parts((*p).Events.as_ptr(), header.Count as usize).to_vec()
        };
        (header.FilterIn, header.Count, events)
    }

    #[test]
    fn event_id_filters_carry_filter_in_and_type() {
        let include = EventFilter::ByEventIds(vec![18, 42])
            .to_event_filter_descriptor()
            .unwrap();
        assert_eq!(include.filter_type(), EVENT_FILTER_TYPE_EVENT_ID);
        assert_eq!(event_id_list_parts(&include), (true, 2, vec![18, 42]));

        let exclude = EventFilter::ExcludeEventIds(vec![7])
            .to_event_filter_descriptor()
            .unwrap();
        assert_eq!(exclude.filter_type(), EVENT_FILTER_TYPE_EVENT_ID);
        assert_eq!(event_id_list_parts(&exclude), (false, 1, vec![7]));
    }

    #[test]
    fn stackwalk_filters_use_the_same_layout_but_their_own_type() {
        let include = EventFilter::StackWalkByEventIds(vec![3])
            .to_event_filter_descriptor()
            .unwrap();
        assert_eq!(include.filter_type(), EVENT_FILTER_TYPE_STACKWALK);
        assert_eq!(event_id_list_parts(&include), (true, 1, vec![3]));

        let exclude = EventFilter::ExcludeStackWalkByEventIds(vec![4])
            .to_event_filter_descriptor()
            .unwrap();
        assert_eq!(exclude.filter_type(), EVENT_FILTER_TYPE_STACKWALK);
        assert_eq!(event_id_list_parts(&exclude), (false, 1, vec![4]));
    }

    #[test]
    fn empty_event_id_lists_are_rejected() {
        assert!(
            EventFilter::ByEventIds(vec![])
                .to_event_filter_descriptor()
                .is_err()
        );
        assert!(
            EventFilter::StackWalkByEventIds(vec![])
                .to_event_filter_descriptor()
                .is_err()
        );
    }

    #[test]
    fn executable_names_are_semicolon_separated_utf16() {
        let filter = EventFilter::ByExecutableNames(vec!["cmd.exe".into(), "pwsh.exe".into()])
            .to_event_filter_descriptor()
            .expect("allocation should succeed");

        let native = filter.as_event_filter_descriptor();
        assert_eq!(native.Type, EVENT_FILTER_TYPE_EXECUTABLE_NAME);
        // "cmd.exe;pwsh.exe\0", 2 bytes per UTF-16 code unit
        let expected: Vec<u16> = "cmd.exe;pwsh.exe\0".encode_utf16().collect();
        assert_eq!(native.Size as usize, size_of_val(expected.as_slice()));

        // Safety: `native.Ptr`/`native.Size` describe the allocation owned by
        // `filter`, which outlives this read
        let data = unsafe {
            std::slice::from_raw_parts(native.Ptr as *const u16, native.Size as usize / 2)
        };
        assert_eq!(data, expected);
    }

    #[test]
    fn executable_name_filters_reject_bad_input() {
        let build = |names: &[&str]| {
            EventFilter::ByExecutableNames(names.iter().map(|n| (*n).to_string()).collect())
                .to_event_filter_descriptor()
        };
        assert!(build(&[]).is_err());
        assert!(build(&[""]).is_err());
        assert!(build(&["a;b"]).is_err());
        assert!(build(&["a\0b"]).is_err());
        assert!(build(&[&"x".repeat(2000)]).is_err()); // > MAX_EVENT_FILTER_DATA_SIZE
    }

    #[test]
    fn event_name_filters_have_header_and_utf8_names() {
        let filter = EventFilter::ByEventNames(
            EventNamesFilter::new(vec!["MyEvent".into(), "Other".into()])
                .any(0xff00)
                .all(0x0011)
                .level(4),
        )
        .to_event_filter_descriptor()
        .expect("allocation should succeed");

        let native = filter.as_event_filter_descriptor();
        assert_eq!(native.Type, EVENT_FILTER_TYPE_EVENT_NAME);

        let expected_names = b"MyEvent\0Other\0";
        assert_eq!(
            native.Size as usize,
            std::mem::offset_of!(EVENT_FILTER_EVENT_NAME, Names) + expected_names.len()
        );

        // Safety: `native.Ptr`/`native.Size` describe the allocation owned by
        // `filter`, which outlives this read
        let header = unsafe { *(native.Ptr as *const EVENT_FILTER_EVENT_NAME) };
        assert_eq!(header.MatchAnyKeyword, 0xff00);
        assert_eq!(header.MatchAllKeyword, 0x0011);
        assert_eq!(header.Level, 4);
        assert!(header.FilterIn);
        assert_eq!(header.NameCount, 2);

        let names = unsafe {
            std::slice::from_raw_parts(
                (native.Ptr as *const u8)
                    .byte_add(std::mem::offset_of!(EVENT_FILTER_EVENT_NAME, Names)),
                expected_names.len(),
            )
        };
        assert_eq!(names, expected_names);
    }

    #[test]
    fn event_name_filters_can_exclude() {
        let filter =
            EventFilter::ByEventNames(EventNamesFilter::new(vec!["MyEvent".into()]).exclude())
                .to_event_filter_descriptor()
                .unwrap();

        let native = filter.as_event_filter_descriptor();
        // Safety: same-owned-allocation read as in the other tests
        let header = unsafe { *(native.Ptr as *const EVENT_FILTER_EVENT_NAME) };
        assert!(!header.FilterIn);
    }

    #[test]
    fn event_name_filters_reject_bad_input() {
        assert!(
            EventFilter::ByEventNames(EventNamesFilter::new(vec![]))
                .to_event_filter_descriptor()
                .is_err()
        );
        assert!(
            EventFilter::ByEventNames(EventNamesFilter::new(vec!["a\0b".into()]))
                .to_event_filter_descriptor()
                .is_err()
        );
        // > MAX_EVENT_FILTER_EVENT_NAME_SIZE, even though that limit is larger
        // than the generic one
        assert!(
            EventFilter::ByEventNames(EventNamesFilter::new(vec!["x".repeat(5000)]))
                .to_event_filter_descriptor()
                .is_err()
        );
    }

    #[test]
    fn pid_filter_uses_dword_sized_pids() {
        let pids = [0x1234_5678u32, 0x09ab_cdef];
        let filter = EventFilterDescriptor::try_new_by_process_ids(&pids)
            .expect("allocation should succeed");

        let native = filter.as_event_filter_descriptor();
        assert_eq!(native.Type, EVENT_FILTER_TYPE_PID);
        // PIDs are DWORDs (4 bytes each), not WORDs
        assert_eq!(
            native.Size,
            u32::try_from(pids.len() * size_of::<u32>()).unwrap()
        );

        // Safety: `native.Ptr`/`native.Size` describe the allocation owned by `filter`,
        // which outlives this read
        let data =
            unsafe { std::slice::from_raw_parts(native.Ptr as *const u8, native.Size as usize) };
        assert_eq!(&data[..4], 0x1234_5678u32.to_ne_bytes());
        assert_eq!(&data[4..], 0x09ab_cdefu32.to_ne_bytes());
    }

    #[test]
    fn pid_filter_rejects_empty_and_too_many_pids() {
        assert!(EventFilterDescriptor::try_new_by_process_ids(&[]).is_err());

        let too_many = vec![1u32; MAX_EVENT_FILTER_PID_COUNT as usize + 1];
        assert!(EventFilterDescriptor::try_new_by_process_ids(&too_many).is_err());
    }

    #[test]
    fn event_ids_filter_has_correct_type_and_size() {
        let filter = EventFilterDescriptor::try_new_by_event_id_list(
            &[18, 42],
            true,
            EVENT_FILTER_TYPE_EVENT_ID,
        )
        .expect("allocation should succeed");

        let native = filter.as_event_filter_descriptor();
        assert_eq!(native.Type, EVENT_FILTER_TYPE_EVENT_ID);
        // sizeof(EVENT_FILTER_EVENT_ID) already includes one event id,
        // each additional one adds a u16
        let header_size = size_of::<EVENT_FILTER_EVENT_ID>();
        assert_eq!(native.Size as usize, header_size + size_of::<u16>());
    }
}
