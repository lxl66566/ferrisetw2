//! Safe wrappers for the native ETW API
//!
//! This module makes sure the calls are safe memory-wise, but does not attempt to ensure they are
//! called in the right order.<br/> Thus, you should prefer using `UserTrace`s, `KernelTrace`s and
//! `TraceBuilder`s, that will ensure these API are correctly used.
use std::{
    collections::HashSet,
    ffi::c_void,
    panic::AssertUnwindSafe,
    sync::{Arc, RwLock},
};

use once_cell::sync::Lazy;
use widestring::U16CStr;
use windows::{
    Win32::{
        Foundation::{
            ERROR_ALREADY_EXISTS, ERROR_CTX_CLOSE_PENDING, ERROR_INSUFFICIENT_BUFFER,
            ERROR_SUCCESS, FILETIME,
        },
        System::Diagnostics::{
            Etw,
            Etw::{
                EVENT_CONTROL_CODE_CAPTURE_STATE, EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_FILTER_TYPE_STACKWALK,
                TRACE_QUERY_INFO_CLASS,
            },
        },
    },
    core::{GUID, PCWSTR},
};

use super::etw_types::*;
use crate::{
    native::etw_types::event_record::EventRecord,
    provider::{Provider, TraceFlags, event_filter::EventFilterDescriptor},
    trace::{
        ExtendedKernelGroup, RealTimeTraceTrait, StackTracingEvent, TraceProperties,
        callback_data::CallbackData,
    },
};

pub type TraceHandle = Etw::PROCESSTRACE_HANDLE;
pub type ControlHandle = Etw::CONTROLTRACE_HANDLE;

/// Evntrace native module errors
#[derive(Debug)]
pub enum EvntraceNativeError {
    /// Represents an Invalid Handle Error
    InvalidHandle,
    /// Represents an ERROR_ALREADY_EXISTS
    AlreadyExist,
    /// Represents an standard IO Error
    IoError(std::io::Error),
    /// A provider filter could not be built (e.g. empty, too large, or several
    /// filters of a type that may only appear once)
    InvalidFilter(String),
}

pub(crate) type EvntraceNativeResult<T> = Result<T, EvntraceNativeError>;

/// When a trace is closing, it is possible that every past events have not been processed yet.
/// These events will still be fed to the callback, **after** the trace has been closed
/// (see `ERROR_CTX_CLOSE_PENDING` in https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-closetrace#remarks)
/// Also, there is no way to tell which callback invocation is the last one.
///
/// But, we would like to free memory used by the callbacks when we're done!
/// Since that is not possible, let's discard every callback run after we've called `CloseTrace`.
/// That's the purpose of this set.
///
/// Note: this must remain an external, pointer-keyed registry: `is_valid` runs
/// when the pointed-to `CallbackData` may already be deallocated, so it is only
/// sound as long as it never dereferences the pointer. (e.g. an `AtomicBool`
/// embedded in `CallbackData` would be read after free)
///
/// TODO: it _might_ be possible to know whether we've processed the last buffered event.
///       `ControlTraceW(EVENT_TRACE_CONTROL_QUERY)` (see `RealTimeTraceTrait::statistics`)
///       and the buffer callback we install (see `buffer_callback_thunk`) both report
///       session statistics, but neither tells us when the last callback of a closing trace
///       has run, so callback memory is still discarded (rather than freed) after
///       `CloseTrace`. That's <https://github.com/n4r1b/ferrisetw/issues/62>
static UNIQUE_VALID_CONTEXTS: UniqueValidContexts = UniqueValidContexts::new();
struct UniqueValidContexts(Lazy<RwLock<HashSet<u64>>>);
enum ContextError {
    AlreadyExist,
}

impl UniqueValidContexts {
    pub const fn new() -> Self {
        Self(Lazy::new(|| RwLock::new(HashSet::new())))
    }

    /// Insert if it did not exist previously
    fn insert(&self, ctx_ptr: *const c_void) -> Result<(), ContextError> {
        if self.0.write().unwrap().insert(ctx_ptr as u64) {
            Ok(())
        } else {
            Err(ContextError::AlreadyExist)
        }
    }

    fn remove(&self, ctx_ptr: *const c_void) {
        self.0.write().unwrap().remove(&(ctx_ptr as u64));
    }

    pub fn is_valid(&self, ctx_ptr: *const c_void) -> bool {
        // Read lock: every event takes this once, and concurrent events (from
        // several ETW delivery threads) must not serialize on each other
        self.0.read().unwrap().contains(&(ctx_ptr as u64))
    }
}

/// This will be called by the ETW framework whenever an ETW event is available
extern "system" fn trace_callback_thunk(p_record: *mut Etw::EVENT_RECORD) {
    match std::panic::catch_unwind(AssertUnwindSafe(|| {
        let record_from_ptr = unsafe {
            // Safety: lifetime is valid at least until the end of the callback. A correct lifetime
            // will be attached when we pass the reference to the child function
            EventRecord::from_ptr(p_record)
        };

        if let Some(event_record) = record_from_ptr {
            let p_user_context = event_record.user_context();
            if !UNIQUE_VALID_CONTEXTS.is_valid(p_user_context) {
                return;
            }
            let p_callback_data = p_user_context.cast::<Arc<CallbackData>>();
            let callback_data = unsafe {
                // Safety:
                //  * the API of this create guarantees this points to a `CallbackData` already
                //    allocated and created
                //  * we've just checked using UNIQUE_VALID_CONTEXTS that this `CallbackData` has
                //    not been dropped
                //  * the API of this crate guarantees this `CallbackData` is not unsynchronizedly
                //    mutated from another thread during the trace:
                //      * we're the only one to change CallbackData::events_handled (and that's an
                //        atomic, so it's fine)
                //      * the provider registry may be mutated at any time (providers can be
                //        enabled/disabled while the trace runs, issue #54), but only under its
                //        RwLock, which `on_event` also takes (and it never holds it while running
                //        user callbacks)
                //      * the schema_locator only has interior mutability
                p_callback_data.as_ref()
            };
            if let Some(callback_data) = callback_data {
                // The UserContext is owned by the `Trace` object. When it is dropped, so will the
                // UserContext. We clone it now, so that the original Arc can be
                // safely dropped at all times, but the callback data (including the closure
                // captured context) will still be alive until the callback ends.
                let cloned_arc = Arc::clone(callback_data);
                cloned_arc.on_event(event_record);
            }
        }
    })) {
        Ok(()) => {},
        Err(e) => {
            log::error!("UNIMPLEMENTED PANIC: {e:?}");
            std::process::exit(1);
        },
    }
}

/// This will be called by the ETW framework after each buffer has been processed
///
/// The `BuffersRead` and `EventsLost` fields of the given log file are valid at this point:
/// they are recorded so that a running trace can be monitored for lost events (see
/// `TraceTrait::events_lost`)
extern "system" fn buffer_callback_thunk(p_logfile: *mut Etw::EVENT_TRACE_LOGFILEW) -> u32 {
    const TRUE: u32 = 1; // Keep processing buffers (FALSE would cancel the trace processing)
    match std::panic::catch_unwind(AssertUnwindSafe(|| {
        if p_logfile.is_null() {
            return TRUE;
        }
        let log_file = unsafe {
            // Safety: the pointer comes from the ETW framework, and is valid for the duration
            // of the callback. Windows reserves the right to modify its content, so it is
            // only read here, and never written to
            &*p_logfile
        };

        let p_user_context = log_file.Context;
        if !UNIQUE_VALID_CONTEXTS.is_valid(p_user_context) {
            return TRUE;
        }
        let p_callback_data = p_user_context.cast::<Arc<CallbackData>>();
        let callback_data = unsafe {
            // Safety: same soundness arguments as in `trace_callback_thunk`, plus the counters
            // written by `on_buffer` are atomics
            p_callback_data.as_ref()
        };
        if let Some(callback_data) = callback_data {
            let cloned_arc = Arc::clone(callback_data);
            cloned_arc.on_buffer(log_file.BuffersRead, log_file.EventsLost);
        }
        TRUE
    })) {
        Ok(result) => result,
        Err(e) => {
            log::error!("UNIMPLEMENTED PANIC: {e:?}");
            std::process::exit(1);
        },
    }
}

fn filter_invalid_trace_handles(h: TraceHandle) -> Option<TraceHandle> {
    // See https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew#return-value
    // We're conservative and we always filter out u32::MAX, although it could be valid on 64-bit
    // setups. But it turns out runtime detection of the current OS bitness is not that easy.
    // Plus, it is not clear whether this depends on how the architecture the binary is compiled
    // for, or the actual OS architecture.
    if h.Value == u64::MAX || h.Value == u64::from(u32::MAX) {
        None
    } else {
        Some(h)
    }
}

fn filter_invalid_control_handle(h: ControlHandle) -> Option<ControlHandle> {
    // The control handle is 0 if the handle is not valid.
    // (https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew)
    if h.Value == 0 {
        None
    } else {
        Some(h)
    }
}

/// Create a new session.
///
/// This builds an `EventTraceProperties`, calls `StartTraceW` and returns the built
/// `EventTraceProperties` as well as the trace ControlHandle
pub(crate) fn start_trace<T>(
    trace_name: &U16CStr,
    etl_dump_file: Option<(&U16CStr, DumpFileLoggingMode, Option<u32>)>,
    trace_properties: &TraceProperties,
    enable_flags: Etw::EVENT_TRACE_FLAG,
) -> EvntraceNativeResult<(EventTraceProperties, ControlHandle)>
where
    T: RealTimeTraceTrait,
{
    let mut properties =
        EventTraceProperties::new::<T>(trace_name, etl_dump_file, trace_properties, enable_flags);

    let mut control_handle = ControlHandle::default();
    let status = unsafe {
        // Safety:
        //  * first argument points to a valid and allocated address (this is an output and will be
        //    modified)
        //  * second argument is a valid, null terminated widestring (note that it will be copied to
        //    the EventTraceProperties...from where it already comes. This will probably be
        //    overwritten by Windows, but heck.)
        //  * third argument is a valid, allocated EVENT_TRACE_PROPERTIES (and will be mutated)
        //  * Note: the string (that will be overwritten to itself) ends with a null widechar before
        //    the end of its buffer (see EventTraceProperties::new())
        Etw::StartTraceW(
            &raw mut control_handle,
            PCWSTR::from_raw(properties.trace_name_array().as_ptr()),
            properties.as_mut_ptr(),
        )
    }
    .ok();

    if let Err(status) = status {
        let code = status.code();

        if code == ERROR_ALREADY_EXISTS.to_hresult() {
            return Err(EvntraceNativeError::AlreadyExist);
        } else if code != ERROR_SUCCESS.to_hresult() {
            return Err(EvntraceNativeError::IoError(
                std::io::Error::from_raw_os_error(code.0),
            ));
        }
    }

    match filter_invalid_control_handle(control_handle) {
        None => Err(EvntraceNativeError::InvalidHandle),
        Some(handle) => Ok((properties, handle)),
    }
}

/// Subscribe to a started trace
///
/// Microsoft calls this "opening" the trace (and this calls `OpenTraceW`)
#[allow(clippy::borrowed_box)] // Being Boxed is really important, let's keep the Box<...> in the function signature to make the intent clearer
pub(crate) fn open_trace(
    subscription_source: SubscriptionSource,
    callback_data: &Box<Arc<CallbackData>>,
) -> EvntraceNativeResult<TraceHandle> {
    let mut log_file = EventTraceLogfile::create(
        callback_data,
        subscription_source,
        trace_callback_thunk,
        buffer_callback_thunk,
    );

    if let Err(ContextError::AlreadyExist) = UNIQUE_VALID_CONTEXTS.insert(log_file.context_ptr()) {
        // Multiple consumers of the same session or ETL file are supported the
        // usual way: one `open_trace` (hence one context) per trace. Reusing a
        // single context for a second open is rejected on purpose: `close_trace`
        // removes the context from the validity registry, so the first close
        // would silently discard the other trace's callbacks. Supporting it
        // would require refcounted validity plus shared, address-stable
        // ownership of the CallbackData (the `Context` pointer must never
        // move), for no use case reachable through the public API.
        return Err(EvntraceNativeError::AlreadyExist);
    }

    let trace_handle = unsafe {
        // This function modifies the data pointed to by log_file.
        // This is fine because there is currently no other ref `self` (the current function takes a `&mut self`, and `self` is not used anywhere else in the current function)
        //
        // > On success, OpenTrace will update the structure with information from the opened file or session.
        // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracea
        Etw::OpenTraceW(log_file.as_mut_ptr())
    };

    if filter_invalid_trace_handles(trace_handle).is_none() {
        Err(EvntraceNativeError::IoError(std::io::Error::last_os_error()))
    } else {
        Ok(trace_handle)
    }
}

/// Builds the provider's filters into descriptors
///
/// Returns an error (rather than silently dropping the filter) if one of them
/// cannot be built: a user misspelling a filter (e.g. an empty list) would
/// otherwise get a trace that does not filter as requested, without any hint
fn build_event_filter_descriptors(
    provider: &Provider,
) -> EvntraceNativeResult<Vec<EventFilterDescriptor>> {
    // Note: > Each type of filter (a specific Type member) may only appear once
    //       in a call to the EnableTraceEx2 function.
    //       (https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks)
    let mut seen_types = HashSet::new();
    let mut descriptors = Vec::with_capacity(provider.filters().len());
    for filter in provider.filters() {
        let descriptor = filter
            .to_event_filter_descriptor()
            .map_err(|err| EvntraceNativeError::InvalidFilter(err.to_string()))?;
        if !seen_types.insert(descriptor.filter_type()) {
            return Err(EvntraceNativeError::InvalidFilter(format!(
                "several filters share the type {}; at most one filter of each type is allowed",
                descriptor.filter_type()
            )));
        }
        descriptors.push(descriptor);
    }
    Ok(descriptors)
}

/// Attach a provider to a trace
pub(crate) fn enable_provider(
    control_handle: ControlHandle,
    provider: &Provider,
) -> EvntraceNativeResult<()> {
    match filter_invalid_control_handle(control_handle) {
        None => Err(EvntraceNativeError::InvalidHandle),
        Some(handle) => {
            let owned_event_filter_descriptors = build_event_filter_descriptors(provider)?;

            // A stackwalk filter is inert unless the provider is enabled with
            // the STACK_TRACE property, so add it on the user's behalf
            // (https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor)
            let mut enable_property = provider.trace_flags();
            if owned_event_filter_descriptors
                .iter()
                .any(|d| d.filter_type() == EVENT_FILTER_TYPE_STACKWALK)
            {
                enable_property |= TraceFlags::EVENT_ENABLE_PROPERTY_STACK_TRACE;
            }

            let parameters = EnableTraceParameters::create(
                provider.guid(),
                enable_property,
                &owned_event_filter_descriptors,
            );

            let res = unsafe {
                Etw::EnableTraceEx2(
                    handle,
                    std::ptr::from_ref::<GUID>(&provider.guid()),
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                    provider.level(),
                    provider.any(),
                    provider.all(),
                    0,
                    Some(parameters.as_ptr()),
                )
            }
            .ok();

            res.map_err(|err| {
                EvntraceNativeError::IoError(std::io::Error::from_raw_os_error(err.code().0))
            })
        },
    }
}

/// Detach a provider from a trace
///
/// Sends `EVENT_CONTROL_CODE_DISABLE_PROVIDER` through `EnableTraceEx2`, so the
/// session stops collecting the provider's events. Level, keywords and filters
/// are irrelevant for a disable, so they are zeroed/not passed.
pub(crate) fn disable_provider(
    control_handle: ControlHandle,
    guid: GUID,
) -> EvntraceNativeResult<()> {
    match filter_invalid_control_handle(control_handle) {
        None => Err(EvntraceNativeError::InvalidHandle),
        Some(handle) => {
            let res = unsafe {
                // Safety:
                //  * the control handle is valid (by construction)
                //  * the provider GUID is a valid, readable GUID
                Etw::EnableTraceEx2(
                    handle,
                    std::ptr::from_ref::<GUID>(&guid),
                    EVENT_CONTROL_CODE_DISABLE_PROVIDER.0,
                    0,
                    0,
                    0,
                    0,
                    None,
                )
            }
            .ok();

            res.map_err(|err| {
                EvntraceNativeError::IoError(std::io::Error::from_raw_os_error(err.code().0))
            })
        },
    }
}

/// Ask a provider to log its current state (a.k.a. rundown)
///
/// Sends `EVENT_CONTROL_CODE_CAPTURE_STATE` to the provider. State-based
/// providers (e.g. those that can enumerate loaded images, open files or
/// handles) only emit their state upon this request.
///
/// The request carries no level, keyword or filter: it is a bare notification,
/// which is what such providers expect (same call shape as krabsetw).
pub(crate) fn capture_provider_state(
    control_handle: ControlHandle,
    provider: &Provider,
) -> EvntraceNativeResult<()> {
    match filter_invalid_control_handle(control_handle) {
        None => Err(EvntraceNativeError::InvalidHandle),
        Some(handle) => {
            let res = unsafe {
                // Safety:
                //  * the control handle is valid (by construction)
                //  * the provider GUID is a valid, readable GUID
                Etw::EnableTraceEx2(
                    handle,
                    std::ptr::from_ref::<GUID>(&provider.guid()),
                    EVENT_CONTROL_CODE_CAPTURE_STATE.0,
                    0,
                    0,
                    0,
                    0,
                    None,
                )
            }
            .ok();

            res.map_err(|err| {
                EvntraceNativeError::IoError(std::io::Error::from_raw_os_error(err.code().0))
            })
        },
    }
}

/// Start processing a trace (this call is blocking until the trace is stopped)
///
/// You probably want to spawn a thread that will block on this call.
pub(crate) fn process_trace(trace_handle: TraceHandle) -> EvntraceNativeResult<()> {
    if filter_invalid_trace_handles(trace_handle).is_none() {
        Err(EvntraceNativeError::InvalidHandle)
    } else {
        let result = unsafe {
            // We want to start processing events as soon as January 1601.
            // * for ETL file traces, this is fine, this means "process everything from the file"
            // * for real-time traces, this means we might process a few events already waiting in
            //   the buffers when the processing is starting. This is fine, I suppose.
            let mut start = FILETIME::default();
            Etw::ProcessTrace(&[trace_handle], Some(&raw mut start), None)
        }
        .ok();

        result.map_err(|err| {
            EvntraceNativeError::IoError(std::io::Error::from_raw_os_error(err.code().0))
        })
    }
}

/// Call `ControlTraceW` on the trace
///
/// # Notes
///
/// In case you want to stop the trace, you probably want to drop the instance rather than calling
/// `control(EVENT_TRACE_CONTROL_STOP)` yourself, because stop the trace makes the trace handle
/// invalid. A stopped trace could theoretically(?) be re-used, but the trace handle should be
/// re-created, so `open` should be called again.
pub(crate) fn control_trace(
    properties: &mut EventTraceProperties,
    control_handle: ControlHandle,
    control_code: Etw::EVENT_TRACE_CONTROL,
) -> EvntraceNativeResult<()> {
    match filter_invalid_control_handle(control_handle) {
        None => Err(EvntraceNativeError::InvalidHandle),
        Some(handle) => {
            let result = unsafe {
                // Safety:
                //  * the trace handle is valid (by construction)
                //  * depending on the control code, the `Properties` can be mutated. This is fine
                //    because properties is declared as `&mut` in this function, which means no
                //    other Rust function has a reference to it, and the mutation can only happen in
                //    the call to `ControlTraceW`, which returns immediately.
                Etw::ControlTraceW(
                    handle,
                    PCWSTR::null(),
                    properties.as_mut_ptr(),
                    control_code,
                )
            }
            .ok();

            result.map_err(|err| {
                EvntraceNativeError::IoError(std::io::Error::from_raw_os_error(err.code().0))
            })
        },
    }
}

/// Similar to [`control_trace`], but using a trace name instead of a handle
pub(crate) fn control_trace_by_name(
    properties: &mut EventTraceProperties,
    trace_name: &U16CStr,
    control_code: Etw::EVENT_TRACE_CONTROL,
) -> windows::core::Result<()> {
    unsafe {
        // Safety:
        //  * depending on the control code, the `Properties` can be mutated. This is fine because
        //    properties is declared as `&mut` in this function, which means no other Rust function
        //    has a reference to it, and the mutation can only happen in the call to
        //    `ControlTraceW`, which returns immediately.
        Etw::ControlTraceW(
            Etw::CONTROLTRACE_HANDLE { Value: 0 },
            PCWSTR::from_raw(trace_name.as_ptr()),
            properties.as_mut_ptr(),
            control_code,
        )
    }
    .ok()
}

/// Close the trace
///
/// It is suggested to stop the trace immediately after `close`ing it (that's what it done in the
/// `impl Drop`), because I'm not sure how sensible it is to call other methods (apart from `stop`)
/// afterwards
///
/// In case ETW reports there are still events in the queue that are still to trigger callbacks,
/// this returns Ok(true).<br/> If no further event callback will be invoked, this returns
/// Ok(false)<br/> On error, this returns an `Err`
#[allow(clippy::borrowed_box)] // Being Boxed is really important, let's keep the Box<...> in the function signature to make the intent clearer
pub(crate) fn close_trace(
    trace_handle: TraceHandle,
    callback_data: &Box<Arc<CallbackData>>,
) -> EvntraceNativeResult<bool> {
    match filter_invalid_trace_handles(trace_handle) {
        None => Err(EvntraceNativeError::InvalidHandle),
        Some(handle) => {
            // By contruction, only one Provider used this context in its callback. It is safe to
            // remove it, it won't be used by anyone else.
            UNIQUE_VALID_CONTEXTS
                .remove(std::ptr::from_ref(callback_data.as_ref()).cast::<c_void>());

            let status = unsafe { Etw::CloseTrace(handle) }.ok();

            match status {
                Ok(()) => Ok(false),
                Err(err) if err.code() == ERROR_CTX_CLOSE_PENDING.to_hresult() => Ok(true),
                Err(err) => Err(EvntraceNativeError::IoError(
                    std::io::Error::from_raw_os_error(err.code().0),
                )),
            }
        },
    }
}

fn win32_error(err: &windows::core::Error) -> EvntraceNativeError {
    EvntraceNativeError::IoError(std::io::Error::from_raw_os_error(err.code().0))
}

/// Calls `TraceQueryInformation`, returning its status along with the number of bytes
/// the API reports as needed (filled even when the call fails with a too-small buffer)
fn trace_query_raw(
    session: ControlHandle,
    class: TraceInformation,
    buf: &mut [u8],
) -> (windows::core::Result<()>, u32) {
    // Query buffers hold small fixed-size structs: cannot overflow a u32
    #[allow(clippy::cast_possible_truncation)]
    let buf_len = buf.len() as u32;
    let mut needed = 0u32;
    let result = unsafe {
        // Safety:
        //  * the buffer is valid for reads and writes over `buf_len` bytes
        //  * `needed` is a valid out-parameter
        Etw::TraceQueryInformation(
            session,
            TRACE_QUERY_INFO_CLASS(class as i32),
            buf.as_mut_ptr().cast(),
            buf_len,
            Some(&raw mut needed),
        )
    }
    .ok();

    (result, needed)
}

/// Queries the system for system-wide ETW information (that does not require an active session).
pub(crate) fn query_info(class: TraceInformation, buf: &mut [u8]) -> EvntraceNativeResult<()> {
    trace_query_raw(ControlHandle::default(), class, buf)
        .0
        .map_err(|err| win32_error(&err))
}

/// Queries a system-wide, variable-sized info class (an array of structures).
///
/// The ETW API is first called with `initial_capacity` bytes, then retried with the
/// size it reports as required. The returned buffer is truncated to the reported size.
pub(crate) fn query_array_info(
    class: TraceInformation,
    initial_capacity: usize,
) -> EvntraceNativeResult<Vec<u8>> {
    let mut capacity = initial_capacity;
    for _ in 0..4 {
        let mut buf = vec![0u8; capacity];
        let (result, needed) = trace_query_raw(ControlHandle::default(), class, &mut buf);
        match result {
            Ok(()) => {
                let written = (needed as usize).min(buf.len());
                buf.truncate(written);
                return Ok(buf);
            },
            Err(err) => {
                let required = needed as usize;
                if err.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() && required > capacity {
                    capacity = required;
                } else {
                    return Err(win32_error(&err));
                }
            },
        }
    }

    Err(EvntraceNativeError::IoError(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "the ETW API kept asking for a larger query buffer",
    )))
}

/// Calls `TraceSetInformation` on an active session
pub(crate) fn set_info(
    session: ControlHandle,
    class: TraceInformation,
    buf: &[u8],
) -> EvntraceNativeResult<()> {
    match filter_invalid_control_handle(session) {
        None => Err(EvntraceNativeError::InvalidHandle),
        Some(handle) => {
            // Set buffers hold small fixed-size structs: cannot overflow a u32
            #[allow(clippy::cast_possible_truncation)]
            let buf_len = buf.len() as u32;
            unsafe {
                // Safety:
                //  * the control handle is valid (checked above)
                //  * the buffer is valid for reads over `buf_len` bytes
                Etw::TraceSetInformation(
                    handle,
                    TRACE_QUERY_INFO_CLASS(class as i32),
                    buf.as_ptr().cast(),
                    buf_len,
                )
            }
            .ok()
            .map_err(|err| win32_error(&err))
        },
    }
}

/// Enables stack trace collection for the given kernel events
///
/// Kernel loggers ignore the `EVENT_ENABLE_PROPERTY_STACK_TRACE` flag of `EnableTraceEx2`:
/// `TraceSetInformation` with the `TraceStackTracingInfo` info class is the only way to get
/// call stacks out of them. Per the Windows SDK, the given list replaces any previous one,
/// so events absent from it lose their stacks.
pub(crate) fn enable_stack_tracing(
    control_handle: ControlHandle,
    events: &[StackTracingEvent],
) -> EvntraceNativeResult<()> {
    if events.is_empty() {
        return Ok(());
    }

    let event_ids: Vec<Etw::CLASSIC_EVENT_ID> = events
        .iter()
        .map(|event| Etw::CLASSIC_EVENT_ID {
            EventGuid: event.event_guid,
            Type: event.event_type,
            Reserved: [0; 7],
        })
        .collect();
    // SAFETY: CLASSIC_EVENT_ID is #[repr(C)] and all-integer (no padding), so this is a
    // valid byte view of the array, valid for reads as long as `event_ids` is alive
    let buf = unsafe {
        std::slice::from_raw_parts(event_ids.as_ptr().cast::<u8>(), size_of_val(&event_ids))
    };

    set_info(control_handle, TraceInformation::TraceStackTracingInfo, buf)
}

/// Enables the given extended kernel event groups, on top of the session's current ones
///
/// These groups cannot be expressed in `EVENT_TRACE_PROPERTIES::EnableFlags` (they do not fit
/// the classic 32-bit flag space). The call replaces the session's whole group mask, so the
/// current mask is first queried and merged into: this preserves the classic groups already
/// enabled through `EnableFlags` (same read-modify-write as krabsetw).
pub(crate) fn set_extended_kernel_groups(
    control_handle: ControlHandle,
    groups: &[ExtendedKernelGroup],
) -> EvntraceNativeResult<()> {
    if groups.is_empty() {
        return Ok(());
    }

    let mut buf = [0u8; size_of::<PerfinfoGroupmask>()];
    let (current, _) = trace_query_raw(
        control_handle,
        TraceInformation::TraceSystemTraceEnableFlagsInfo,
        &mut buf,
    );
    // An error here means the session (or OS, these need Windows 8+) does not support the
    // extended group mask: surface it rather than silently skipping the groups
    current.map_err(|err| win32_error(&err))?;
    let mut groupmask = PerfinfoGroupmask::from_bytes(&buf);
    groupmask.set_groups(groups);

    set_info(
        control_handle,
        TraceInformation::TraceSystemTraceEnableFlagsInfo,
        groupmask.as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::EventFilter;

    #[test]
    fn unbuidable_filters_are_reported() {
        // An empty PID list cannot become a filter: this must be an explicit
        // error, not a silently-ignored filter
        let provider = Provider::by_guid(GUID::new().unwrap())
            .add_filter(EventFilter::ByPids(vec![]))
            .build();

        assert!(matches!(
            build_event_filter_descriptors(&provider),
            Err(EvntraceNativeError::InvalidFilter(_))
        ));
    }

    #[test]
    fn valid_filters_are_all_built() {
        let provider = Provider::by_guid(GUID::new().unwrap())
            .add_filter(EventFilter::ByPids(vec![1234]))
            .add_filter(EventFilter::ByEventIds(vec![18]))
            .build();

        assert_eq!(build_event_filter_descriptors(&provider).unwrap().len(), 2);
    }

    #[test]
    fn filters_sharing_a_type_are_rejected() {
        // EnableTraceEx2 documentation: each filter type may only appear once,
        // otherwise the call fails
        let provider = Provider::by_guid(GUID::new().unwrap())
            .add_filter(EventFilter::ByEventIds(vec![18]))
            .add_filter(EventFilter::ByEventIds(vec![42]))
            .build();

        assert!(matches!(
            build_event_filter_descriptors(&provider),
            Err(EvntraceNativeError::InvalidFilter(_))
        ));
    }
}
