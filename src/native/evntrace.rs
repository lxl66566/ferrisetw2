//! Safe wrappers for the native ETW API
//!
//! This module makes sure the calls are safe memory-wise, but does not attempt to ensure they are
//! called in the right order.<br/> Thus, you should prefer using `UserTrace`s, `KernelTrace`s and
//! `TraceBuilder`s, that will ensure these API are correctly used.
use std::{
    collections::HashSet,
    ffi::c_void,
    panic::AssertUnwindSafe,
    sync::{
        Arc, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use once_cell::sync::Lazy;
use rustc_hash::FxHashMap;
use widestring::U16CStr;
use windows::{
    Win32::{
        Foundation::{
            ERROR_ALREADY_EXISTS, ERROR_CANCELLED, ERROR_CTX_CLOSE_PENDING,
            ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, FILETIME, WIN32_ERROR,
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

/// Registry of the callback context of every open trace
///
/// When a trace is closing, it is possible that every past events have not been processed yet.
/// These events will still be fed to the callback, **after** the trace has been closed
/// (see `ERROR_CTX_CLOSE_PENDING` in https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-closetrace#remarks)
/// Also, there is no way to tell which callback invocation is the last one.
///
/// But, we would like to free memory used by the callbacks when we're done!
/// The registry owns an `Arc` clone of every registered `CallbackData`, and the callbacks
/// resolve their context through a single locked lookup, which validates the id and
/// hands out an owned `Arc` clone in one step (`ContextRegistry::get`):
/// * a callback that runs after `close_trace` removed the entry misses and drops the event
/// * a callback that already got its `Arc` keeps the data alive, whatever the closing thread does
///   in between (closing a trace while a callback is in flight is the normal case, not a race to
///   defend against)
/// * the data is freed by the last live `Arc` (registry entry, `Trace`, in-flight callbacks), which
///   settles the memory-management half of <https://github.com/n4r1b/ferrisetw/issues/62> without
///   waiting for the last buffered event
///
/// The context id is only ever compared to the keys, never dereferenced (it is not even a
/// pointer, see `TraceContextId`), so the lookup cannot race a free.
///
/// Lock hierarchy: this registry is a leaf lock. It never nests with the provider registry's
/// `RwLock` nor with the session-mutations `Mutex`: callbacks clone the `Arc` and release it
/// before dispatching (so `on_event` never runs under it), and `open_trace`/`close_trace`
/// hold it alone, never across an OS call.
static CONTEXT_REGISTRY: ContextRegistry = ContextRegistry::new();
struct ContextRegistry(Lazy<RwLock<FxHashMap<usize, Arc<CallbackData>>>>);

impl ContextRegistry {
    pub const fn new() -> Self {
        Self(Lazy::new(|| RwLock::new(FxHashMap::default())))
    }

    fn insert(&self, id: TraceContextId, callback_data: Arc<CallbackData>) {
        self.0.write().unwrap().insert(id.0, callback_data);
    }

    fn remove(&self, id: TraceContextId) {
        self.0.write().unwrap().remove(&id.0);
    }

    /// Resolve a context id handed back by the ETW framework into an owned `Arc` clone of
    /// the callback data, validating the id and keeping the data alive in one step
    ///
    /// Read lock: every event takes this once, and concurrent events (from several ETW
    /// delivery threads) must not serialize on each other
    pub fn get(&self, id: TraceContextId) -> Option<Arc<CallbackData>> {
        self.0.read().unwrap().get(&id.0).cloned()
    }
}

/// The unique identity of one open trace, handed to the ETW APIs as their `Context`
///
/// The ETW framework round-trips this value opaquely: the `Context` of the
/// `EVENT_TRACE_LOGFILEW` comes back as the `UserContext` of every `EVENT_RECORD` delivered
/// for that trace. It is a registry key, not a pointer: it is only ever compared (see
/// [`CONTEXT_REGISTRY`]), never dereferenced.
///
/// Ids come from a process-wide counter and are never reused: once a trace is closed, its id
/// is retired, so a stale event of a closed trace can only ever miss the registry — even if
/// the allocator hands a newer trace the memory just freed by the older one (an id scheme is
/// what rules this ABA misrouting out; keys taken from allocated addresses could not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TraceContextId(usize);

/// Backing counter of [`TraceContextId`]: starts at 1, so ids are never null
static NEXT_CONTEXT_ID: AtomicUsize = AtomicUsize::new(1);

impl TraceContextId {
    fn mint() -> Self {
        Self(NEXT_CONTEXT_ID.fetch_add(1, Ordering::Relaxed))
    }

    /// Rebuild the id from the `UserContext` the ETW framework handed back
    fn from_user_context(user_context: *const c_void) -> Self {
        Self(user_context.addr())
    }

    /// The value to store in `EVENT_TRACE_LOGFILEW::Context`
    pub(crate) fn as_user_context(self) -> *mut c_void {
        // The id is never dereferenced (not by ETW, not by this crate): a bare
        // integer-to-pointer conversion is exactly what is needed here
        std::ptr::with_exposed_provenance_mut(self.0)
    }
}

/// The registered context of an open trace: its unique [`TraceContextId`], plus the `Arc`
/// keeping its [`CallbackData`] alive
///
/// The registry holds its own clone of the `Arc` while this is registered: ETW callbacks
/// resolve their `UserContext` through [`CONTEXT_REGISTRY`] and dispatch on their own clone.
/// Dropping this unregisters the id, so a `TraceContext` must stay owned by the trace until
/// `close_trace` ran.
// `pub` within a `pub(crate)` module, like `CallbackData`: it only crosses private signatures
#[derive(Debug)]
pub struct TraceContext {
    id: TraceContextId,
    data: Arc<CallbackData>,
}

impl TraceContext {
    /// Register a freshly built callback data for dispatch, minting its unique context id
    pub(crate) fn new(callback_data: Arc<CallbackData>) -> Self {
        let id = TraceContextId::mint();
        CONTEXT_REGISTRY.insert(id, Arc::clone(&callback_data));
        Self {
            id,
            data: callback_data,
        }
    }

    /// The id handed to the ETW APIs for this trace
    pub(crate) fn id(&self) -> TraceContextId {
        self.id
    }

    /// Retire the context: callbacks resolving it from now on drop their event
    fn unregister(&self) {
        CONTEXT_REGISTRY.remove(self.id);
    }
}

impl Drop for TraceContext {
    fn drop(&mut self) {
        // `close_trace` already unregistered this context, but a `start()` that fails
        // between `open_trace` and the actual `build` drops the context without a close
        self.unregister();
    }
}

impl std::ops::Deref for TraceContext {
    type Target = CallbackData;

    fn deref(&self) -> &CallbackData {
        &self.data
    }
}

/// This will be called by the ETW framework whenever an ETW event is available
///
/// The user callbacks dispatched here run across the FFI boundary, on a delivery thread
/// owned by Windows: a panic must not unwind into the ETW framework, as unwinding into
/// `extern "system"` native code is undefined behavior. Panics are therefore caught, and
/// since a callback that panicked midway may have left the subscriber's state
/// inconsistent, the process is terminated with exit code 1 (see the crate-level
/// "Callback panics" section) rather than silently dropping the following events.
extern "system" fn trace_callback_thunk(p_record: *mut Etw::EVENT_RECORD) {
    match std::panic::catch_unwind(AssertUnwindSafe(|| {
        let record_from_ptr = unsafe {
            // Safety: lifetime is valid at least until the end of the callback. A correct lifetime
            // will be attached when we pass the reference to the child function
            EventRecord::from_ptr(p_record)
        };

        if let Some(event_record) = record_from_ptr {
            // The locked lookup validates the context and hands out an owned `Arc` in one
            // step: from here on, the callback data is owned by this callback, and neither
            // `close_trace` nor dropping the whole `Trace` can free it while it runs. The
            // `UserContext` is a registry key, and is only ever compared, never
            // dereferenced.
            let context = TraceContextId::from_user_context(event_record.user_context());
            if let Some(callback_data) = CONTEXT_REGISTRY.get(context) {
                callback_data.on_event(event_record);
            }
        }
    })) {
        Ok(()) => {},
        Err(e) => {
            log::error!("a user callback panicked, terminating the process: {e:?}");
            std::process::exit(1);
        },
    }
}

/// This will be called by the ETW framework after each buffer has been processed
///
/// The `BuffersRead` field of the given log file is valid at this point. `EventsLost` is
/// recorded too, but the Windows documentation marks it as "not used": the resulting
/// `TraceTrait::events_lost` counter usually stays at 0, and loss monitoring should rely on
/// the session-side statistics instead
///
/// Like `trace_callback_thunk`, this must never unwind into Windows: a panic here
/// terminates the process (see the crate-level "Callback panics" section).
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

        // The locked lookup validates the context and hands out an owned `Arc` in one
        // step (see `trace_callback_thunk`: neither `close_trace` nor dropping the
        // `Trace` can free the callback data while this callback runs)
        let context = TraceContextId::from_user_context(log_file.Context);
        if let Some(callback_data) = CONTEXT_REGISTRY.get(context) {
            callback_data.on_buffer(log_file.BuffersRead, log_file.EventsLost);
        }
        TRUE
    })) {
        Ok(result) => result,
        Err(e) => {
            log::error!("the buffer callback panicked, terminating the process: {e:?}");
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
    };

    match status {
        ERROR_SUCCESS => {},
        ERROR_ALREADY_EXISTS => return Err(EvntraceNativeError::AlreadyExist),
        other => return Err(win32_error(other)),
    }

    match filter_invalid_control_handle(control_handle) {
        None => Err(EvntraceNativeError::InvalidHandle),
        Some(handle) => Ok((properties, handle)),
    }
}

/// Subscribe to a started trace
///
/// Microsoft calls this "opening" the trace (and this calls `OpenTraceW`)
///
/// On success, the returned [`TraceContext`] must stay owned (and be passed to
/// [`close_trace`]) for as long as the trace handle is open: dropping it retires the
/// context, and the thunks would drop every event of the trace.
pub(crate) fn open_trace(
    subscription_source: SubscriptionSource,
    callback_data: Arc<CallbackData>,
) -> EvntraceNativeResult<(TraceHandle, TraceContext)> {
    // Register the context before opening: the thunks of this handle will resolve their
    // `UserContext` through it. The registry keeps its own `Arc` clone, so the data
    // outlives the closing of the trace if a callback is in flight. Several consumers of
    // the same session or ETL file each get their own context (one `open_trace` each), so
    // closing one never discards the callbacks of the other.
    let context = TraceContext::new(callback_data);
    let mut log_file = EventTraceLogfile::create(
        context.id(),
        subscription_source,
        trace_callback_thunk,
        buffer_callback_thunk,
    );

    let trace_handle = unsafe {
        // This function modifies the data pointed to by log_file.
        // This is fine because there is currently no other ref `self` (the current function takes a `&mut self`, and `self` is not used anywhere else in the current function)
        //
        // > On success, OpenTrace will update the structure with information from the opened file or session.
        // https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracea
        Etw::OpenTraceW(log_file.as_mut_ptr())
    };

    if filter_invalid_trace_handles(trace_handle).is_none() {
        // The trace never ran: dropping the context unregisters it (ids are never
        // reused, so this is only hygiene against an unbounded registry)
        Err(EvntraceNativeError::IoError(std::io::Error::last_os_error()))
    } else {
        Ok((trace_handle, context))
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

            let parameters =
                EnableTraceParameters::create(enable_property, &owned_event_filter_descriptors);

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
            };

            win32_result(res)
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
            };

            win32_result(res)
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
            };

            win32_result(res)
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
        let status = unsafe {
            // We want to start processing events as soon as January 1601.
            // * for ETL file traces, this is fine, this means "process everything from the file"
            // * for real-time traces, this means we might process a few events already waiting in
            //   the buffers when the processing is starting. This is fine, I suppose.
            let mut start = FILETIME::default();
            Etw::ProcessTrace(&[trace_handle], Some(&raw mut start), None)
        };

        process_trace_status(status)
    }
}

/// Interpret the exit status of `ProcessTrace`
///
/// When the trace is stopped (explicitly, or by dropping it), or its handle is
/// closed, `ProcessTrace` ends with `ERROR_CANCELLED`: that is the normal end
/// of the processing loop, not an error. This crate's buffer callback always
/// returns TRUE, so `ERROR_CANCELLED` can only ever mean that normal
/// termination here.
fn process_trace_status(status: WIN32_ERROR) -> EvntraceNativeResult<()> {
    if status.is_ok() || status == ERROR_CANCELLED {
        Ok(())
    } else {
        Err(win32_error(status))
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
            let status = unsafe {
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
            };

            win32_result(status)
        },
    }
}

/// Similar to [`control_trace`], but using a trace name instead of a handle
///
/// Returns the raw `WIN32_ERROR` on failure: some callers special-case
/// particular codes (e.g. `ERROR_WMI_INSTANCE_NOT_FOUND` means "nothing to
/// stop" for `stop_trace_by_name`)
pub(crate) fn control_trace_by_name(
    properties: &mut EventTraceProperties,
    trace_name: &U16CStr,
    control_code: Etw::EVENT_TRACE_CONTROL,
) -> Result<(), WIN32_ERROR> {
    let status = unsafe {
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
    };
    if status.is_ok() {
        Ok(())
    } else {
        Err(status)
    }
}

/// Close the trace
///
/// It is suggested to stop the trace immediately after `close`ing it (that's what it done in the
/// `impl Drop`), because I'm not sure how sensible it is to call other methods (apart from `stop`)
/// afterwards
///
/// Returns `Ok(true)` when the close is pending because events are still queued in the consumer
/// session (`ERROR_CTX_CLOSE_PENDING`), `Ok(false)` when no further event will be processed. Those
/// queued events still reach the thunks, but the context is retired before the close, so they are
/// dropped instead of dispatched; callbacks already in flight keep running on their own `Arc`
/// clone (see the module-level documentation). On error, this returns an `Err`
pub(crate) fn close_trace(
    trace_handle: TraceHandle,
    context: &TraceContext,
) -> EvntraceNativeResult<bool> {
    match filter_invalid_trace_handles(trace_handle) {
        None => Err(EvntraceNativeError::InvalidHandle),
        Some(handle) => {
            // Retire the context before the close: the events still queued will still
            // trigger the thunks, which must miss the registry and drop them. Callbacks
            // already in flight keep their own `Arc` clone (see `CONTEXT_REGISTRY`).
            context.unregister();

            let status = unsafe { Etw::CloseTrace(handle) };

            match status {
                ERROR_SUCCESS => Ok(false),
                // Events are still queued: they will reach the thunks, which
                // drop them (the context is already retired)
                ERROR_CTX_CLOSE_PENDING => Ok(true),
                other => Err(win32_error(other)),
            }
        },
    }
}

/// Convert a bare `WIN32_ERROR` — the return type of every ETW control API —
/// into the crate error
///
/// Do not route this through `WIN32_ERROR::ok()` and its `windows::core::Error`:
/// that wraps the code into an `HRESULT_FROM_WIN32` (0x8007xxxx), which
/// `io::Error::from_raw_os_error` would take at face value (e.g. os error
/// -2147024713 instead of 183 for `ERROR_ALREADY_EXISTS`), losing every
/// `ErrorKind` mapping.
#[allow(clippy::cast_possible_wrap)] // Win32 error codes always fit in an i32
pub(crate) fn win32_error(status: WIN32_ERROR) -> EvntraceNativeError {
    EvntraceNativeError::IoError(std::io::Error::from_raw_os_error(status.0 as i32))
}

/// [`win32_error`], unless `status` is `ERROR_SUCCESS`
pub(crate) fn win32_result(status: WIN32_ERROR) -> EvntraceNativeResult<()> {
    if status.is_ok() {
        Ok(())
    } else {
        Err(win32_error(status))
    }
}

/// Calls `TraceQueryInformation`, returning its status along with the number of bytes
/// the API reports as needed (filled even when the call fails with a too-small buffer)
fn trace_query_raw(
    session: ControlHandle,
    class: TraceInformation,
    buf: &mut [u8],
) -> (WIN32_ERROR, u32) {
    // Query buffers hold small fixed-size structs: cannot overflow a u32
    #[allow(clippy::cast_possible_truncation)]
    let buf_len = buf.len() as u32;
    let mut needed = 0u32;
    let status = unsafe {
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
    };

    (status, needed)
}

/// Queries the system for system-wide ETW information (that does not require an active session).
pub(crate) fn query_info(class: TraceInformation, buf: &mut [u8]) -> EvntraceNativeResult<()> {
    let (status, _) = trace_query_raw(ControlHandle::default(), class, buf);
    win32_result(status)
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
        let (status, needed) = trace_query_raw(ControlHandle::default(), class, &mut buf);
        match status {
            ERROR_SUCCESS => {
                let written = (needed as usize).min(buf.len());
                buf.truncate(written);
                return Ok(buf);
            },
            ERROR_INSUFFICIENT_BUFFER if needed as usize > capacity => {
                capacity = needed as usize;
            },
            other => return Err(win32_error(other)),
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
            let status = unsafe {
                // Safety:
                //  * the control handle is valid (checked above)
                //  * the buffer is valid for reads over `buf_len` bytes
                Etw::TraceSetInformation(
                    handle,
                    TRACE_QUERY_INFO_CLASS(class as i32),
                    buf.as_ptr().cast(),
                    buf_len,
                )
            };
            win32_result(status)
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

    let buf = stack_tracing_buffer(events);
    set_info(
        control_handle,
        TraceInformation::TraceStackTracingInfo,
        &buf,
    )
}

/// Builds the CLASSIC_EVENT_ID array expected by `TraceStackTracingInfo`, as a byte buffer
// The byte view in `stack_tracing_buffer` is only sound while CLASSIC_EVENT_ID stays a
// padding-free struct (a GUID + a type byte + 7 reserved bytes)
const _: () = assert!(size_of::<Etw::CLASSIC_EVENT_ID>() == 24);

fn stack_tracing_buffer(events: &[StackTracingEvent]) -> Vec<u8> {
    let event_ids: Vec<Etw::CLASSIC_EVENT_ID> = events
        .iter()
        .map(|event| Etw::CLASSIC_EVENT_ID {
            EventGuid: event.event_guid,
            Type: event.event_type,
            Reserved: [0; 7],
        })
        .collect();
    // SAFETY: CLASSIC_EVENT_ID is #[repr(C)] and all-integer (no padding), so this is a
    // valid byte view of the array, valid for reads as long as `event_ids` is alive.
    // The size must come from the *slice*, not the Vec: `size_of_val(&event_ids)` would
    // measure the Vec header (3 pointers = 24 bytes on x64, i.e. exactly one
    // CLASSIC_EVENT_ID), silently truncating the list to its first event
    unsafe {
        std::slice::from_raw_parts(
            event_ids.as_ptr().cast::<u8>(),
            size_of_val(event_ids.as_slice()),
        )
    }
    .to_vec()
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
    let (status, _) = trace_query_raw(
        control_handle,
        TraceInformation::TraceSystemTraceEnableFlagsInfo,
        &mut buf,
    );
    // An error here means the session (or OS, these need Windows 8+) does not support the
    // extended group mask: surface it rather than silently skipping the groups
    win32_result(status)?;
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
    use std::sync::{
        Barrier, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use widestring::U16CString;
    use windows::Win32::Foundation::ERROR_INVALID_PARAMETER;

    use super::*;
    use crate::{provider::EventFilter, trace::callback_data::RealTimeCallbackData};

    /// The provider GUID of the counting provider used by the thunk tests
    const COUNTED_PROVIDER: u128 = 0x1212;

    /// A real-time callback data whose well-known provider increments `counter` per event
    fn counting_callback_data(counter: &Arc<AtomicUsize>) -> Arc<CallbackData> {
        let bump = Arc::clone(counter);
        let data = RealTimeCallbackData::new();
        data.add_provider(
            Provider::by_guid(COUNTED_PROVIDER)
                .add_callback(move |_, _| {
                    bump.fetch_add(1, Ordering::Relaxed);
                })
                .build(),
        );
        Arc::new(CallbackData::RealTime(data))
    }

    /// An event record whose only meaningful fields are the provider and the user context
    fn record_for(provider: u128, user_context: *mut c_void) -> Etw::EVENT_RECORD {
        Etw::EVENT_RECORD {
            EventHeader: Etw::EVENT_HEADER {
                ProviderId: GUID::from_u128(provider),
                ..Default::default()
            },
            UserContext: user_context,
            ..Default::default()
        }
    }

    #[test]
    fn win32_errors_map_to_their_raw_code_not_the_hresult() {
        // Regression: routing WIN32_ERROR through `ok()` produced an
        // HRESULT_FROM_WIN32 (0x800700B7), which from_raw_os_error surfaced as
        // os error -2147024713, with every ErrorKind mapping lost
        let err = win32_error(ERROR_ALREADY_EXISTS);
        let EvntraceNativeError::IoError(err) = err else {
            panic!("expected an IoError, got {err:?}");
        };
        let raw = i32::try_from(ERROR_ALREADY_EXISTS.0).unwrap();
        assert_eq!(err.raw_os_error(), Some(raw));
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);

        let err = win32_error(ERROR_INVALID_PARAMETER);
        let EvntraceNativeError::IoError(err) = err else {
            panic!("expected an IoError, got {err:?}");
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn win32_result_accepts_success_only() {
        assert!(win32_result(ERROR_SUCCESS).is_ok());
        assert!(win32_result(ERROR_INVALID_PARAMETER).is_err());
    }

    #[test]
    fn cancelled_processing_is_not_an_error() {
        // Stopping the session (or closing the handle) is the normal way a
        // ProcessTrace call ends: it must surface as Ok, like ERROR_SUCCESS
        assert!(process_trace_status(ERROR_SUCCESS).is_ok());
        assert!(process_trace_status(ERROR_CANCELLED).is_ok());

        let err = process_trace_status(ERROR_INVALID_PARAMETER).unwrap_err();
        assert!(matches!(
            err,
            EvntraceNativeError::IoError(ref e)
                if e.kind() == std::io::ErrorKind::InvalidInput
        ));
    }

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

    #[test]
    fn stack_tracing_buffer_is_sized_per_event_not_per_vec() {
        // Regression: the buffer used to be sized with `size_of_val(&Vec)`, i.e. the
        // Vec header (24 bytes on x64 = exactly one CLASSIC_EVENT_ID), so only the
        // first event was ever stack-traced, and the call still succeeded
        let events: Vec<StackTracingEvent> = [46u8, 47, 12]
            .map(|ty| StackTracingEvent::new(GUID::new().unwrap(), ty))
            .into();

        let buf = stack_tracing_buffer(&events);
        assert_eq!(buf.len(), events.len() * size_of::<Etw::CLASSIC_EVENT_ID>());

        // Decode every element back per the SDK layout: GUID (16 bytes), type byte,
        // 7 reserved bytes
        for (i, event) in events.iter().enumerate() {
            let id = &buf[i * 24..][..24];
            let guid = GUID::from_values(
                u32::from_ne_bytes(id[0..4].try_into().unwrap()),
                u16::from_ne_bytes(id[4..6].try_into().unwrap()),
                u16::from_ne_bytes(id[6..8].try_into().unwrap()),
                id[8..16].try_into().unwrap(),
            );
            assert_eq!(guid, event.event_guid);
            assert_eq!(id[16], event.event_type);
            assert!(id[17..].iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn failed_open_trace_fails_with_the_os_error() {
        // A nonexistent ETL file makes OpenTraceW fail deterministically
        let source =
            SubscriptionSource::FromFile(U16CString::from_str("Z:\\no\\such\\trace.etl").unwrap());

        let result = open_trace(
            source,
            Arc::new(CallbackData::RealTime(RealTimeCallbackData::new())),
        );
        assert!(
            matches!(result, Err(EvntraceNativeError::IoError(_))),
            "OpenTraceW on a nonexistent file must surface the OS error"
        );
        // The context of the failed open was dropped inside `open_trace`, which
        // unregistered it (see `TraceContext::drop`): no dead id piles up in the
        // registry
    }

    #[test]
    fn thunk_drops_events_of_unknown_contexts() {
        // A minted-but-never-registered id: no `TraceContext` was built with it, so the
        // thunk must drop the event without touching any callback
        let counter = Arc::new(AtomicUsize::new(0));
        let _unregistered = counting_callback_data(&counter);
        let id = TraceContextId::mint();

        let mut record = record_for(COUNTED_PROVIDER, id.as_user_context());
        trace_callback_thunk(&raw mut record);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn registered_contexts_dispatch_until_they_are_unregistered() {
        let counter = Arc::new(AtomicUsize::new(0));
        let context = TraceContext::new(counting_callback_data(&counter));

        let mut record = record_for(COUNTED_PROVIDER, context.id().as_user_context());
        trace_callback_thunk(&raw mut record);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        assert_eq!(context.events_handled(), 1);

        // What `close_trace` does before `CloseTrace`: from then on, the events still
        // queued by ETW carry a retired id and must be dropped, not dispatched
        context.unregister();
        trace_callback_thunk(&raw mut record);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        assert_eq!(context.events_handled(), 1);
    }

    #[test]
    fn a_callback_past_the_lookup_survives_close_and_drop() {
        // The P1-1 race: a delivery thread resolved its context, then the trace was closed
        // and fully dropped before the callback body ran. The `Arc` handed out by the
        // registry keeps the callback data alive, so the in-flight callback must dispatch
        // on live memory, while events looked up after the retirement must be dropped.
        let counter = Arc::new(AtomicUsize::new(0));
        let data = counting_callback_data(&counter);
        let context = TraceContext::new(Arc::clone(&data));
        let id = context.id();

        // The delivery thread won the race against the close: it holds its own `Arc`
        let in_flight = CONTEXT_REGISTRY.get(id).unwrap();

        // ... then the trace closes and is entirely dropped (retiring the context)
        context.unregister();
        drop(context);
        drop(data);

        let record = EventRecord(record_for(COUNTED_PROVIDER, id.as_user_context()));
        in_flight.on_event(&record);
        assert_eq!(counter.load(Ordering::Relaxed), 1);

        // Later lookups of the retired context miss: their events are dropped
        assert!(CONTEXT_REGISTRY.get(id).is_none());
    }

    #[test]
    fn a_new_trace_never_reuses_a_closed_context_id() {
        // ABA: a stale event of a closed trace carries its retired id. Even if a newer
        // trace's callback data landed on the very same memory, the ids differ, so the
        // stale event can only miss the registry instead of dispatching into the new trace
        let counter = Arc::new(AtomicUsize::new(0));
        let first = TraceContext::new(counting_callback_data(&counter));
        let first_id = first.id();
        drop(first);

        let second = TraceContext::new(counting_callback_data(&counter));
        assert_ne!(second.id(), first_id);
        assert!(CONTEXT_REGISTRY.get(first_id).is_none());
        assert!(CONTEXT_REGISTRY.get(second.id()).is_some());

        let mut stale = record_for(COUNTED_PROVIDER, first_id.as_user_context());
        trace_callback_thunk(&raw mut stale);
        assert_eq!(counter.load(Ordering::Relaxed), 0);

        let mut fresh = record_for(COUNTED_PROVIDER, second.id().as_user_context());
        trace_callback_thunk(&raw mut fresh);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        assert_eq!(second.events_handled(), 1);
    }

    #[test]
    fn buffer_thunk_records_the_totals_of_registered_contexts_only() {
        let data = Arc::new(CallbackData::RealTime(RealTimeCallbackData::new()));
        let context = TraceContext::new(Arc::clone(&data));

        let mut log_file = Etw::EVENT_TRACE_LOGFILEW {
            Context: context.id().as_user_context(),
            BuffersRead: 3,
            EventsLost: 1,
            ..Default::default()
        };
        buffer_callback_thunk(&raw mut log_file);
        assert_eq!(data.buffers_read(), 3);
        assert_eq!(data.events_lost(), 1);

        // Stale buffer reports of a retired context are dropped too
        context.unregister();
        let mut stale = Etw::EVENT_TRACE_LOGFILEW {
            Context: context.id().as_user_context(),
            BuffersRead: 9,
            EventsLost: 9,
            ..Default::default()
        };
        buffer_callback_thunk(&raw mut stale);
        assert_eq!(data.buffers_read(), 3);
        assert_eq!(data.events_lost(), 1);
    }

    #[test]
    fn dispatch_survives_racing_registrations_and_unregistrations() {
        // Stress the lookup/close interleaving: dispatcher threads simulate ETW delivery
        // (registry lookup + dispatch, replaying both live and stale ids), while closer
        // threads churn registrations (as open/close races do). Whatever the interleaving:
        // a successful lookup must hand out a live `Arc`, dispatch exactly once into the
        // instance it resolved, retired ids must never dispatch again, and the ids left
        // registered must all resolve.
        const DISPATCHERS: usize = 4;
        const CLOSERS: usize = 2;
        const INSTANCES: usize = 4;
        const DISPATCH_ROUNDS: usize = 20_000;
        const CHURN_ROUNDS: usize = 2_000;

        /// One registered trace instance: its context id, and which of the fixed
        /// callback data it dispatches to
        struct Registration {
            id: TraceContextId,
            instance: usize,
        }

        // The instances are owned here so their counters stay readable after unregistration
        let instances: Vec<Arc<CallbackData>> = (0..INSTANCES)
            .map(|_| Arc::new(CallbackData::RealTime(RealTimeCallbackData::new())))
            .collect();
        let live: Mutex<Vec<Registration>> = Mutex::new(
            (0..INSTANCES)
                .map(|instance| {
                    let id = TraceContextId::mint();
                    CONTEXT_REGISTRY.insert(id, Arc::clone(&instances[instance]));
                    Registration { id, instance }
                })
                .collect(),
        );
        // The initially registered ids: the closers retire all of them and replace them
        // with fresh ones, so the dispatchers replay a mix of live and stale ids
        let replayed_ids: Vec<TraceContextId> = live.lock().unwrap().iter().map(|r| r.id).collect();
        let next_slot = AtomicUsize::new(0);
        let dispatched = AtomicUsize::new(0);

        let barrier = Arc::new(Barrier::new(DISPATCHERS + CLOSERS));
        std::thread::scope(|s| {
            for _ in 0..DISPATCHERS {
                let barrier = Arc::clone(&barrier);
                let (replayed_ids, next_slot, dispatched) =
                    (&replayed_ids, &next_slot, &dispatched);
                s.spawn(move || {
                    barrier.wait();
                    // No provider matches this GUID: on_event only counts the dispatch
                    let record = EventRecord(Etw::EVENT_RECORD {
                        EventHeader: Etw::EVENT_HEADER {
                            ProviderId: GUID::from_u128(0x9999),
                            ..Default::default()
                        },
                        ..Default::default()
                    });
                    for _ in 0..DISPATCH_ROUNDS {
                        let slot = next_slot.fetch_add(1, Ordering::Relaxed) % replayed_ids.len();
                        if let Some(callback_data) = CONTEXT_REGISTRY.get(replayed_ids[slot]) {
                            dispatched.fetch_add(1, Ordering::Relaxed);
                            callback_data.on_event(&record);
                        }
                    }
                });
            }
            for _ in 0..CLOSERS {
                let barrier = Arc::clone(&barrier);
                let (live, instances) = (&live, &instances);
                s.spawn(move || {
                    barrier.wait();
                    for round in 0..CHURN_ROUNDS {
                        // Close a registration (as `close_trace` does), then register the
                        // same instance afresh (as a new open would: a brand-new id). The
                        // instance is picked round-robin, so every initially registered id
                        // is deterministically retired along the way.
                        let target = round % INSTANCES;
                        let retired = {
                            let mut guard = live.lock().unwrap();
                            match guard.iter().position(|reg| reg.instance == target) {
                                Some(pos) => guard.remove(pos),
                                // The same instance is mid-re-registration in the other
                                // closer: nothing to retire this round
                                None => continue,
                            }
                        };
                        CONTEXT_REGISTRY.remove(retired.id);
                        let id = TraceContextId::mint();
                        CONTEXT_REGISTRY.insert(id, Arc::clone(&instances[retired.instance]));
                        live.lock().unwrap().push(Registration {
                            id,
                            instance: retired.instance,
                        });
                    }
                });
            }
        });

        // Every successful lookup dispatched exactly once, into a live instance
        let total_handled: usize = instances.iter().map(|d| d.events_handled()).sum();
        assert_eq!(dispatched.load(Ordering::Relaxed), total_handled);

        // All the initially registered ids were retired by the churn: none resolves
        for id in replayed_ids {
            assert!(CONTEXT_REGISTRY.get(id).is_none());
        }
        // The registrations left by the closers all resolve
        for registration in live.lock().unwrap().iter() {
            assert!(CONTEXT_REGISTRY.get(registration.id).is_some());
        }
    }
}
