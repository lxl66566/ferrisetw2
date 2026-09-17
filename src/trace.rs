//! ETW Tracing/Session abstraction
//!
//! Provides both a Kernel and User trace that allows to start an ETW session
use std::{ffi::OsString, marker::PhantomData, path::PathBuf, sync::Arc, time::Duration};

use widestring::U16CString;
use windows::{
    Win32::{Foundation::ERROR_WMI_INSTANCE_NOT_FOUND, System::Diagnostics::Etw},
    core::GUID,
};

use self::private::{PrivateRealTimeTraceTrait, PrivateTraceTrait};
pub use crate::native::etw_types::{ClockType, DumpFileLoggingMode, LoggingMode};
use crate::{
    EventRecord, SchemaLocator,
    native::{
        EvntraceNativeError,
        etw_types::{EventTraceProperties, SubscriptionSource},
        evntrace::{
            ControlHandle, TraceContext, TraceHandle, capture_provider_state, close_trace,
            control_trace, control_trace_by_name, disable_provider, enable_provider,
            enable_stack_tracing, open_trace, process_trace, set_extended_kernel_groups,
            start_trace, win32_error,
        },
        version_helper,
    },
    provider::Provider,
    utils,
};

pub(crate) mod callback_data;
use callback_data::{CallbackData, CallbackDataFromFile, RealTimeCallbackData};

const KERNEL_LOGGER_NAME: &str = "NT Kernel Logger";
const SYSTEM_TRACE_CONTROL_GUID: GUID = GUID::from_u128(0x9e814aad_3204_11d2_9a82_006008a86939);
const EVENT_TRACE_SYSTEM_LOGGER_MODE: u32 = 0x0200_0000;

/// Trace module errors
#[derive(Debug)]
pub enum TraceError {
    InvalidTraceName,
    /// Wrapper over an internal [`EvntraceNativeError`]
    EtwNativeError(EvntraceNativeError),
}

impl From<EvntraceNativeError> for TraceError {
    fn from(err: EvntraceNativeError) -> Self {
        TraceError::EtwNativeError(err)
    }
}

type TraceResult<T> = Result<T, TraceError>;

/// Trace Properties struct
///
/// These are some configuration settings that will be included in an [`EVENT_TRACE_PROPERTIES`](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)
///
/// [More info](https://docs.microsoft.com/en-us/message-analyzer/specifying-advanced-etw-session-configuration-settings#configuring-the-etw-session)
#[derive(Debug, Copy, Clone)]
pub struct TraceProperties {
    /// Represents the ETW Session in KB
    pub buffer_size: u32,
    /// Represents the ETW Session minimum number of buffers to use
    pub min_buffer: u32,
    /// Represents the ETW Session maximum number of buffers in the buffer pool
    pub max_buffer: u32,
    /// Represents the ETW Session flush interval.
    ///
    /// This duration will be rounded to the closest second (and 0 will be translated as 1 second)
    pub flush_timer: Duration,
    /// Represents the ETW Session [Logging Mode](https://docs.microsoft.com/en-us/windows/win32/etw/logging-mode-constants)
    pub log_file_mode: LoggingMode,
    /// Represents the ETW Session clock resolution used to timestamp events.
    ///
    /// Defaults to [`ClockType::Qpc`] (the Windows default)
    pub clock_type: ClockType,
}

impl Default for TraceProperties {
    fn default() -> Self {
        // Sane defaults, inspired by https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
        TraceProperties {
            buffer_size: 32,
            min_buffer: 0,
            max_buffer: 0,
            flush_timer: Duration::from_secs(1),
            log_file_mode: LoggingMode::EVENT_TRACE_REAL_TIME_MODE
                | LoggingMode::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING,
            clock_type: ClockType::default(),
        }
    }
}

// Kernel events of the PerfInfo provider (syscalls, sampled profile, ...) have well-known
// numeric types ("hook ids"). They are not part of the public SDK: the values below are the
// ones behind xperf's `-stackwalk` names, as also used by krabsetw.
// Mirrors kernel_providers' (private) PERF_INFO_GUID
const PERF_INFO_GUID: GUID = GUID::from_values(0xce1d_bfb4, 0x137e, 0x4da6, [
    0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc,
]);

/// A snapshot of the statistics of a running trace session
///
/// This is returned by [`RealTimeTraceTrait::statistics`], which queries the session live
/// (through `ControlTraceW` with `EVENT_TRACE_CONTROL_QUERY`). The values can be re-queried
/// at any time while the session is running, e.g. to detect a growing `events_lost` counter
/// on a long-running real-time trace.
///
/// These are the **logger-side** statistics, as maintained by the ETW session itself. The
/// **consumer-side** counters exposed by [`TraceTrait::events_handled`] and
/// [`TraceTrait::buffers_read`] are a complementary view of the same session.
///
/// A [`FileTrace`] has no session handle, so it does not offer this query; the loss counters
/// recorded in an ETL file are reported to it through [`TraceTrait::events_lost`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceStatistics {
    /// Number of events the session has dropped because no buffer was available to hold them
    /// (e.g. a burst of events while all buffers were busy flushing)
    pub events_lost: u32,
    /// Number of buffers lost while logging to the dump file: e.g. the disk was too slow, or
    /// the file system errored out. Non-zero only for sessions with a dump file.
    pub log_buffers_lost: u32,
    /// Number of buffers lost while delivering events to real-time consumers: e.g. the
    /// consumer was not attached, or did not drain the buffers fast enough
    pub real_time_buffers_lost: u32,
    /// Total number of buffers written so far
    pub buffers_written: u32,
    /// Number of buffers currently allocated for the session
    pub number_of_buffers: u32,
    /// Number of allocated buffers currently free (a `free_buffers` of 0 with a non-zero
    /// `events_lost` is the signature of a session dropping events for lack of buffers)
    pub free_buffers: u32,
    /// Identifier of the thread running the logger
    pub logger_thread_id: u32,
}

impl TraceStatistics {
    /// Maps the statistics fields of a raw [`Etw::EVENT_TRACE_PROPERTIES`], as filled in by
    /// the `ControlTraceW` QUERY control code
    pub(crate) fn from_properties(props: &Etw::EVENT_TRACE_PROPERTIES) -> Self {
        // The logger thread id is a thread id disguised as a HANDLE: only its low 32 bits can
        // ever be meaningful
        #[allow(clippy::cast_possible_truncation)]
        let logger_thread_id = props.LoggerThreadId.0 as usize as u32;
        Self {
            events_lost: props.EventsLost,
            log_buffers_lost: props.LogBuffersLost,
            real_time_buffers_lost: props.RealTimeBuffersLost,
            buffers_written: props.BuffersWritten,
            number_of_buffers: props.NumberOfBuffers,
            free_buffers: props.FreeBuffers,
            logger_thread_id,
        }
    }
}

/// A kernel event to collect call stacks for
///
/// Kernel loggers cannot use the per-provider stack trace flag of user traces
/// (`EVENT_ENABLE_PROPERTY_STACK_TRACE`): stacks are enabled per event, through the
/// `TraceStackTracingInfo` info class, whose payload is an array of Windows'
/// `CLASSIC_EVENT_ID` (an event GUID + type pair).
///
/// Valid GUIDs and types are the classic kernel event identifiers, the same values xperf's
/// [`-stackwalk`](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/stackwalk)
/// option names. For the most common use case, syscall stack collection, ready-made
/// constants exist: [`StackTracingEvent::SYSCALL_ENTER`] and [`StackTracingEvent::SYSCALL_EXIT`].
///
/// # Example
/// ```
/// # use ferrisetw::trace::{KernelTrace, StackTracingEvent};
/// let builder = KernelTrace::new().set_stack_tracing(vec![StackTracingEvent::SYSCALL_ENTER]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StackTracingEvent {
    /// GUID of the kernel provider the event belongs to
    pub event_guid: GUID,
    /// Type (a.k.a. hook id) of the event within its provider
    pub event_type: u8,
}

impl StackTracingEvent {
    /// Syscall entry (`xperf -stackwalk SyscallEnter`)
    ///
    /// Syscall events come from the
    /// [`SYSTEM_CALL_PROVIDER`](crate::provider::kernel_providers::SYSTEM_CALL_PROVIDER), which
    /// must also be enabled for the trace to see them.
    pub const SYSCALL_ENTER: Self = Self::new(PERF_INFO_GUID, 46);
    /// Syscall exit (`xperf -stackwalk SyscallExit`)
    ///
    /// See [`StackTracingEvent::SYSCALL_ENTER`] about enabling the syscall events themselves.
    pub const SYSCALL_EXIT: Self = Self::new(PERF_INFO_GUID, 47);

    /// Create a stack tracing event from its provider GUID and event type
    #[must_use]
    pub const fn new(event_guid: GUID, event_type: u8) -> Self {
        Self {
            event_guid,
            event_type,
        }
    }
}

/// A fine-grained kernel event group, enabled through the extended kernel group mask
///
/// [The `EnableFlags` of `EVENT_TRACE_PROPERTIES`](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)
/// can only express the 32 classic kernel groups (those of
/// [`crate::provider::kernel_providers`]). Finer-grained groups are enabled on a running
/// session through the `TraceSystemTraceEnableFlagsInfo` info class, which
/// [`KernelTrace::set_extended_groups`](TraceBuilder::set_extended_groups) does when
/// starting the trace. Requires Windows 8 or later.
///
/// Each variant is a `PERF_*` group id as named in
/// [krabsetw](https://github.com/microsoft/krabsetw/blob/master/krabs/krabs/perfinfo_groupmask.hpp)
/// (the `PERF_*` names come from the kernel's `ntwmi.h`): the top 3 bits select one of the
/// eight masks of the group mask, the low 29 bits the groups within it. Groups that are mere
/// aliases of a classic `EnableFlags` bit are not duplicated here.
///
/// # Example
/// ```
/// # use ferrisetw::trace::{ExtendedKernelGroup, KernelTrace};
/// let builder = KernelTrace::new()
///     .set_extended_groups(vec![ExtendedKernelGroup::Memory, ExtendedKernelGroup::Pool]);
/// ```
#[non_exhaustive]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtendedKernelGroup {
    // Masks[1]
    /// `PERF_MEMORY`
    Memory = 0x2000_0001,
    /// `PERF_FOOTPRINT`
    Footprint = 0x2000_0008,
    /// `PERF_REFSET`
    RefSet = 0x2000_0020,
    /// `PERF_POOL`
    Pool = 0x2000_0040,
    /// `PERF_POOLTRACE`
    PoolTrace = 0x2000_0041,
    /// `PERF_COMPACT_CSWITCH`
    CompactContextSwitch = 0x2000_0100,
    /// `PERF_PMC_PROFILE`
    PmcProfile = 0x2000_0400,
    /// `PERF_PROCESS_INSWAP`
    ProcessInswap = 0x2000_0800,
    /// `PERF_AFFINITY`
    Affinity = 0x2000_1000,
    /// `PERF_PRIORITY`
    Priority = 0x2000_2000,
    /// `PERF_SPINLOCK`
    Spinlock = 0x2001_0000,
    /// `PERF_SYNC_OBJECTS`
    SyncObjects = 0x2002_0000,
    /// `PERF_DPC_QUEUE`
    DpcQueue = 0x2004_0000,
    /// `PERF_MEMINFO`
    MemInfo = 0x2008_0000,
    /// `PERF_CONTMEM_GEN`
    ContiguousMemoryGeneration = 0x2010_0000,
    /// `PERF_SPINLOCK_CNTRS`
    SpinlockCounters = 0x2020_0000,
    /// `PERF_SPININSTR`
    SpinlockInstructions = 0x2021_0000,
    /// `PERF_SESSION` (also known as `PERF_PFSECTION`, same value)
    Session = 0x2040_0000,
    /// `PERF_MEMINFO_WS`
    MemInfoWorkingSet = 0x2080_0000,
    /// `PERF_KERNEL_QUEUE`
    KernelQueue = 0x2100_0000,
    /// `PERF_INTERRUPT_STEER`
    InterruptSteering = 0x2200_0000,
    /// `PERF_SHOULD_YIELD`
    ShouldYield = 0x2400_0000,
    /// `PERF_WS`
    WorkingSet = 0x2800_0000,
    // Masks[2]
    /// `PERF_ANTI_STARVATION`
    AntiStarvation = 0x4000_0001,
    /// `PERF_PROCESS_FREEZE`
    ProcessFreeze = 0x4000_0002,
    /// `PERF_PFN_LIST`
    PfnList = 0x4000_0004,
    /// `PERF_WS_DETAIL`
    WorkingSetDetail = 0x4000_0008,
    /// `PERF_WS_ENTRY`
    WorkingSetEntry = 0x4000_0010,
    /// `PERF_HEAP`
    Heap = 0x4000_0020,
    /// `PERF_UMS`
    Ums = 0x4000_0080,
    /// `PERF_BACKTRACE`
    Backtrace = 0x4000_0100,
    /// `PERF_VULCAN`
    Vulcan = 0x4000_0200,
    /// `PERF_OBJECTS`
    Objects = 0x4000_0400,
    /// `PERF_EVENTS`
    Events = 0x4000_0800,
    /// `PERF_FULLTRACE`
    FullTrace = 0x4000_1000,
    /// `PERF_DFSS`
    Dfss = 0x4000_2000,
    /// `PERF_PREFETCH`
    Prefetch = 0x4000_4000,
    /// `PERF_PROCESSOR_IDLE`
    ProcessorIdle = 0x4000_8000,
    /// `PERF_CPU_CONFIG`
    CpuConfig = 0x4001_0000,
    /// `PERF_TIMER`
    Timer = 0x4002_0000,
    /// `PERF_CLOCK_INTERRUPT`
    ClockInterrupt = 0x4004_0000,
    /// `PERF_LOAD_BALANCER`
    LoadBalancer = 0x4008_0000,
    /// `PERF_CLOCK_TIMER`
    ClockTimer = 0x4010_0000,
    /// `PERF_IDLE_SELECTION`
    IdleSelection = 0x4020_0000,
    /// `PERF_IPI`
    Ipi = 0x4040_0000,
    /// `PERF_IO_TIMER`
    IoTimer = 0x4080_0000,
    /// `PERF_REG_HIVE`
    RegistryHive = 0x4100_0000,
    /// `PERF_REG_NOTIF`
    RegistryNotification = 0x4200_0000,
    /// `PERF_PPM_EXIT_LATENCY`
    PpmExitLatency = 0x4400_0000,
    /// `PERF_WORKER_THREAD`
    WorkerThread = 0x4800_0000,
    // Masks[4]
    /// `PERF_OPTICAL_IO`
    OpticalIo = 0x8000_0001,
    /// `PERF_OPTICAL_IO_INIT`
    OpticalIoInit = 0x8000_0002,
    /// `PERF_DLL_INFO`
    DllInfo = 0x8000_0008,
    /// `PERF_DLL_FLUSH_WS`
    DllFlushWorkingSet = 0x8000_0010,
    /// `PERF_OB_HANDLE` (object manager handles)
    ObHandle = 0x8000_0040,
    /// `PERF_OB_OBJECT` (object manager objects)
    ObObject = 0x8000_0080,
    /// `PERF_WAKE_DROP`
    WakeDrop = 0x8000_0200,
    /// `PERF_WAKE_EVENT`
    WakeEvent = 0x8000_0400,
    /// `PERF_DEBUGGER`
    Debugger = 0x8000_0800,
    /// `PERF_PROC_ATTACH`
    ProcessAttach = 0x8000_1000,
    /// `PERF_WAKE_COUNTER`
    WakeCounter = 0x8000_2000,
    /// `PERF_POWER`
    Power = 0x8000_8000,
    /// `PERF_SOFT_TRIM`
    SoftTrim = 0x8001_0000,
    /// `PERF_CC` (cache manager)
    Cc = 0x8002_0000,
    /// `PERF_FLT_IO_INIT` (filter manager)
    FilteredIoInit = 0x8008_0000,
    /// `PERF_FLT_IO`
    FilteredIo = 0x8010_0000,
    /// `PERF_FLT_FASTIO`
    FilteredFastIo = 0x8020_0000,
    /// `PERF_FLT_IO_FAILURE`
    FilteredIoFailure = 0x8040_0000,
    /// `PERF_HV_PROFILE` (hypervisor)
    HvProfile = 0x8080_0000,
    /// `PERF_WDF_DPC` (driver framework)
    WdfDpc = 0x8100_0000,
    /// `PERF_WDF_INTERRUPT`
    WdfInterrupt = 0x8200_0000,
    /// `PERF_CACHE_FLUSH`
    CacheFlush = 0x8400_0000,
    // Masks[5]
    /// `PERF_HIBER_RUNDOWN`
    HibernateRundown = 0xa000_0001,
    // Masks[6]
    /// `PERF_SYSCFG_SYSTEM` (system configuration rundown)
    SysCfgSystem = 0xc000_0001,
    /// `PERF_SYSCFG_GRAPHICS`
    SysCfgGraphics = 0xc000_0002,
    /// `PERF_SYSCFG_STORAGE`
    SysCfgStorage = 0xc000_0004,
    /// `PERF_SYSCFG_NETWORK`
    SysCfgNetwork = 0xc000_0008,
    /// `PERF_SYSCFG_SERVICES`
    SysCfgServices = 0xc000_0010,
    /// `PERF_SYSCFG_PNP`
    SysCfgPnp = 0xc000_0020,
    /// `PERF_SYSCFG_OPTICAL`
    SysCfgOptical = 0xc000_0040,
    /// `PERF_SYSCFG_ALL`: all system configuration groups
    SysCfgAll = 0xdfff_ffff,
    // Masks[7] - control flags, they change system behavior
    /// `PERF_CLUSTER_OFF`
    ClusterOff = 0xe000_0001,
    /// `PERF_MEMORY_CONTROL`
    MemoryControl = 0xe000_0002,
}

impl ExtendedKernelGroup {
    /// The raw `PERF_*` group id, as consumed by the extended group mask
    #[must_use]
    pub const fn group_id(self) -> u32 {
        self as u32
    }
}

/// Trait for common methods to user, kernel and file traces
pub trait TraceTrait: PrivateTraceTrait + Sized {
    // This must be implemented for every trace, as this getter is needed by other methods from this
    // trait
    fn trace_handle(&self) -> TraceHandle;

    /// How many events have been delivered to the callbacks so far
    ///
    /// This is a consumer-side counter. For the session-side statistics (including events
    /// lost by the logger itself), see [`RealTimeTraceTrait::statistics`] on real-time
    /// traces, or [`TraceTrait::events_lost`] for the loss count reported through the
    /// consumer's buffer callback.
    fn events_handled(&self) -> usize;

    /// How many buffers have been processed so far, as reported by the ETW buffer callback
    ///
    /// This counter is fed after each buffer has been processed. For an ETL
    /// [`FileTrace`], it counts the buffers read from the file.
    fn buffers_read(&self) -> usize {
        self.callback_data().buffers_read()
    }

    /// How many events the ETW framework reported as lost while consuming this trace
    ///
    /// For a real-time trace, this catches events the session dropped (e.g. events logged
    /// while the consumer was not attached, or too slow to drain the buffers). For an ETL
    /// [`FileTrace`], this is the lost-events count recorded when the file was written.
    ///
    /// On real-time traces, this complements [`RealTimeTraceTrait::statistics`]: both
    /// observe losses, from the consumer side and from the logger side respectively.
    fn events_lost(&self) -> usize {
        self.callback_data().events_lost()
    }

    fn close(self) -> TraceResult<bool>;

    // The following are default implementations, that work on both user and kernel traces

    /// This is blocking and starts triggerring the callbacks.
    ///
    /// Because this call is blocking, you probably want to call this from a background thread.<br/>
    /// See [`TraceBuilder::start`] for alternative and more convenient ways to start a trace.
    ///
    /// When the trace is stopped while this is blocked (e.g. by calling
    /// [`TraceTrait::stop`], by dropping the trace, or by closing its handle),
    /// this returns `Ok`: Windows reports `ERROR_CANCELLED` as the end of the
    /// processing loop, which is an outcome, not a failure.
    fn process(&mut self) -> TraceResult<()> {
        process_trace(self.trace_handle()).map_err(Into::into)
    }

    /// Process a trace given its handle.
    ///
    /// Like [`TraceTrait::process`], this returns `Ok` when the trace is
    /// stopped while processing.
    ///
    /// See [`TraceBuilder::start`] for alternative and more convenient ways to start a trace.
    fn process_from_handle(handle: TraceHandle) -> TraceResult<()> {
        process_trace(handle).map_err(Into::into)
    }

    /// Stops the trace
    ///
    /// This consumes the trace, that can no longer be used afterwards.
    /// The same result is achieved by dropping `Self`
    fn stop(mut self) -> TraceResult<()> {
        self.non_consuming_stop()
    }
}

/// Trait for common methods to real-time traces
pub trait RealTimeTraceTrait: TraceTrait + PrivateRealTimeTraceTrait {
    // This differs between UserTrace and KernelTrace
    fn trace_guid() -> GUID;

    // This utility function should be implemented for every trace
    fn trace_name(&self) -> OsString;

    /// Query the current statistics of the session (events lost, buffer usage, ...)
    ///
    /// This calls `ControlTraceW` with `EVENT_TRACE_CONTROL_QUERY`, and can be issued at any
    /// time while the session is running, as often as needed.
    ///
    /// This takes `&mut self` because the query is an in/out call over the session's own
    /// properties buffer (Windows writes the statistics fields into it): the exclusive
    /// borrow is what rules out concurrent queries racing on that buffer. A `&self`
    /// signature would not enable polling from another thread anyway — `UserTrace` and
    /// `KernelTrace` are deliberately `!Send + !Sync` (their properties embed raw handles),
    /// so sharing a running trace across threads requires the caller's own synchronization
    /// around the whole trace, whatever the signature.
    ///
    /// Traces obtained through [`TraceBuilder::open_existing`] do not own their session and
    /// hold no control handle: querying them returns an error.
    ///
    /// # Example
    /// ```no_run
    /// # use ferrisetw::trace::{RealTimeTraceTrait, UserTrace};
    /// # let mut trace = UserTrace::new().start().unwrap().0;
    /// let stats = trace.statistics().unwrap();
    /// if stats.events_lost > 0 || stats.real_time_buffers_lost > 0 {
    ///     eprintln!("the trace session is dropping events: {stats:?}");
    /// }
    /// ```
    fn statistics(&mut self) -> TraceResult<TraceStatistics> {
        // The QUERY is an in/out call: Windows fills the statistics fields of `properties`,
        // and copies the session (and dump file, if any) name back into the name buffers of
        // `properties`. The offsets and buffers are ours and untouched, so subsequent QUERY
        // or STOP calls keep working (STOP passes the handle anyway, not the name).
        let control_handle = self.control_handle();
        let properties = self.properties_mut();
        control_trace(properties, control_handle, Etw::EVENT_TRACE_CONTROL_QUERY)?;
        Ok(TraceStatistics::from_properties(properties.as_native()))
    }
}

impl TraceTrait for UserTrace {
    fn trace_handle(&self) -> TraceHandle {
        self.trace_handle
    }

    fn events_handled(&self) -> usize {
        self.context.events_handled()
    }

    fn close(self) -> TraceResult<bool> {
        close_trace(self.trace_handle, &self.context).map_err(TraceError::EtwNativeError)
    }
}

impl RealTimeTraceTrait for UserTrace {
    fn trace_guid() -> GUID {
        GUID::new().unwrap_or(GUID::zeroed())
    }

    fn trace_name(&self) -> OsString {
        self.properties.name()
    }
}

// Kernel providers that need the extended PERFINFO_GROUPMASK (see
// `ExtendedKernelGroup`) are enabled through `TraceBuilder::set_extended_groups` when the
// trace is started
impl TraceTrait for KernelTrace {
    fn trace_handle(&self) -> TraceHandle {
        self.trace_handle
    }

    fn events_handled(&self) -> usize {
        self.context.events_handled()
    }

    fn close(self) -> TraceResult<bool> {
        close_trace(self.trace_handle, &self.context).map_err(TraceError::EtwNativeError)
    }
}

impl RealTimeTraceTrait for KernelTrace {
    fn trace_guid() -> GUID {
        if version_helper::is_win8_or_greater() {
            GUID::new().unwrap_or(GUID::zeroed())
        } else {
            SYSTEM_TRACE_CONTROL_GUID
        }
    }

    fn trace_name(&self) -> OsString {
        self.properties.name()
    }
}

impl TraceTrait for FileTrace {
    fn trace_handle(&self) -> TraceHandle {
        self.trace_handle
    }

    fn events_handled(&self) -> usize {
        self.context.events_handled()
    }

    fn close(self) -> TraceResult<bool> {
        close_trace(self.trace_handle, &self.context).map_err(TraceError::EtwNativeError)
    }
}

/// A real-time trace session to collect events from user-mode applications
///
/// To stop the session, you can drop this instance
#[derive(Debug)]
pub struct UserTrace {
    properties: EventTraceProperties,
    control_handle: ControlHandle,
    trace_handle: TraceHandle,
    // The context owns the `Arc<CallbackData>` registered for dispatch: the ETW callbacks
    // resolve their `UserContext` through the context registry and hold their own `Arc`
    // clones, so dropping the trace while a callback runs is safe
    context: TraceContext,
}

/// A real-time trace session to collect events from kernel-mode drivers
///
/// To stop the session, you can drop this instance
#[derive(Debug)]
pub struct KernelTrace {
    properties: EventTraceProperties,
    control_handle: ControlHandle,
    trace_handle: TraceHandle,
    // See `UserTrace::context`
    context: TraceContext,
}

/// A trace session that reads events from an ETL file
///
/// To stop the session, you can drop this instance
#[derive(Debug)]
pub struct FileTrace {
    trace_handle: TraceHandle,
    // See `UserTrace::context`
    context: TraceContext,
}

/// Various parameters related to an ETL dump file
#[derive(Clone, Default)]
pub struct DumpFileParams {
    pub file_path: PathBuf,
    /// Options that control how the file is written. If you're not sure, you can use
    /// [`DumpFileLoggingMode::default()`].
    pub file_logging_mode: DumpFileLoggingMode,
    /// Maximum size of the dump file. This is expressed in MB, unless `file_logging_mode` requires
    /// it otherwise.
    pub max_size: Option<u32>,
}

/// Provides a way to crate Trace objects.
///
/// These builders are created using [`UserTrace::new`] or [`KernelTrace::new`]
pub struct TraceBuilder<T: RealTimeTraceTrait> {
    name: String,
    etl_dump_file: Option<DumpFileParams>,
    properties: TraceProperties,
    rt_callback_data: RealTimeCallbackData,
    stop_if_exist: bool,
    // Kernel-only settings (see the `TraceBuilder<KernelTrace>` impl block). They live on the
    // generic builder because both `new()` build one directly, but stay unreachable for user
    // traces at compile time
    stack_tracing_events: Vec<StackTracingEvent>,
    extended_kernel_groups: Vec<ExtendedKernelGroup>,
    trace_kind: PhantomData<T>,
}

pub struct FileTraceBuilder {
    etl_file_path: PathBuf,
    callback: crate::EtwCallback,
}

impl UserTrace {
    /// Create a UserTrace builder
    #[must_use]
    pub fn new() -> TraceBuilder<UserTrace> {
        let name = format!("n4r1b-trace-{}", utils::rand_string());
        TraceBuilder {
            name,
            etl_dump_file: None,
            rt_callback_data: RealTimeCallbackData::new(),
            properties: TraceProperties::default(),
            stop_if_exist: true,
            stack_tracing_events: Vec::new(),
            extended_kernel_groups: Vec::new(),
            trace_kind: PhantomData,
        }
    }

    /// Ask every provider created with
    /// [`ProviderBuilder::request_capture_state`](crate::provider::ProviderBuilder::request_capture_state)
    /// to log its current state (rundown)
    ///
    /// This is automatically done when the trace is started. Calling this
    /// again requests a fresh rundown, e.g. to observe state changes during a
    /// long-running trace. The events will be delivered to the processing
    /// callbacks, as usual.
    ///
    /// # Example
    /// ```no_run
    /// # use ferrisetw::provider::Provider;
    /// # use ferrisetw::trace::UserTrace;
    /// # let provider = Provider::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716")
    /// #     .request_capture_state()
    /// #     .build();
    /// # let trace = UserTrace::new().enable(provider).start().unwrap().0;
    /// // ... process events for a while ...
    /// trace.request_capture_state().unwrap();
    /// ```
    pub fn request_capture_state(&self) -> TraceResult<()> {
        // A UserTrace always holds real-time callback data
        if let CallbackData::RealTime(rt) = &*self.context {
            for provider in rt.providers() {
                if provider.requests_capture_state() {
                    capture_provider_state(self.control_handle, &provider)?;
                }
            }
        }
        Ok(())
    }

    /// Enable an additional provider on a started (possibly processing) trace
    ///
    /// This is the runtime counterpart of [`TraceBuilder::enable`]: the
    /// provider is registered for event dispatch, then enabled on the session
    /// with `EnableTraceEx2`. Events start flowing to the provider's callbacks
    /// right away, even if another thread is already blocked in `process`.
    ///
    /// If the provider was built with
    /// [`ProviderBuilder::request_capture_state`](crate::provider::ProviderBuilder::request_capture_state),
    /// a rundown is requested once the enable succeeded (same order as
    /// [`TraceBuilder::start`]). A rundown error does not undo the enable: the
    /// provider stays enabled and registered, but the error is returned.
    ///
    /// On failure of the enable itself, the registration is rolled back and
    /// the error returned.
    ///
    /// Runtime provider mutations are serialized: an `enable_provider` and a
    /// `disable_provider` issued concurrently (from any thread) can never
    /// interleave their OS-level and registration steps, so a same-GUID pair
    /// of such calls always ends in a consistent state.
    ///
    /// The same provider GUID may be enabled several times: each entry keeps
    /// its own callbacks (but see [`UserTrace::disable_provider`] about how
    /// Windows only keeps one configuration per GUID, the last one enabled).
    ///
    /// Only a `UserTrace` owns the session it processes, so this method
    /// exists here only. Kernel traces select their events through
    /// `EnableFlags`/group masks, which can only be changed through another
    /// (unsupported) `ControlTrace` flow, and [`FileTrace`]
    /// has no session at all. Traces obtained through
    /// [`TraceBuilder::open_existing`] hold no control handle: this returns
    /// an error.
    ///
    /// # Example
    /// ```no_run
    /// # use ferrisetw::provider::Provider;
    /// # use ferrisetw::trace::UserTrace;
    /// # let trace = UserTrace::new().start_and_process().unwrap();
    /// let provider = Provider::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716")
    ///     .add_callback(|_event, _schema| { /* ... */ })
    ///     .build();
    /// trace.enable_provider(provider).unwrap();
    /// ```
    pub fn enable_provider(&self, provider: Provider) -> TraceResult<()> {
        let provider = Arc::new(provider);
        // A UserTrace always holds real-time callback data: the let-else below is
        // unreachable by construction, but a broken invariant must fail loudly in
        // debug builds instead of silently skipping the registration
        debug_assert!(
            matches!(&*self.context, CallbackData::RealTime(_)),
            "a UserTrace always holds real-time callback data"
        );
        let CallbackData::RealTime(rt) = &*self.context else {
            return Ok(());
        };
        // Register first, enable second: once the OS starts delivering events,
        // the dispatch registry must already know the provider. Both steps run
        // under the session-mutation lock: a concurrent `disable_provider` of
        // the same GUID must observe either both steps or none of them (see
        // [`UserTrace::disable_provider`]).
        let session_mutation = rt.lock_session_mutations();
        rt.add_provider_shared(Arc::clone(&provider));

        if let Err(e) = enable_provider(self.control_handle, &provider) {
            // Rollback so the callbacks of a provider the OS rejected never
            // fire
            rt.remove_provider_instance(&provider);
            return Err(e.into());
        }
        // The registry is consistent again: release the lock before the
        // (potentially slow) rundown request, which mutates nothing
        drop(session_mutation);

        if provider.requests_capture_state() {
            capture_provider_state(self.control_handle, &provider)?;
        }
        Ok(())
    }

    /// Disable a provider on a started (possibly processing) trace, removing
    /// **every** entry registered for this GUID
    ///
    /// This sends `EVENT_CONTROL_CODE_DISABLE_PROVIDER` to the session, then
    /// unregisters all the entries with this GUID (the library allows several
    /// registrations of the same GUID, each with its own callbacks; Windows
    /// itself only ever holds one configuration per GUID, so all entries are
    /// removed together). Returns how many entries were removed.
    ///
    /// Notes:
    /// * If no entry is registered for this GUID, this returns `Ok(0)` without touching the
    ///   session.
    /// * If the OS rejects the disable (e.g. the provider was not enabled on this session), the
    ///   error is returned and the registry is left untouched.
    /// * Events already buffered may still be delivered to the removed callbacks for a short while
    ///   after this returns.
    /// * Like [`UserTrace::enable_provider`], this is only available on a `UserTrace` that owns its
    ///   session: a [`TraceBuilder::open_existing`] trace returns an error, kernel traces and file
    ///   traces do not offer this method.
    /// * Provider mutations are serialized (see [`UserTrace::enable_provider`]): a disable racing
    ///   an enable of the same GUID never leaves the provider enabled but unregistered.
    ///
    /// # Example
    /// ```no_run
    /// # use ferrisetw::trace::UserTrace;
    /// # use windows::core::GUID;
    /// # let trace = UserTrace::new().start_and_process().unwrap();
    /// # let guid = GUID::new().unwrap();
    /// let removed = trace.disable_provider(guid).unwrap();
    /// assert_eq!(removed, 1);
    /// ```
    pub fn disable_provider(&self, guid: GUID) -> TraceResult<usize> {
        // A UserTrace always holds real-time callback data: the let-else below is
        // unreachable by construction, but a broken invariant must fail loudly in
        // debug builds instead of silently reporting "nothing to disable"
        debug_assert!(
            matches!(&*self.context, CallbackData::RealTime(_)),
            "a UserTrace always holds real-time callback data"
        );
        let CallbackData::RealTime(rt) = &*self.context else {
            return Ok(0);
        };
        // The whole "OS disable + unregister" sequence runs under the
        // session-mutation lock: without it, a concurrent `enable_provider` of
        // the same GUID could register between the two steps, and be removed
        // right after its OS-level enable succeeded - leaving the session
        // enabled for a GUID nobody is registered to dispatch anymore (its
        // events would pile up and eventually be lost)
        let _disable_in_flight = rt.lock_session_mutations();
        if !rt.has_provider_with_guid(guid) {
            // Nothing of ours is registered under this GUID: do not touch the
            // session (disabling a provider we never enabled would be surprising)
            return Ok(0);
        }
        // Disable at the OS level first, unregister second: should the OS
        // reject the request, the registry (and thus dispatch) stays unchanged
        disable_provider(self.control_handle, guid)?;
        Ok(rt.remove_all_by_guid(guid))
    }

    /// The providers currently registered on this trace, in registration order
    ///
    /// The snapshot includes providers enabled at build time (through
    /// [`TraceBuilder::enable`]) and at runtime (through
    /// [`UserTrace::enable_provider`]).
    #[must_use]
    pub fn providers(&self) -> Vec<Arc<Provider>> {
        // A UserTrace always holds real-time callback data
        match &*self.context {
            CallbackData::RealTime(rt) => rt.providers(),
            CallbackData::FromFile(_) => Vec::new(),
        }
    }
}

impl KernelTrace {
    /// Create a KernelTrace builder
    #[must_use]
    pub fn new() -> TraceBuilder<KernelTrace> {
        let builder = TraceBuilder {
            name: String::new(),
            etl_dump_file: None,
            rt_callback_data: RealTimeCallbackData::new(),
            properties: TraceProperties::default(),
            stop_if_exist: true,
            stack_tracing_events: Vec::new(),
            extended_kernel_groups: Vec::new(),
            trace_kind: PhantomData,
        };
        // Not all names are valid. Let's use the setter to check them for us
        builder.named(format!("n4r1b-trace-{}", utils::rand_string()))
    }
}

mod private {
    //! The only reason for this private module is to have a "private" trait in an otherwise
    //! publicly exported type (`TraceBuilder`)
    //!
    //! See <https://github.com/rust-lang/rust/issues/34537>
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    pub enum TraceKind {
        User,
        Kernel,
    }

    pub trait PrivateRealTimeTraceTrait: PrivateTraceTrait {
        const TRACE_KIND: TraceKind;
        // Accessors used by the default methods of `RealTimeTraceTrait` (e.g. `statistics`)
        fn properties_mut(&mut self) -> &mut EventTraceProperties;
        fn control_handle(&self) -> ControlHandle;
        // The properties are moved into the built trace: passing by value is the point
        #[allow(clippy::large_types_passed_by_value)]
        fn build(
            properties: EventTraceProperties,
            control_handle: ControlHandle,
            trace_handle: TraceHandle,
            context: TraceContext,
        ) -> Self;
        fn augmented_file_mode() -> u32;
        fn enable_flags(_providers: &[Arc<Provider>]) -> u32;
    }

    pub trait PrivateTraceTrait {
        // This function aims at de-deduplicating code called by `impl Drop` and `Trace::stop`.
        // It is basically [`Self::stop`], without consuming self (because the `impl Drop` only has
        // a `&mut self`, not a `self`)
        fn non_consuming_stop(&mut self) -> TraceResult<()>;
        // Accessor backing the default methods of `TraceTrait` (e.g. `events_lost`)
        fn callback_data(&self) -> &CallbackData;
    }
}

impl PrivateRealTimeTraceTrait for UserTrace {
    const TRACE_KIND: private::TraceKind = private::TraceKind::User;

    fn properties_mut(&mut self) -> &mut EventTraceProperties {
        &mut self.properties
    }

    fn control_handle(&self) -> ControlHandle {
        self.control_handle
    }

    fn build(
        properties: EventTraceProperties,
        control_handle: ControlHandle,
        trace_handle: TraceHandle,
        context: TraceContext,
    ) -> Self {
        UserTrace {
            properties,
            control_handle,
            trace_handle,
            context,
        }
    }

    fn augmented_file_mode() -> u32 {
        0
    }

    fn enable_flags(_providers: &[Arc<Provider>]) -> u32 {
        0
    }
}

impl PrivateTraceTrait for UserTrace {
    fn non_consuming_stop(&mut self) -> TraceResult<()> {
        // Always attempt both steps: short-circuiting on the close result would skip the
        // STOP on a retry (the consumer handle is already closed by then), leaking the
        // session. The close error is reported first, as it ran first.
        let closed = close_trace(self.trace_handle, &self.context);
        let stopped = control_trace(
            &mut self.properties,
            self.control_handle,
            Etw::EVENT_TRACE_CONTROL_STOP,
        );
        closed?;
        stopped?;
        Ok(())
    }

    fn callback_data(&self) -> &CallbackData {
        &self.context
    }
}

impl PrivateRealTimeTraceTrait for KernelTrace {
    const TRACE_KIND: private::TraceKind = private::TraceKind::Kernel;

    fn properties_mut(&mut self) -> &mut EventTraceProperties {
        &mut self.properties
    }

    fn control_handle(&self) -> ControlHandle {
        self.control_handle
    }

    fn build(
        properties: EventTraceProperties,
        control_handle: ControlHandle,
        trace_handle: TraceHandle,
        context: TraceContext,
    ) -> Self {
        KernelTrace {
            properties,
            control_handle,
            trace_handle,
            context,
        }
    }

    fn augmented_file_mode() -> u32 {
        if version_helper::is_win8_or_greater() {
            EVENT_TRACE_SYSTEM_LOGGER_MODE
        } else {
            0
        }
    }

    fn enable_flags(providers: &[Arc<Provider>]) -> u32 {
        providers.iter().fold(0, |acc, x| acc | x.kernel_flags())
    }
}

impl PrivateTraceTrait for KernelTrace {
    fn non_consuming_stop(&mut self) -> TraceResult<()> {
        // Always attempt both steps: short-circuiting on the close result would skip the
        // STOP on a retry (the consumer handle is already closed by then), leaking the
        // session. The close error is reported first, as it ran first.
        let closed = close_trace(self.trace_handle, &self.context);
        let stopped = control_trace(
            &mut self.properties,
            self.control_handle,
            Etw::EVENT_TRACE_CONTROL_STOP,
        );
        closed?;
        stopped?;
        Ok(())
    }

    fn callback_data(&self) -> &CallbackData {
        &self.context
    }
}

impl PrivateTraceTrait for FileTrace {
    fn non_consuming_stop(&mut self) -> TraceResult<()> {
        close_trace(self.trace_handle, &self.context)?;
        Ok(())
    }

    fn callback_data(&self) -> &CallbackData {
        &self.context
    }
}

/// Stops a half-started session when [`TraceBuilder::start`] fails after `StartTraceW`
///
/// `StartTraceW` leaves a live session behind, under a random name the caller never sees
/// when `start` fails: the returned error cannot tell them how to stop it. This guard stops
/// the session on the way out (and closes the consumer once `OpenTraceW` provided one),
/// with the same steps as `PrivateTraceTrait::non_consuming_stop`: it is the `Drop` path of
/// a trace that never made it to a `Trace`.
struct StartedSessionGuard<'a> {
    /// The session properties, also serving as the in/out buffer of the STOP call
    properties: &'a mut EventTraceProperties,
    control_handle: ControlHandle,
    /// The consumer side, registered as soon as `open_trace` succeeded
    consumer: Option<(TraceHandle, TraceContext)>,
    /// Whether the session was handed over to the built trace
    handed_over: bool,
}

impl StartedSessionGuard<'_> {
    /// Marks the session as owned by the built trace, returning its consumer half
    fn hand_over(&mut self) -> (TraceHandle, TraceContext) {
        self.handed_over = true;
        self.consumer
            .take()
            .expect("the consumer is registered right after `open_trace`")
    }
}

impl Drop for StartedSessionGuard<'_> {
    fn drop(&mut self) {
        if self.handed_over {
            return;
        }
        // Best-effort: this runs on a failure path whose original error is the one worth
        // reporting. A failed STOP is logged, as it leaves a live session behind.
        if let Some((trace_handle, context)) = self.consumer.take() {
            let _ignored_error_in_drop = close_trace(trace_handle, &context);
        }
        if let Err(err) = control_trace(
            self.properties,
            self.control_handle,
            Etw::EVENT_TRACE_CONTROL_STOP,
        ) {
            log::error!(
                "failed to stop a session that `TraceBuilder::start` could not finish building: \
                 {err:?}"
            );
        }
    }
}

impl<T: RealTimeTraceTrait + PrivateRealTimeTraceTrait> TraceBuilder<T> {
    /// Define the trace name
    ///
    /// For kernel traces on Windows Versions older than Win8, this method won't change the trace
    /// name. In those versions the trace name will be set to "NT Kernel Logger".
    ///
    /// Note: this trace name may be truncated to a few hundred characters if it is too long.
    #[must_use]
    pub fn named(mut self, name: String) -> Self {
        if T::TRACE_KIND == private::TraceKind::Kernel && !version_helper::is_win8_or_greater() {
            self.name = String::from(KERNEL_LOGGER_NAME);
        } else {
            self.name = name;
        }

        self
    }

    /// Define several low-level properties of the trace at once.
    ///
    /// These are part of [`EVENT_TRACE_PROPERTIES`](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::trace::{ClockType, TraceProperties, UserTrace};
    /// let props = TraceProperties {
    ///     clock_type: ClockType::SystemTime,
    ///     ..Default::default()
    /// };
    /// let builder = UserTrace::new().set_trace_properties(props);
    /// ```
    #[must_use]
    pub fn set_trace_properties(mut self, props: TraceProperties) -> Self {
        self.properties = props;
        self
    }

    /// Define a dump file for the events.
    ///
    /// If set, events will be dumped to a file on disk.<br/>
    /// Such files usually have a `.etl` extension.<br/>
    /// Dumped events will also be processed by the callbacks you'll specify with
    /// [`crate::provider::ProviderBuilder::add_callback`].
    ///
    /// It is possible to control many aspects of the logging file (whether its size is limited,
    /// whether it should be a circular buffer file, etc.). If you're not sure, `params` has a
    /// safe [`default` value](`DumpFileParams::default`).
    ///
    /// Note: the file name may be truncated to a few hundred characters if it is too long.
    #[must_use]
    pub fn set_etl_dump_file(mut self, params: DumpFileParams) -> Self {
        self.etl_dump_file = Some(params);
        self
    }

    /// Enable a Provider for this trace
    ///
    /// This will invoke the provider's callback whenever an event is available
    ///
    /// # Note
    /// The provider is enabled when the trace is started. Providers can also be
    /// enabled (or disabled) later, on a running trace, through
    /// [`UserTrace::enable_provider`] and [`UserTrace::disable_provider`]
    /// (user traces only, see <https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks>)
    #[must_use]
    pub fn enable(self, provider: Provider) -> Self {
        self.rt_callback_data.add_provider(provider);
        self
    }

    #[must_use]
    pub fn stop_if_exist(mut self, b: bool) -> Self {
        self.stop_if_exist = b;
        self
    }

    /// Build the `UserTrace` and start the trace session
    ///
    /// Internally, this calls the `StartTraceW`, `EnableTraceEx2` and `OpenTraceW`.
    ///
    /// To start receiving events, you'll still have to call either:
    /// * Worst option: `process()` on the returned `T`. This will block the current thread until
    ///   the trace is stopped.<br/> This means you'll probably want to call this on a spawned
    ///   thread, where the `T` must be moved to. This will prevent you from re-using it from the
    ///   another thread.<br/> This means you will not be able to explicitly stop the trace, because
    ///   you'll no longer have a `T` to drop or to call `stop` on. The trace will stop when the
    ///   program exits, or when the ETW API hits an error.<br/>
    /// * Most powerful option: `T::process_from_handle()` with the returned [`TraceHandle`].<br/>
    ///   This will block, so this also has to be run in a spawned thread. But, as this does not
    ///   "consume" the `T`, you'll be able to call `stop` on it (or to drop it) to explicitly close
    ///   the trace. Stopping a trace will make the `process` function return.
    /// * Easiest option: [`TraceBuilder::start_and_process()`].<br/> This convenience function
    ///   spawns a thread for you, call [`TraceBuilder::start`] on the trace, and returns
    ///   immediately.<br/> This option returns a `T`, so you can explicitly stop the trace, but
    ///   there is no way to get the status code of the ProcessTrace API.
    ///
    /// If a failure happens once the session is already running (a rejected provider enable,
    /// a failed `OpenTraceW`, ...), the half-built session is stopped (and its consumer
    /// closed) before the error is returned: no session is left running behind the caller's
    /// back.
    pub fn start(self) -> TraceResult<(T, TraceHandle)> {
        if self.stop_if_exist {
            stop_trace_by_name(&self.name)?;
        }
        // Prepare a wide version of the trace name
        let trace_wide_name = U16CString::from_str_truncate(self.name);
        let mut trace_wide_vec = trace_wide_name.into_vec();
        trace_wide_vec.truncate(crate::native::etw_types::TRACE_NAME_MAX_CHARS);
        let trace_wide_name = U16CString::from_vec_truncate(trace_wide_vec);

        // Prepare a wide version of the ETL dump file path
        let wide_etl_dump_file = match self.etl_dump_file {
            None => None,
            Some(DumpFileParams {
                file_path,
                file_logging_mode,
                max_size,
            }) => {
                let wide_path = U16CString::from_os_str_truncate(file_path.as_os_str());
                let mut wide_path_vec = wide_path.into_vec();
                wide_path_vec.truncate(crate::native::etw_types::TRACE_NAME_MAX_CHARS);
                Some((
                    U16CString::from_vec_truncate(wide_path_vec),
                    file_logging_mode,
                    max_size,
                ))
            },
        };

        let flags = self.rt_callback_data.provider_flags::<T>();
        let (mut full_properties, control_handle) = start_trace::<T>(
            &trace_wide_name,
            wide_etl_dump_file
                .as_ref()
                .map(|(path, params, max_size)| (path.as_ucstr(), *params, *max_size)),
            &self.properties,
            flags,
        )?;

        // From here on, a session is running in the kernel: any failure must stop it on
        // the way out, or it would keep running under a name the caller never sees
        let mut started = StartedSessionGuard {
            properties: &mut full_properties,
            control_handle,
            consumer: None,
            handed_over: false,
        };

        // Kernel-only TraceSetInformation configuration, applied between StartTraceW and
        // OpenTraceW (the control handle is valid as soon as the session is started, and the
        // settings must be in place before events start flowing)
        if T::TRACE_KIND == private::TraceKind::Kernel {
            enable_stack_tracing(control_handle, &self.stack_tracing_events)?;
            set_extended_kernel_groups(control_handle, &self.extended_kernel_groups)?;
        }

        if T::TRACE_KIND == private::TraceKind::User {
            for prov in self.rt_callback_data.providers() {
                enable_provider(control_handle, &prov)?;
            }
        }

        let (trace_handle, context) = open_trace(
            SubscriptionSource::RealTimeSession(trace_wide_name),
            Arc::new(CallbackData::RealTime(self.rt_callback_data)),
        )?;
        // Registered before anything that may fail past this point: a failure from here on
        // must close the consumer, not just stop the session
        started.consumer = Some((trace_handle, context));

        // Request provider states (rundown) now that the consumer is attached:
        // real-time sessions drop events nobody listens to, so this must happen
        // after `open_trace` (same ordering as krabsetw, which fires it right
        // before ProcessTrace)
        if T::TRACE_KIND == private::TraceKind::User {
            if let Some((_, context)) = started.consumer.as_ref() {
                if let CallbackData::RealTime(rt) = &**context {
                    for prov in rt.providers() {
                        if prov.requests_capture_state() {
                            capture_provider_state(control_handle, &prov)?;
                        }
                    }
                }
            }
        }

        // The built trace now owns the session. The guard holds a mutable borrow of
        // `full_properties`, and a type with `Drop` keeps its borrows until the end of
        // the scope: end it explicitly, so the properties can move into `T::build`
        let (trace_handle, context) = started.hand_over();
        drop(started);
        Ok((
            T::build(full_properties, control_handle, trace_handle, context),
            trace_handle,
        ))
    }

    /// Build the `UserTrace` by opening a trace session, without starting it
    ///
    /// Internally, this calls the `OpenTraceW`.
    ///
    /// This function is to be used when you want to receive events on a trace you don't own.
    /// This can be useful when dealing with sources that only authorize one trace to be created,
    /// such as EventLog-Security.
    ///
    /// Since the trace is not owed, it cannot be stopped using StopTraceW or controlled using
    /// ControlTraceW, but can be closed using CloseTraceW.
    ///
    /// To start receiving events, see the [`TraceBuilder::start`] function to see the options,
    /// while keeping in mind that the trace cannot be stopped.
    pub fn open_existing(self) -> TraceResult<(T, TraceHandle)> {
        // Prepare a wide version of the trace name
        let trace_wide_name = U16CString::from_str_truncate(self.name);
        let mut trace_wide_vec = trace_wide_name.into_vec();
        trace_wide_vec.truncate(crate::native::etw_types::TRACE_NAME_MAX_CHARS);
        let trace_wide_name = U16CString::from_vec_truncate(trace_wide_vec);

        let flags = self.rt_callback_data.provider_flags::<T>();

        // Prepare a wide version of the ETL dump file path
        let wide_etl_dump_file = match self.etl_dump_file {
            None => None,
            Some(DumpFileParams {
                file_path,
                file_logging_mode,
                max_size,
            }) => {
                let wide_path = U16CString::from_os_str_truncate(file_path.as_os_str());
                let mut wide_path_vec = wide_path.into_vec();
                wide_path_vec.truncate(crate::native::etw_types::TRACE_NAME_MAX_CHARS);
                Some((
                    U16CString::from_vec_truncate(wide_path_vec),
                    file_logging_mode,
                    max_size,
                ))
            },
        };

        let (trace_handle, context) = open_trace(
            SubscriptionSource::RealTimeSession(trace_wide_name.clone()),
            Arc::new(CallbackData::RealTime(self.rt_callback_data)),
        )
        .map_err(TraceError::EtwNativeError)?;

        // Build the User/Kernel Trace using an invalid ControlHandle (value is 0)
        // This Trace will fail to stop, but the handle can still be closed to stop receiving events
        Ok((
            T::build(
                EventTraceProperties::new::<T>(
                    &trace_wide_name,
                    wide_etl_dump_file
                        .as_ref()
                        .map(|(path, params, max_size)| (path.as_ucstr(), *params, *max_size)),
                    &self.properties,
                    flags,
                ),
                ControlHandle { Value: 0 },
                trace_handle,
                context,
            ),
            trace_handle,
        ))
    }

    /// Convenience method that calls [`TraceBuilder::start`] then `process`
    ///
    /// # Notes
    /// * See the documentation of [`TraceBuilder::start`] for more info
    /// * `process` is called on a spawned thread, and thus this method does not give any way to
    ///   retrieve the error of `process` (if any)
    pub fn start_and_process(self) -> TraceResult<T> {
        let (trace, trace_handle) = self.start()?;

        std::thread::spawn(move || T::process_from_handle(trace_handle));

        Ok(trace)
    }
}

// Settings that only make sense for kernel traces. A dedicated impl block (rather than methods
// on the generic builder) makes them impossible to set on a `UserTrace` builder at compile time.
impl TraceBuilder<KernelTrace> {
    /// Collect call stacks for these kernel events
    ///
    /// This is the kernel-trace counterpart of user traces'
    /// [`EVENT_ENABLE_PROPERTY_STACK_TRACE`](crate::provider::TraceFlags::EVENT_ENABLE_PROPERTY_STACK_TRACE):
    /// kernel loggers ignore that flag, and stacks are instead enabled per event through the
    /// `TraceStackTracingInfo` info class. Per the Windows SDK, the given list replaces any
    /// previous one: events absent from it will not carry stacks.
    ///
    /// The events must also be enabled themselves (e.g. syscall stacks need the
    /// [`SYSTEM_CALL_PROVIDER`](crate::provider::kernel_providers::SYSTEM_CALL_PROVIDER)),
    /// and stack collection requires the `SeSystemProfilePrivilege` privilege on the process.
    ///
    /// # Example
    /// ```no_run
    /// # use ferrisetw::provider::{Provider, kernel_providers};
    /// # use ferrisetw::trace::{KernelTrace, StackTracingEvent};
    /// let syscall_provider = Provider::kernel(&kernel_providers::SYSTEM_CALL_PROVIDER).build();
    /// let trace = KernelTrace::new()
    ///     .enable(syscall_provider)
    ///     .set_stack_tracing(vec![
    ///         StackTracingEvent::SYSCALL_ENTER,
    ///         StackTracingEvent::SYSCALL_EXIT,
    ///     ])
    ///     .start(); // starting a kernel trace requires administrator privileges
    /// ```
    #[must_use]
    pub fn set_stack_tracing(mut self, events: Vec<StackTracingEvent>) -> Self {
        self.stack_tracing_events = events;
        self
    }

    /// Enable these fine-grained kernel event groups (see [`ExtendedKernelGroup`])
    ///
    /// Unlike the classic kernel groups of
    /// [`kernel_providers`](crate::provider::kernel_providers), these cannot be set through
    /// `EVENT_TRACE_PROPERTIES::EnableFlags`: they are applied to the session's extended group
    /// mask when the trace is started, on top of the groups already enabled. Requires
    /// Windows 8 or later.
    #[must_use]
    pub fn set_extended_groups(mut self, groups: Vec<ExtendedKernelGroup>) -> Self {
        self.extended_kernel_groups = groups;
        self
    }
}

impl FileTrace {
    /// Create a trace that will read events from a file
    #[allow(clippy::new_ret_no_self)]
    pub fn new<T>(path: PathBuf, callback: T) -> FileTraceBuilder
    where
        T: FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static,
    {
        FileTraceBuilder {
            etl_file_path: path,
            callback: Box::new(callback),
        }
    }

    fn non_consuming_stop(&mut self) -> TraceResult<()> {
        close_trace(self.trace_handle, &self.context)?;
        Ok(())
    }
}

impl FileTraceBuilder {
    /// Build the `FileTrace` and start the trace session
    ///
    /// See the documentation for [`TraceBuilder::start`] for more information.
    pub fn start(self) -> TraceResult<(FileTrace, TraceHandle)> {
        // Prepare a wide version of the source ETL file path
        let wide_etl_file_path = U16CString::from_os_str_truncate(self.etl_file_path.as_os_str());

        let from_file_cb = CallbackDataFromFile::new(self.callback);
        let (trace_handle, context) = open_trace(
            SubscriptionSource::FromFile(wide_etl_file_path),
            Arc::new(CallbackData::FromFile(from_file_cb)),
        )?;

        Ok((
            FileTrace {
                trace_handle,
                context,
            },
            trace_handle,
        ))
    }

    /// Convenience method that calls [`TraceBuilder::start`] then `process`
    ///
    /// # Notes
    /// * See the documentation of [`TraceBuilder::start`] for more info
    /// * `process` is called on a spawned thread, and thus this method does not give any way to
    ///   retrieve the error of `process` (if any)
    pub fn start_and_process(self) -> TraceResult<FileTrace> {
        let (trace, trace_handle) = self.start()?;

        std::thread::spawn(move || FileTrace::process_from_handle(trace_handle));

        Ok(trace)
    }
}

impl Drop for UserTrace {
    fn drop(&mut self) {
        let _ignored_error_in_drop = self.non_consuming_stop();
    }
}

impl Drop for KernelTrace {
    fn drop(&mut self) {
        let _ignored_error_in_drop = self.non_consuming_stop();
    }
}

impl Drop for FileTrace {
    fn drop(&mut self) {
        let _ignored_error_in_drop = self.non_consuming_stop();
    }
}

/// Stop a trace given its name.
///
/// This function is intended to close a trace you did not start yourself.
/// Otherwise, you should prefer [`UserTrace::stop()`] or [`KernelTrace::stop()`]
pub fn stop_trace_by_name(trace_name: &str) -> TraceResult<()> {
    let trace_properties = TraceProperties::default();
    let flags = Etw::EVENT_TRACE_FLAG::default();
    let wide_name = U16CString::from_str(trace_name).map_err(|_| TraceError::InvalidTraceName)?;

    let mut properties = EventTraceProperties::new::<UserTrace>(
        // for EVENT_TRACE_CONTROL_STOP, we don't really care about most of the contents of the
        // EventTraceProperties, so using new::<UserTrace>() is fine, even when stopping a kernel
        // trace
        &wide_name,
        None, /* MSDN says the dump file name (if any) must be populated for a
               * EVENT_TRACE_CONTROL_STOP, but experience shows this is not necessary. */
        &trace_properties,
        flags,
    );

    let result = control_trace_by_name(&mut properties, &wide_name, Etw::EVENT_TRACE_CONTROL_STOP);
    match result {
        // A not-running trace is not an error: there is simply nothing to stop
        Ok(()) | Err(ERROR_WMI_INSTANCE_NOT_FOUND) => {},
        Err(status) => return Err(TraceError::EtwNativeError(win32_error(status))),
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        native::etw_types::PerfinfoGroupmask, provider::kernel_providers::SYSTEM_CALL_PROVIDER,
    };

    /// A `UserTrace` whose control handle is invalid (value 0), as if it had
    /// been obtained through `open_existing`: enough to exercise the runtime
    /// provider registry and the error paths of enable/disable, without an
    /// actual ETW session (which would need administrator privileges)
    fn trace_without_session(providers: Vec<Provider>) -> UserTrace {
        let rt_callback_data = RealTimeCallbackData::new();
        for provider in providers {
            rt_callback_data.add_provider(provider);
        }
        let wide_name = U16CString::from_str_truncate("ferrisetw-test-trace");
        UserTrace {
            properties: EventTraceProperties::new::<UserTrace>(
                &wide_name,
                None,
                &TraceProperties::default(),
                Etw::EVENT_TRACE_FLAG::default(),
            ),
            control_handle: ControlHandle { Value: 0 },
            trace_handle: TraceHandle { Value: 0 },
            context: TraceContext::new(Arc::new(CallbackData::RealTime(rt_callback_data))),
        }
    }

    #[test]
    fn test_enable_multiple_providers() {
        let prov = Provider::by_guid(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716).build();
        let prov1 = Provider::by_guid(0xa0c1853b_5c40_4b15_8766_3cf1c58f985a).build();

        let trace_builder = UserTrace::new().enable(prov).enable(prov1);

        assert_eq!(trace_builder.rt_callback_data.providers().len(), 2);
    }

    #[test]
    fn runtime_enable_without_control_handle_fails_and_rolls_back() {
        let trace = trace_without_session(vec![Provider::by_guid(0x1111).build()]);

        let result = trace.enable_provider(Provider::by_guid(0x2222).build());
        assert!(matches!(
            result,
            Err(TraceError::EtwNativeError(
                EvntraceNativeError::InvalidHandle
            ))
        ));
        // The pre-existing registration is intact, the failed one was rolled back
        assert_eq!(trace.providers().len(), 1);
        assert_eq!(trace.providers()[0].guid(), GUID::from_u128(0x1111));
    }

    #[test]
    fn runtime_disable_without_control_handle_fails_and_keeps_the_registry() {
        let guid = GUID::from_u128(0x1111);
        let trace = trace_without_session(vec![Provider::by_guid(guid).build()]);

        let result = trace.disable_provider(guid);
        assert!(matches!(
            result,
            Err(TraceError::EtwNativeError(
                EvntraceNativeError::InvalidHandle
            ))
        ));
        assert_eq!(trace.providers().len(), 1);

        // A GUID nothing is registered under is a no-op, session untouched
        assert_eq!(trace.disable_provider(GUID::from_u128(0x3333)).unwrap(), 0);
    }

    /// A `UserTrace` handle that may be borrowed from several threads
    ///
    /// `UserTrace` itself is not `Sync` (its properties embed raw pointers),
    /// but nothing in the mutation paths under test touches them: they only
    /// use `CallbackData`, whose interior mutability is fully synchronized
    /// (atomics, registry `RwLock`, session-mutation mutex).
    #[derive(Debug)]
    struct SharedTrace(UserTrace);

    // Safety: see the type documentation
    unsafe impl Sync for SharedTrace {}

    impl SharedTrace {
        fn enable_provider(&self, provider: Provider) -> TraceResult<()> {
            self.0.enable_provider(provider)
        }

        fn disable_provider(&self, guid: GUID) -> TraceResult<usize> {
            self.0.disable_provider(guid)
        }

        fn providers(&self) -> Vec<Arc<Provider>> {
            self.0.providers()
        }
    }

    #[test]
    fn concurrent_provider_mutations_wait_for_each_other() {
        // A session mutation (runtime enable or disable) holds the mutation
        // lock across its OS call and registry update: a concurrent mutation
        // must wait instead of interleaving (which could leave a provider
        // enabled at the OS level but unregistered). Here the "OS call" of
        // both workers deterministically fails (invalid control handle), so
        // the final registry must come out unchanged.
        let trace = SharedTrace(trace_without_session(vec![
            Provider::by_guid(0x1111).build(),
        ]));
        let CallbackData::RealTime(rt) = &*trace.0.context else {
            unreachable!("a UserTrace always holds real-time callback data");
        };
        let mutation_in_flight = rt.lock_session_mutations();

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::scope(|s| {
            let disabler = s.spawn(|| {
                let result = trace.disable_provider(GUID::from_u128(0x1111));
                let _ = done_tx.send(());
                result
            });
            let enabler = s.spawn(|| {
                let result = trace.enable_provider(Provider::by_guid(0x2222).build());
                let _ = done_tx.send(());
                result
            });

            // While the lock is held, neither mutation may complete
            assert!(done_rx.recv_timeout(Duration::from_millis(200)).is_err());
            drop(mutation_in_flight);
            for _ in 0..2 {
                done_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("both mutations completed once the lock was released");
            }

            // Both proceeded past the lock and failed at the (invalid) OS
            // level: the disable kept its registration, the enable rolled back
            assert!(matches!(
                disabler.join().unwrap(),
                Err(TraceError::EtwNativeError(
                    EvntraceNativeError::InvalidHandle
                ))
            ));
            assert!(matches!(
                enabler.join().unwrap(),
                Err(TraceError::EtwNativeError(
                    EvntraceNativeError::InvalidHandle
                ))
            ));
        });
        assert_eq!(trace.providers().len(), 1);
        assert_eq!(trace.providers()[0].guid(), GUID::from_u128(0x1111));
    }

    #[test]
    fn syscall_stack_tracing_events_match_the_perfinfo_provider() {
        // PERF_INFO_GUID must not drift from kernel_providers' definition
        assert_eq!(
            StackTracingEvent::SYSCALL_ENTER.event_guid,
            SYSTEM_CALL_PROVIDER.guid
        );
        assert_eq!(
            StackTracingEvent::SYSCALL_EXIT.event_guid,
            SYSTEM_CALL_PROVIDER.guid
        );
        assert_eq!(StackTracingEvent::SYSCALL_ENTER.event_type, 46);
        assert_eq!(StackTracingEvent::SYSCALL_EXIT.event_type, 47);
    }

    #[test]
    fn extended_kernel_groups_encode_into_the_groupmask() {
        let mut groupmask = PerfinfoGroupmask::default();
        groupmask.set_groups(&[
            ExtendedKernelGroup::Memory,
            ExtendedKernelGroup::PoolTrace,
            ExtendedKernelGroup::Heap,
            ExtendedKernelGroup::ObHandle,
            ExtendedKernelGroup::SysCfgAll,
            ExtendedKernelGroup::MemoryControl,
        ]);

        assert_eq!(groupmask.masks(), &[
            0,
            0x41,
            0x20,
            0,
            0x40,
            0,
            0x1fff_ffff,
            2
        ]);
    }

    #[test]
    fn overlapping_and_empty_extended_groups_merge_correctly() {
        // PoolTrace is Pool plus another group: applying both must not double anything
        let mut groupmask = PerfinfoGroupmask::default();
        groupmask.set_groups(&[ExtendedKernelGroup::PoolTrace, ExtendedKernelGroup::Pool]);
        assert_eq!(groupmask.masks()[1], 0x41);

        groupmask.set_groups(&[]);
        assert_eq!(groupmask.masks()[1], 0x41);
    }

    #[test]
    fn kernel_trace_builder_stores_kernel_only_settings() {
        let builder = KernelTrace::new()
            .set_stack_tracing(vec![StackTracingEvent::SYSCALL_ENTER])
            .set_extended_groups(vec![ExtendedKernelGroup::Pool]);

        assert_eq!(builder.stack_tracing_events, [
            StackTracingEvent::SYSCALL_ENTER
        ]);
        assert_eq!(builder.extended_kernel_groups, [ExtendedKernelGroup::Pool]);
    }

    #[test]
    fn trace_statistics_are_mapped_from_the_native_properties() {
        use windows::Win32::Foundation::HANDLE;

        // Simulate what ControlTraceW(QUERY) does: an EVENT_TRACE_PROPERTIES whose
        // statistics fields have been filled in
        let native = Etw::EVENT_TRACE_PROPERTIES {
            EventsLost: 11,
            LogBuffersLost: 22,
            RealTimeBuffersLost: 33,
            BuffersWritten: 44,
            NumberOfBuffers: 55,
            FreeBuffers: 66,
            LoggerThreadId: HANDLE(std::ptr::with_exposed_provenance_mut(0x1a2b)),
            ..Default::default()
        };

        assert_eq!(TraceStatistics::from_properties(&native), TraceStatistics {
            events_lost: 11,
            log_buffers_lost: 22,
            real_time_buffers_lost: 33,
            buffers_written: 44,
            number_of_buffers: 55,
            free_buffers: 66,
            logger_thread_id: 0x1a2b,
        });

        // Everything zeroed (e.g. before any event was processed) maps to zeroed statistics
        let zeroed = Etw::EVENT_TRACE_PROPERTIES::default();
        assert_eq!(
            TraceStatistics::from_properties(&zeroed).logger_thread_id,
            0
        );
    }
}
