//! ETW Providers abstraction.
//!
//! Provides an abstraction over an [ETW Provider](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing#providers)
use std::{
    convert::TryFrom,
    sync::{Arc, Mutex},
};

use windows::core::GUID;

use crate::{
    native::{etw_types::event_record::EventRecord, pla},
    schema_locator::SchemaLocator,
};

pub(crate) mod event_filter;
pub use event_filter::EventFilter;

pub mod kernel_providers;
mod trace_flags;
pub use trace_flags::TraceFlags;

/// Provider module errors
#[derive(Debug)]
pub enum ProviderError {
    /// Wrapper over an internal [PlaError](crate::native::PlaError)
    ComProvider(crate::native::PlaError),
}

impl From<crate::native::PlaError> for ProviderError {
    fn from(err: crate::native::PlaError) -> Self {
        ProviderError::ComProvider(err)
    }
}

/// Describes an ETW Provider to use, along with its options
pub struct Provider {
    /// Provider GUID
    guid: GUID,
    /// Provider Any keyword
    any: u64,
    /// Provider All keyword
    all: u64,
    /// Provider level flag
    level: u8,
    /// Provider trace flags
    ///
    /// Used as `EnableParameters.EnableProperty` when starting the trace (using [EnableTraceEx2](https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2))
    trace_flags: TraceFlags,
    /// Provider kernel flags, only apply to KernelProvider
    kernel_flags: u32,
    /// Whether the provider should be asked for its state (rundown) when the
    /// trace starts
    capture_state: bool,
    /// Provider filters
    filters: Vec<EventFilter>,
    /// Callbacks that will receive events from this Provider
    // A Mutex rather than a RwLock: callbacks are FnMut, so every event takes
    // an exclusive lock anyway, and an uncontended Mutex is cheaper than a
    // RwLock write lock
    callbacks: Arc<Mutex<Vec<crate::EtwCallback>>>,
}

/// A Builder for a `Provider`
///
/// See [`Provider`] for various functions that create `ProviderBuilder`s.
pub struct ProviderBuilder {
    guid: GUID,
    any: u64,
    all: u64,
    level: u8,
    trace_flags: TraceFlags,
    kernel_flags: u32,
    capture_state: bool,
    filters: Vec<EventFilter>,
    callbacks: Arc<Mutex<Vec<crate::EtwCallback>>>,
}

impl std::fmt::Debug for ProviderBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderBuilder")
            .field("guid", &self.guid)
            .field("any", &self.any)
            .field("all", &self.all)
            .field("level", &self.level)
            .field("trace_flags", &self.trace_flags)
            .field("kernel_flags", &self.kernel_flags)
            .field("capture_state", &self.capture_state)
            .field("filters", &self.filters)
            .field("n_callbacks", &self.callbacks.lock().unwrap().len())
            .finish()
    }
}

/// Types that can be converted into a provider [`GUID`].
///
/// This is a substitute for the `Into<GUID>` bound that used to accept GUID
/// string literals: windows-core 0.61.2 removed its `From<&str> for GUID`
/// implementation (only fallible `TryFrom<&str>` remains), which would break
/// `Provider::by_guid("22fb2cd6-...")` and every doc example of this crate.
pub trait IntoGuid {
    /// Consumes self, returning the equivalent [`GUID`]
    fn into_guid(self) -> GUID;
}

impl IntoGuid for GUID {
    fn into_guid(self) -> GUID {
        self
    }
}

impl IntoGuid for u128 {
    fn into_guid(self) -> GUID {
        GUID::from(self)
    }
}

impl IntoGuid for &str {
    fn into_guid(self) -> GUID {
        GUID::try_from(self).unwrap_or_else(|_| panic!("invalid GUID string: {self:?}"))
    }
}

// Create builders
impl Provider {
    /// Create a Provider defined by its GUID
    ///
    /// Many types are acceptable as argument: `GUID` themselves, `u128` values
    /// and `&str` strings such as `"22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716"`.
    pub fn by_guid<G: IntoGuid>(guid: G) -> ProviderBuilder {
        ProviderBuilder {
            guid: guid.into_guid(),
            any: 0,
            all: 0,
            level: 5,
            trace_flags: TraceFlags::empty(),
            kernel_flags: 0,
            capture_state: false,
            filters: Vec::new(),
            callbacks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a Kernel Provider
    ///
    /// You can pass either a KernelProvider you have created yourself, or one of the standard
    /// providers from [`crate::provider::kernel_providers`].
    #[must_use]
    pub fn kernel(kernel_provider: &kernel_providers::KernelProvider) -> ProviderBuilder {
        let mut builder = Self::by_guid(kernel_provider.guid);
        builder.kernel_flags = kernel_provider.flags;
        builder
    }

    /// Create a Provider defined by its name.
    ///
    /// This function will look for the Provider GUID by means of the [ITraceDataProviderCollection](https://docs.microsoft.com/en-us/windows/win32/api/pla/nn-pla-itracedataprovidercollection)
    /// interface.
    ///
    /// # Remark
    /// This function is considerably slow, prefer using the `by_guid` function when possible
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::provider::Provider;
    /// let my_provider = Provider::by_name("Microsoft-Windows-WinINet")
    ///     .unwrap()
    ///     .build();
    /// ```
    pub fn by_name(name: &str) -> Result<ProviderBuilder, crate::native::PlaError> {
        let guid = unsafe { pla::get_provider_guid(name) }?;
        Ok(Self::by_guid(guid))
    }
}

// Actually use the Provider
impl Provider {
    #[must_use]
    pub fn guid(&self) -> GUID {
        self.guid
    }

    #[must_use]
    pub fn any(&self) -> u64 {
        self.any
    }

    #[must_use]
    pub fn all(&self) -> u64 {
        self.all
    }

    #[must_use]
    pub fn level(&self) -> u8 {
        self.level
    }

    #[must_use]
    pub fn trace_flags(&self) -> TraceFlags {
        self.trace_flags
    }

    #[must_use]
    pub fn kernel_flags(&self) -> u32 {
        self.kernel_flags
    }

    /// Whether the provider is asked for its state (rundown) when the trace
    /// starts
    ///
    /// Set through [`ProviderBuilder::request_capture_state`]
    #[must_use]
    pub fn requests_capture_state(&self) -> bool {
        self.capture_state
    }

    #[must_use]
    pub fn filters(&self) -> &[EventFilter] {
        &self.filters
    }

    pub(crate) fn on_event(&self, record: &EventRecord, locator: &SchemaLocator) {
        if let Ok(mut callbacks) = self.callbacks.lock() {
            callbacks.iter_mut().for_each(|cb| cb(record, locator));
        }
    }
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider")
            .field("guid", &self.guid)
            .field("any", &self.any)
            .field("all", &self.all)
            .field("level", &self.level)
            .field("trace_flags", &self.trace_flags)
            .field("kernel_flags", &self.kernel_flags)
            .field("capture_state", &self.capture_state)
            .field("filters", &self.filters)
            .field("callbacks", &self.callbacks.lock().unwrap().len())
            .finish()
    }
}

impl ProviderBuilder {
    /// Set the `any` flag in the Provider instance
    /// [More info](https://docs.microsoft.com/en-us/message-analyzer/system-etw-provider-event-keyword-level-settings#filtering-with-system-etw-provider-event-keywords-and-levels)
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::provider::Provider;
    /// let my_provider = Provider::by_guid("1EDEEE53-0AFE-4609-B846-D8C0B2075B1F")
    ///     .any(0xf0010000000003ff)
    ///     .build();
    /// ```
    #[must_use]
    pub fn any(mut self, any: u64) -> Self {
        self.any = any;
        self
    }

    /// Set the `all` flag in the Provider instance
    /// [More info](https://docs.microsoft.com/en-us/message-analyzer/system-etw-provider-event-keyword-level-settings#filtering-with-system-etw-provider-event-keywords-and-levels)
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::provider::Provider;
    /// let my_provider = Provider::by_guid("1EDEEE53-0AFE-4609-B846-D8C0B2075B1F")
    ///     .all(0x4000000000000000)
    ///     .build();
    /// ```
    #[must_use]
    pub fn all(mut self, all: u64) -> Self {
        self.all = all;
        self
    }

    /// Set the `level` flag in the Provider instance
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::provider::{Provider};
    /// // LogAlways (0x0)
    /// // Critical (0x1)
    /// // Error (0x2)
    /// // Warning (0x3)
    /// // Information (0x4)
    /// // Verbose (0x5)
    /// let my_provider = Provider::by_guid("1EDEEE53-0AFE-4609-B846-D8C0B2075B1F")
    ///     .level(0x5)
    ///     .build();
    /// ```
    #[must_use]
    pub fn level(mut self, level: u8) -> Self {
        self.level = level;
        self
    }

    /// Set the `trace_flags` flag in the Provider instance
    /// [More info](https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/trace-flags)
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::provider::{Provider, TraceFlags};
    /// let my_provider = Provider::by_guid("1EDEEE53-0AFE-4609-B846-D8C0B2075B1F")
    ///     .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_SID)
    ///     .build();
    /// ```
    #[must_use]
    pub fn trace_flags(mut self, trace_flags: TraceFlags) -> Self {
        self.trace_flags = trace_flags;
        self
    }

    /// Ask this provider to log its state information (a.k.a. rundown) when
    /// the trace starts
    ///
    /// This sends an `EVENT_CONTROL_CODE_CAPTURE_STATE` request to the
    /// provider. State-based providers (e.g. those that can enumerate loaded
    /// images, open files or handles) only emit their current state upon this
    /// request, so they need it to appear in the trace at all.
    ///
    /// For a [`UserTrace`](crate::trace::UserTrace), the request is sent right
    /// after the consumer is attached (rundown events would be dropped with no
    /// consumer listening), and can be re-sent at any time with
    /// [`UserTrace::request_capture_state`](crate::trace::UserTrace::request_capture_state).
    /// This is a no-op for kernel trace providers: their rundown goes through
    /// another (undocumented) mechanism.
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::provider::Provider;
    /// let provider = Provider::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716") // Microsoft-Windows-Kernel-Process
    ///     .request_capture_state()
    ///     .build();
    /// ```
    #[must_use]
    pub fn request_capture_state(mut self) -> Self {
        self.capture_state = true;
        self
    }

    /// Add a callback function that will be called when the Provider generates an Event
    ///
    /// # Notes
    ///
    /// The callback will be run on a background thread (the one that is blocked on the `process`
    /// function).
    ///
    /// # Example
    /// ```no_run
    /// # use ferrisetw::provider::Provider;
    /// # use ferrisetw::trace::UserTrace;
    /// # use ferrisetw::EventRecord;
    /// # use ferrisetw::schema_locator::SchemaLocator;
    /// let provider = Provider::by_guid("1EDEEE53-0AFE-4609-B846-D8C0B2075B1F")
    ///     .add_callback(|record: &EventRecord, schema_locator: &SchemaLocator| {
    ///         // Handle Event
    ///     })
    ///     .build();
    /// UserTrace::new().enable(provider).start().unwrap();
    /// ```
    ///
    /// [SchemaLocator]: crate::schema_locator::SchemaLocator
    #[must_use]
    pub fn add_callback<T>(self, callback: T) -> Self
    where
        T: FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static,
    {
        if let Ok(mut callbacks) = self.callbacks.lock() {
            callbacks.push(Box::new(callback));
        }
        self
    }

    /// Add a filter to this Provider.
    ///
    /// Adding multiple filters will bind them with an `AND` relationship.<br/>
    /// If you want an `OR` relationship, include them in the same `EventFilter`.<br/>
    /// Note that Windows allows at most one filter of each type per provider
    /// (e.g. only one `EventFilter::ByEventIds`): adding more will make trace creation fail.
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::provider::{EventFilter, Provider};
    /// let only_events_18_or_42 = EventFilter::ByEventIds(vec![18, 42]);
    /// let only_pid_1234 = EventFilter::ByPids(vec![1234]);
    ///
    /// Provider::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716")
    ///     .add_filter(only_events_18_or_42)
    ///     .add_filter(only_pid_1234)
    ///     .build();
    /// ```
    #[must_use]
    pub fn add_filter(mut self, filter: EventFilter) -> Self {
        self.filters.push(filter);
        self
    }

    /// Build the provider
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::provider::Provider;
    /// # use ferrisetw::EventRecord;
    /// # use ferrisetw::schema_locator::SchemaLocator;
    /// # let process_callback = |_event: &EventRecord, _locator: &SchemaLocator| {};
    /// Provider::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716") // Microsoft-Windows-Kernel-Process
    ///     .add_callback(process_callback)
    ///     .build();
    /// ```
    // TODO: should we check if callbacks is empty ???
    #[must_use]
    pub fn build(self) -> Provider {
        Provider {
            guid: self.guid,
            any: self.any,
            all: self.all,
            level: self.level,
            trace_flags: self.trace_flags,
            kernel_flags: self.kernel_flags,
            capture_state: self.capture_state,
            filters: self.filters,
            callbacks: self.callbacks,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn by_guid_accepts_guid_u128_and_str() {
        let guid = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
        assert_eq!(Provider::by_guid(guid).build().guid(), guid);
        assert_eq!(
            Provider::by_guid(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716)
                .build()
                .guid(),
            guid
        );
        assert_eq!(
            Provider::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716")
                .build()
                .guid(),
            guid
        );
    }
}
