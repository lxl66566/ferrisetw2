//! ETW Event Schema and handler
//!
//! This module contains the means needed to interact with the Schema of an ETW event
use once_cell::sync::OnceCell;

use crate::native::{etw_types::DecodingSource, tdh::TraceEventInfo, tdh_types::Property};

/// A schema suitable for parsing a given kind of event.
///
/// It is usually retrieved from [`crate::schema_locator::SchemaLocator::event_schema`].
///
/// This structure is basically a wrapper over a [TraceEventInfo](https://docs.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-trace_event_info),
/// with a few info parsed (and cached) out of it
pub struct Schema {
    te_info: TraceEventInfo,
    cached_properties: OnceCell<Vec<Property>>,
    /// Extracting a name requires a UTF-16 -> String conversion of the raw
    /// `TRACE_EVENT_INFO` buffer; these values are constant per schema, and
    /// the serde path requests them for every serialized event
    cached_provider_name: OnceCell<String>,
    cached_task_name: OnceCell<String>,
    cached_opcode_name: OnceCell<String>,
}

impl Schema {
    pub(crate) fn new(te_info: TraceEventInfo) -> Self {
        Schema {
            te_info,
            cached_properties: OnceCell::new(),
            cached_provider_name: OnceCell::new(),
            cached_task_name: OnceCell::new(),
            cached_opcode_name: OnceCell::new(),
        }
    }

    /// Use the `decoding_source` function to obtain the [DecodingSource] from the
    /// `TRACE_EVENT_INFO`
    ///
    /// This getter returns the DecodingSource from the event, this value identifies the source used
    /// parse the event data
    ///
    /// # Example
    /// ```
    /// # use ferrisetw2::EventRecord;
    /// # use ferrisetw2::schema_locator::SchemaLocator;
    /// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    ///     let decoding_source = schema.decoding_source();
    /// };
    /// ```
    pub fn decoding_source(&self) -> DecodingSource {
        self.te_info.decoding_source()
    }

    /// Use the `provider_name` function to obtain the Provider name from the `TRACE_EVENT_INFO`
    ///
    /// # Example
    /// ```
    /// # use ferrisetw2::EventRecord;
    /// # use ferrisetw2::schema_locator::SchemaLocator;
    /// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    ///     let provider_name = schema.provider_name();
    /// };
    /// ```
    pub fn provider_name(&self) -> String {
        self.provider_name_cached().to_owned()
    }

    /// Cached variant of [`Schema::provider_name`], avoiding a copy
    pub(crate) fn provider_name_cached(&self) -> &str {
        self.cached_provider_name
            .get_or_init(|| self.te_info.provider_name())
    }

    /// Use the `task_name` function to obtain the Task name from the `TRACE_EVENT_INFO`
    ///
    /// See: [TaskType](https://docs.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-tasktype-complextype)
    /// # Example
    /// ```
    /// # use ferrisetw2::EventRecord;
    /// # use ferrisetw2::schema_locator::SchemaLocator;
    /// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    ///     let task_name = schema.task_name();
    /// };
    /// ```
    pub fn task_name(&self) -> String {
        self.task_name_cached().to_owned()
    }

    /// Cached variant of [`Schema::task_name`], avoiding a copy
    pub(crate) fn task_name_cached(&self) -> &str {
        self.cached_task_name
            .get_or_init(|| self.te_info.task_name())
    }

    /// Use the `opcode_name` function to obtain the Opcode name from the `TRACE_EVENT_INFO`
    ///
    /// See: [OpcodeType](https://docs.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-opcodetype-complextype)
    /// # Example
    /// ```
    /// # use ferrisetw2::EventRecord;
    /// # use ferrisetw2::schema_locator::SchemaLocator;
    /// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    ///     let opcode_name = schema.opcode_name();
    /// };
    /// ```
    pub fn opcode_name(&self) -> String {
        self.opcode_name_cached().to_owned()
    }

    /// Cached variant of [`Schema::opcode_name`], avoiding a copy
    pub(crate) fn opcode_name_cached(&self) -> &str {
        self.cached_opcode_name
            .get_or_init(|| self.te_info.opcode_name())
    }

    /// Parses the list of properties of the wrapped `TRACE_EVENT_INFO`
    ///
    /// Parsed on first call, then cached. Properties the crate cannot decode
    /// (e.g. `PROPERTY_HAS_CUSTOM_SCHEMA`) stay in the list, marked as
    /// [`crate::native::tdh_types::PropertyInfo::Unsupported`]: they occupy
    /// their bytes in the event buffer, so leaving them out would shift the
    /// offsets of every later property
    pub(crate) fn properties(&self) -> &[Property] {
        self.cached_properties
            .get_or_init(|| self.te_info.properties().collect())
            .as_slice()
    }
}

impl PartialEq for Schema {
    fn eq(&self, other: &Self) -> bool {
        self.te_info.event_id() == other.te_info.event_id()
            && self.te_info.provider_guid() == other.te_info.provider_guid()
            && self.te_info.event_version() == other.te_info.event_version()
    }
}

impl Eq for Schema {}
