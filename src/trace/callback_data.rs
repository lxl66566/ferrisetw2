use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustc_hash::FxHashMap;
use windows::Win32::System::Diagnostics::Etw;

use crate::EtwCallback;
use crate::native::etw_types::event_record::EventRecord;
use crate::provider::Provider;
use crate::schema_locator::SchemaLocator;
use crate::trace::RealTimeTraceTrait;
use windows::core::GUID;

/// Data used by callbacks when the trace is running
// NOTE: this structure is accessed in an unsafe block in a separate thread (see the `trace_callback_thunk` function)
//       Thus, this struct must not be mutated (outside of interior mutability and/or using Mutex and other synchronization mechanisms) when the associated trace is running.
#[derive(Debug)]
pub enum CallbackData {
    RealTime(RealTimeCallbackData),
    FromFile(CallbackDataFromFile),
}

#[derive(Debug)]
pub struct RealTimeCallbackData {
    /// Represents how many events have been handled so far
    events_handled: AtomicUsize,
    schema_locator: SchemaLocator,
    /// List of Providers associated with the Trace. This also owns the callback closures and their state
    providers: Vec<Provider>,
    /// Maps a provider GUID to the indices of `providers` with that GUID, so
    /// that `on_event` does not linearly scan every provider on each event
    providers_by_guid: FxHashMap<GUID, Vec<usize>>,
}

pub struct CallbackDataFromFile {
    /// Represents how many events have been handled so far
    events_handled: AtomicUsize,
    schema_locator: SchemaLocator,
    /// This trace is reading from an ETL file, and has a single callback
    callback: RwLock<EtwCallback>,
}

impl CallbackData {
    pub fn on_event(&self, record: &EventRecord) {
        match self {
            CallbackData::RealTime(rt_cb) => rt_cb.on_event(record),
            CallbackData::FromFile(f_cb) => f_cb.on_event(record),
        }
    }

    pub fn events_handled(&self) -> usize {
        match self {
            CallbackData::RealTime(rt_cb) => rt_cb.events_handled(),
            CallbackData::FromFile(f_cb) => f_cb.events_handled(),
        }
    }
}

impl std::default::Default for RealTimeCallbackData {
    fn default() -> Self {
        Self {
            events_handled: AtomicUsize::new(0),
            schema_locator: SchemaLocator::new(),
            providers: Vec::new(),
            providers_by_guid: HashMap::default(),
        }
    }
}

impl RealTimeCallbackData {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_provider(&mut self, provider: Provider) {
        self.providers_by_guid
            .entry(provider.guid())
            .or_default()
            .push(self.providers.len());
        self.providers.push(provider)
    }

    pub fn providers(&self) -> &[Provider] {
        &self.providers
    }

    /// How many events have been handled since this instance was created
    pub fn events_handled(&self) -> usize {
        self.events_handled.load(Ordering::Relaxed)
    }

    pub fn provider_flags<T: RealTimeTraceTrait>(&self) -> Etw::EVENT_TRACE_FLAG {
        Etw::EVENT_TRACE_FLAG(T::enable_flags(&self.providers))
    }

    pub fn on_event(&self, record: &EventRecord) {
        self.events_handled.fetch_add(1, Ordering::Relaxed);

        if let Some(providers) = self.providers_by_guid.get(&record.provider_id()) {
            for &prov_idx in providers {
                self.providers[prov_idx].on_event(record, &self.schema_locator);
            }
        }
    }
}

impl CallbackDataFromFile {
    pub fn new(callback: EtwCallback) -> Self {
        Self {
            events_handled: AtomicUsize::new(0),
            schema_locator: SchemaLocator::new(),
            callback: RwLock::new(callback),
        }
    }

    /// How many events have been handled since this instance was created
    pub fn events_handled(&self) -> usize {
        self.events_handled.load(Ordering::Relaxed)
    }

    pub fn on_event(&self, record: &EventRecord) {
        self.events_handled.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut cb) = self.callback.write() {
            cb(record, &self.schema_locator);
        }
    }
}

impl std::fmt::Debug for CallbackDataFromFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackDataFromFile")
            .field("events_handled", &self.events_handled)
            .field("schema_locator", &self.schema_locator)
            .finish()
    }
}
