use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use rustc_hash::FxHashMap;
use windows::{Win32::System::Diagnostics::Etw, core::GUID};

use crate::{
    EtwCallback, native::etw_types::event_record::EventRecord, provider::Provider,
    schema_locator::SchemaLocator, trace::RealTimeTraceTrait,
};

/// Data used by callbacks when the trace is running
// NOTE: this structure is accessed in an unsafe block in a separate thread (see the
// `trace_callback_thunk` function)       Thus, this struct must not be mutated (outside of interior
// mutability and/or using Mutex and other synchronization mechanisms) when the associated trace is
// running.
#[derive(Debug)]
pub enum CallbackData {
    RealTime(RealTimeCallbackData),
    FromFile(CallbackDataFromFile),
}

#[derive(Debug)]
pub struct RealTimeCallbackData {
    /// Represents how many events have been handled so far
    events_handled: AtomicUsize,
    /// Running totals reported by the ETW buffer callback, so loss of events can be
    /// observed while a real-time trace is running
    buffers_read: AtomicUsize,
    /// See [`RealTimeCallbackData::buffers_read`]
    events_lost: AtomicUsize,
    schema_locator: SchemaLocator,
    /// List of Providers associated with the Trace. This also owns the callback closures and their
    /// state
    providers: Vec<Provider>,
    /// Maps a provider GUID to the indices of `providers` with that GUID, so
    /// that `on_event` does not linearly scan every provider on each event
    providers_by_guid: FxHashMap<GUID, Vec<usize>>,
}

pub struct CallbackDataFromFile {
    /// Represents how many events have been handled so far
    events_handled: AtomicUsize,
    /// Running totals reported by the ETW buffer callback. For an ETL file, the
    /// `EventsLost` count is the one recorded when the file was written
    buffers_read: AtomicUsize,
    /// See [`CallbackDataFromFile::buffers_read`]
    events_lost: AtomicUsize,
    schema_locator: SchemaLocator,
    /// This trace is reading from an ETL file, and has a single callback
    // A Mutex rather than a RwLock: the callback is FnMut, so every event
    // takes an exclusive lock anyway
    callback: Mutex<EtwCallback>,
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

    pub fn on_buffer(&self, buffers_read: u32, events_lost: u32) {
        match self {
            CallbackData::RealTime(rt_cb) => rt_cb.on_buffer(buffers_read, events_lost),
            CallbackData::FromFile(f_cb) => f_cb.on_buffer(buffers_read, events_lost),
        }
    }

    pub fn buffers_read(&self) -> usize {
        match self {
            CallbackData::RealTime(rt_cb) => rt_cb.buffers_read(),
            CallbackData::FromFile(f_cb) => f_cb.buffers_read(),
        }
    }

    pub fn events_lost(&self) -> usize {
        match self {
            CallbackData::RealTime(rt_cb) => rt_cb.events_lost(),
            CallbackData::FromFile(f_cb) => f_cb.events_lost(),
        }
    }
}

impl Default for RealTimeCallbackData {
    fn default() -> Self {
        Self {
            events_handled: AtomicUsize::new(0),
            buffers_read: AtomicUsize::new(0),
            events_lost: AtomicUsize::new(0),
            schema_locator: SchemaLocator::new(),
            providers: Vec::new(),
            providers_by_guid: HashMap::default(),
        }
    }
}

impl RealTimeCallbackData {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_provider(&mut self, provider: Provider) {
        self.providers_by_guid
            .entry(provider.guid())
            .or_default()
            .push(self.providers.len());
        self.providers.push(provider);
    }

    pub fn providers(&self) -> &[Provider] {
        &self.providers
    }

    /// How many events have been handled since this instance was created
    pub fn events_handled(&self) -> usize {
        self.events_handled.load(Ordering::Relaxed)
    }

    /// How many buffers have been processed so far, as reported by the OS
    pub fn buffers_read(&self) -> usize {
        self.buffers_read.load(Ordering::Relaxed)
    }

    /// How many events the OS reported as lost so far
    pub fn events_lost(&self) -> usize {
        self.events_lost.load(Ordering::Relaxed)
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

    pub fn on_buffer(&self, buffers_read: u32, events_lost: u32) {
        // BuffersRead/EventsLost are session-wide running totals: keep the max seen so
        // far, rather than summing (buffers may be delivered concurrently, and summing
        // would count the same buffer several times)
        #[allow(clippy::cast_lossless)] // no From<u32> for usize on 32-bit targets
        let (buffers_read, events_lost) = (buffers_read as usize, events_lost as usize);
        self.buffers_read.fetch_max(buffers_read, Ordering::Relaxed);
        self.events_lost.fetch_max(events_lost, Ordering::Relaxed);
    }
}

impl CallbackDataFromFile {
    pub fn new(callback: EtwCallback) -> Self {
        Self {
            events_handled: AtomicUsize::new(0),
            buffers_read: AtomicUsize::new(0),
            events_lost: AtomicUsize::new(0),
            schema_locator: SchemaLocator::new(),
            callback: Mutex::new(callback),
        }
    }

    /// How many events have been handled since this instance was created
    pub fn events_handled(&self) -> usize {
        self.events_handled.load(Ordering::Relaxed)
    }

    /// How many buffers have been processed so far, as reported by the OS
    pub fn buffers_read(&self) -> usize {
        self.buffers_read.load(Ordering::Relaxed)
    }

    /// How many events the OS reported as lost so far
    pub fn events_lost(&self) -> usize {
        self.events_lost.load(Ordering::Relaxed)
    }

    pub fn on_event(&self, record: &EventRecord) {
        self.events_handled.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut cb) = self.callback.lock() {
            cb(record, &self.schema_locator);
        }
    }

    pub fn on_buffer(&self, buffers_read: u32, events_lost: u32) {
        // See the note in RealTimeCallbackData::on_buffer: these are running totals
        #[allow(clippy::cast_lossless)] // no From<u32> for usize on 32-bit targets
        let (buffers_read, events_lost) = (buffers_read as usize, events_lost as usize);
        self.buffers_read.fetch_max(buffers_read, Ordering::Relaxed);
        self.events_lost.fetch_max(events_lost, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for CallbackDataFromFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `callback` holds function objects, which cannot be Debug-formatted
        f.debug_struct("CallbackDataFromFile")
            .field("events_handled", &self.events_handled)
            .field("buffers_read", &self.buffers_read)
            .field("events_lost", &self.events_lost)
            .field("schema_locator", &self.schema_locator)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_stats_track_the_running_totals_of_a_real_time_trace() {
        let callback_data = CallbackData::RealTime(RealTimeCallbackData::new());
        callback_data.on_buffer(1, 0);
        callback_data.on_buffer(2, 0);
        callback_data.on_buffer(5, 3);
        assert_eq!(callback_data.buffers_read(), 5);
        assert_eq!(callback_data.events_lost(), 3);
    }

    #[test]
    fn buffer_stats_track_the_running_totals_of_a_file_trace() {
        let callback_data = CallbackData::FromFile(CallbackDataFromFile::new(Box::new(|_, _| {})));
        callback_data.on_buffer(7, 2);
        assert_eq!(callback_data.buffers_read(), 7);
        assert_eq!(callback_data.events_lost(), 2);
    }

    #[test]
    fn buffer_stats_ignore_out_of_order_reports() {
        // Buffers can be processed by concurrent delivery threads: a stale, smaller
        // running total must not bring the counters down (or double-count them)
        let callback_data = CallbackData::RealTime(RealTimeCallbackData::new());
        callback_data.on_buffer(5, 3);
        callback_data.on_buffer(4, 1);
        assert_eq!(callback_data.buffers_read(), 5);
        assert_eq!(callback_data.events_lost(), 3);
    }
}
