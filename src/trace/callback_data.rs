use std::sync::{
    Arc, Mutex, MutexGuard, RwLock,
    atomic::{AtomicUsize, Ordering},
};

use rustc_hash::FxHashMap;
use windows::{Win32::System::Diagnostics::Etw, core::GUID};

use crate::{
    EtwCallback, native::etw_types::event_record::EventRecord, provider::Provider,
    schema_locator::SchemaLocator, trace::RealTimeTraceTrait,
};

/// Data used by callbacks when the trace is running
// NOTE: this structure is accessed from the ETW delivery threads, through `Arc` clones handed
// out by the context registry (see the `trace_callback_thunk` function). Thus, this struct must
// only be mutated through interior mutability backed by a synchronization primitive (atomics,
// the provider registry's RwLock, ...) when the associated trace is running. Providers can be
// added and removed while the trace processes events (see
// `UserTrace::enable_provider`/`disable_provider`, issue #54): the registry is guarded by a
// RwLock, and user callbacks are only ever invoked *without* holding it.
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
    /// Providers associated with the Trace, along with their callback closures and
    /// state. Behind a RwLock so that providers can be enabled/disabled while the
    /// trace is processing events (issue #54): event dispatch takes a read lock,
    /// while (un)registration takes the write lock. User callbacks run *after*
    /// the lock has been released, so a callback may itself enable or disable
    /// providers.
    providers: RwLock<ProviderRegistry>,
    /// Serializes session mutations: `UserTrace::enable_provider` and
    /// `disable_provider` must apply their "OS-level call + registry update"
    /// pair atomically with respect to each other. Without it, a disable whose
    /// OS call races with a concurrent enable of the same GUID could remove the
    /// freshly registered provider, leaving it enabled at the OS level with
    /// nothing registered to dispatch (and eventually lose) its events.
    ///
    /// Lock order: acquire this before the `providers` lock, never after. Event
    /// dispatch only ever takes the `providers` read lock, so it never stalls
    /// on this mutex.
    session_mutations: Mutex<()>,
}

/// The providers registered on a real-time trace, indexed both by insertion
/// order and by GUID
///
/// Both collections must stay consistent: they are only mutated together, under
/// the enclosing `RwLock`. Providers are shared as `Arc`s so that `on_event`
/// can clone the ones it needs, release the lock, and only then run the user
/// callbacks (which may take the lock again).
#[derive(Debug, Default)]
struct ProviderRegistry {
    /// Providers in insertion order
    providers: Vec<Arc<Provider>>,
    /// Providers by GUID, so that `on_event` does not linearly scan every
    /// provider on each event (a GUID may map to several entries: the library
    /// allows registering the same provider GUID multiple times, each with its
    /// own callbacks)
    by_guid: FxHashMap<GUID, Vec<Arc<Provider>>>,
}

impl ProviderRegistry {
    fn add(&mut self, provider: Arc<Provider>) {
        self.by_guid
            .entry(provider.guid())
            .or_default()
            .push(Arc::clone(&provider));
        self.providers.push(provider);
    }

    /// Remove every entry registered for this GUID, returning how many were
    /// removed
    fn remove_all_by_guid(&mut self, guid: GUID) -> usize {
        match self.by_guid.remove(&guid) {
            None => 0,
            Some(entries) => {
                let same_guid = || self.providers.iter().filter(|p| p.guid() == guid).count();
                debug_assert_eq!(entries.len(), same_guid());
                self.providers.retain(|p| p.guid() != guid);
                entries.len()
            },
        }
    }

    /// Remove one specific provider instance (identity comparison, not GUID
    /// equality), used to roll back a registration whose OS-level enable
    /// failed. Returns whether the provider was found.
    fn remove_one(&mut self, provider: &Arc<Provider>) -> bool {
        let guid = provider.guid();
        let mut removed = false;
        if let Some(entries) = self.by_guid.get_mut(&guid) {
            entries.retain(|p| {
                let same = Arc::ptr_eq(p, provider);
                removed |= same;
                !same
            });
        }
        if removed {
            if self.by_guid.get(&guid).is_some_and(Vec::is_empty) {
                self.by_guid.remove(&guid);
            }
            self.providers.retain(|p| !Arc::ptr_eq(p, provider));
        }
        removed
    }
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
            providers: RwLock::new(ProviderRegistry::default()),
            session_mutations: Mutex::new(()),
        }
    }
}

impl RealTimeCallbackData {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock guarding the "OS call + registry update" pair of the runtime
    /// provider mutations (see the `session_mutations` field)
    pub(crate) fn lock_session_mutations(&self) -> MutexGuard<'_, ()> {
        self.session_mutations.lock().unwrap()
    }

    pub fn add_provider(&self, provider: Provider) {
        self.providers.write().unwrap().add(Arc::new(provider));
    }

    /// Same as [`RealTimeCallbackData::add_provider`], for a provider that is
    /// already shared (the runtime `enable_provider` path keeps an `Arc` so it
    /// can roll back the registration by identity)
    pub(crate) fn add_provider_shared(&self, provider: Arc<Provider>) {
        self.providers.write().unwrap().add(provider);
    }

    /// Whether at least one provider is registered for this GUID
    pub fn has_provider_with_guid(&self, guid: GUID) -> bool {
        self.providers.read().unwrap().by_guid.contains_key(&guid)
    }

    /// A snapshot of the registered providers, in registration order
    pub fn providers(&self) -> Vec<Arc<Provider>> {
        self.providers.read().unwrap().providers.clone()
    }

    /// Remove every entry registered for this GUID, returning how many were
    /// removed. Does not touch the OS-level session configuration: the caller
    /// is responsible for disabling the provider.
    pub fn remove_all_by_guid(&self, guid: GUID) -> usize {
        self.providers.write().unwrap().remove_all_by_guid(guid)
    }

    /// Rollback counterpart of [`RealTimeCallbackData::add_provider`]:
    /// unregisters exactly this provider instance
    pub(crate) fn remove_provider_instance(&self, provider: &Arc<Provider>) -> bool {
        self.providers.write().unwrap().remove_one(provider)
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
        Etw::EVENT_TRACE_FLAG(T::enable_flags(&self.providers()))
    }

    pub fn on_event(&self, record: &EventRecord) {
        self.events_handled.fetch_add(1, Ordering::Relaxed);

        // The lock must be released before running user callbacks: they may
        // enable/disable providers (which takes the write lock), and holding a
        // read lock over every callback would serialize all events. Hence the
        // clones of the needed `Arc`s: removals racing with this dispatch are
        // fine, the cloned providers simply receive their in-flight events.
        let registry = self.providers.read().unwrap();
        match registry.by_guid.get(&record.provider_id()) {
            None => {},
            // Fast path: a single provider for this GUID, no allocation
            Some(entries) if entries.len() == 1 => {
                let provider = Arc::clone(&entries[0]);
                drop(registry);
                provider.on_event(record, &self.schema_locator);
            },
            Some(entries) => {
                let providers: Vec<Arc<Provider>> = entries.clone();
                drop(registry);
                for provider in providers {
                    provider.on_event(record, &self.schema_locator);
                }
            },
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
    use std::sync::atomic::AtomicUsize;

    use super::*;

    /// A record whose only meaningful field is the provider it comes from
    fn record_for_provider(guid: GUID) -> EventRecord {
        EventRecord(Etw::EVENT_RECORD {
            EventHeader: Etw::EVENT_HEADER {
                ProviderId: guid,
                ..Default::default()
            },
            ..Default::default()
        })
    }

    /// A provider whose callback increments `counter` once per received event
    fn counting_provider<G: crate::provider::IntoGuid>(
        guid: G,
        counter: &Arc<AtomicUsize>,
    ) -> Provider {
        let bump = Arc::clone(counter);
        Provider::by_guid(guid)
            .add_callback(move |_, _| {
                bump.fetch_add(1, Ordering::Relaxed);
            })
            .build()
    }

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

    #[test]
    fn runtime_providers_are_listed_in_registration_order() {
        let callback_data = RealTimeCallbackData::new();
        callback_data.add_provider(Provider::by_guid(0x1111).build());
        callback_data.add_provider(Provider::by_guid(0x2222).build());
        callback_data.add_provider(Provider::by_guid(0x1111).build());

        let providers = callback_data.providers();
        assert_eq!(
            providers.iter().map(|p| p.guid()).collect::<Vec<_>>(),
            vec![
                GUID::from_u128(0x1111),
                GUID::from_u128(0x2222),
                GUID::from_u128(0x1111)
            ]
        );
        assert!(callback_data.has_provider_with_guid(GUID::from_u128(0x2222)));
        assert!(!callback_data.has_provider_with_guid(GUID::from_u128(0x3333)));
    }

    #[test]
    fn runtime_disable_removes_every_entry_of_that_guid() {
        let callback_data = RealTimeCallbackData::new();
        callback_data.add_provider(Provider::by_guid(0x1111).build());
        callback_data.add_provider(Provider::by_guid(0x2222).build());
        callback_data.add_provider(Provider::by_guid(0x1111).build());

        // Disabling a GUID removes all of its entries, and only them
        assert_eq!(callback_data.remove_all_by_guid(GUID::from_u128(0x1111)), 2);
        let remaining = callback_data.providers();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].guid(), GUID::from_u128(0x2222));
        assert!(!callback_data.has_provider_with_guid(GUID::from_u128(0x1111)));

        // A second disable has nothing left to remove
        assert_eq!(callback_data.remove_all_by_guid(GUID::from_u128(0x1111)), 0);
        assert_eq!(callback_data.providers().len(), 1);
    }

    #[test]
    fn rollback_removes_only_the_rolled_back_instance() {
        // Two registrations of the same GUID: rolling back one (because its
        // OS-level enable failed) must leave the other one dispatching
        let callback_data = RealTimeCallbackData::new();
        callback_data.add_provider(Provider::by_guid(0x1111).build());
        callback_data.add_provider(Provider::by_guid(0x1111).build());
        callback_data.add_provider(Provider::by_guid(0x2222).build());

        let victim = callback_data.providers().remove(0); // first 0x1111 entry
        assert!(callback_data.remove_provider_instance(&victim));
        // The instance is gone, but its GUID still has an entry...
        assert!(callback_data.has_provider_with_guid(GUID::from_u128(0x1111)));
        assert_eq!(callback_data.providers().len(), 2);

        // ...and the exact same Arc is not registered twice (removal is idempotent)
        assert!(!callback_data.remove_provider_instance(&victim));
        assert_eq!(callback_data.providers().len(), 2);
    }

    #[test]
    fn on_event_dispatches_to_every_matching_provider_only() {
        let callback_data = RealTimeCallbackData::new();
        let first = Arc::new(AtomicUsize::new(0));
        let second = Arc::new(AtomicUsize::new(0));
        let other = Arc::new(AtomicUsize::new(0));
        // Same GUID registered twice: both entries must receive the event
        callback_data.add_provider(counting_provider(0x1111, &first));
        callback_data.add_provider(counting_provider(0x1111, &second));
        callback_data.add_provider(counting_provider(0x2222, &other));

        callback_data.on_event(&record_for_provider(GUID::from_u128(0x1111)));
        assert_eq!(first.load(Ordering::Relaxed), 1);
        assert_eq!(second.load(Ordering::Relaxed), 1);
        assert_eq!(other.load(Ordering::Relaxed), 0);
        assert_eq!(callback_data.events_handled(), 1);

        // Unknown providers are not dispatched, but still counted as handled
        callback_data.on_event(&record_for_provider(GUID::from_u128(0x3333)));
        assert_eq!(first.load(Ordering::Relaxed), 1);
        assert_eq!(callback_data.events_handled(), 2);
    }

    #[test]
    fn on_event_does_not_dispatch_disabled_providers() {
        let callback_data = RealTimeCallbackData::new();
        let counter = Arc::new(AtomicUsize::new(0));
        callback_data.add_provider(counting_provider(0x1111, &counter));

        callback_data.remove_all_by_guid(GUID::from_u128(0x1111));
        callback_data.on_event(&record_for_provider(GUID::from_u128(0x1111)));
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }
}
