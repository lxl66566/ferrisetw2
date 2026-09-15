//! A way to cache and retrieve Schemas

use std::sync::{Arc, Mutex};

use rustc_hash::FxHashMap;
use windows::core::GUID;

use crate::{
    native::{etw_types::event_record::EventRecord, tdh, tdh::TraceEventInfo},
    schema::Schema,
};

/// Schema module errors
#[derive(Debug)]
pub enum SchemaError {
    /// Represents an internal [TdhNativeError]
    ///
    /// [TdhNativeError]: tdh::TdhNativeError
    TdhNativeError(tdh::TdhNativeError),
}

impl From<tdh::TdhNativeError> for SchemaError {
    fn from(err: tdh::TdhNativeError) -> Self {
        SchemaError::TdhNativeError(err)
    }
}

pub(crate) type SchemaResult<T> = Result<T, SchemaError>;

/// A way to group events that share the same [`Schema`]
///
/// From the [docs](https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor):
/// > For manifest-based ETW, the combination Provider.DecodeGuid + Event.Id + Event.Version should
/// > uniquely identify an event,
/// > i.e. all events with the same DecodeGuid, Id, and Version should have the same set of fields
/// > with no changes in field names, field types, or field ordering.
#[derive(Debug, Eq, PartialEq, Hash)]
struct SchemaKey {
    provider: GUID,
    /// From the [docs](https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor): A 16-bit number used to identify manifest-based events
    id: u16,
    /// From the [docs](https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor): An 8-bit number used to specify the version of a manifest-based event.
    // The version indicates a revision to the definition of an event with a particular Id.
    // All events with a given Id should have similar semantics, but a change in version
    // can be used to indicate a minor modification of the event details, e.g. a change to
    // the type of a field or the addition of a new field.
    version: u8,

    // TODO: not sure why these ones are required in a SchemaKey. If they are, document why.
    //       note that krabsetw also uses these fields (without an explanation)
    //       however, krabsetw's `schema::operator==` do not use them to compare schemas for
    // equality.       see https://github.com/microsoft/krabsetw/issues/195
    opcode: u8,
    level: u8,
    // From MS documentation `evntprov.h`
    // For manifest-free events (i.e. TraceLogging), Event.Id and Event.Version are not useful
    // and should be ignored. Use Event name, level, keyword, and opcode for event filtering and
    // identification.
    event_name: String,
}

impl SchemaKey {
    pub fn new(event: &EventRecord) -> Self {
        SchemaKey {
            provider: event.provider_id(),
            id: event.event_id(),
            opcode: event.opcode(),
            version: event.version(),
            level: event.level(),
            event_name: event.event_name(),
        }
    }
}

/// Represents a cache of Schemas already located
///
/// This cache is implemented as a [FxHashMap] where the key is a combination of the following
/// elements of an [Event Record](https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record)
/// * EventHeader.ProviderId
/// * EventHeader.EventDescriptor.Id
/// * EventHeader.EventDescriptor.Opcode
/// * EventHeader.EventDescriptor.Version
/// * EventHeader.EventDescriptor.Level
///
/// The hasher is FxHash rather than the default SipHash: the keys are trusted
/// fixed-size data (built by this crate), and this lookup runs once per event.
///
/// Credits: [KrabsETW::schema_locator](https://github.com/microsoft/krabsetw/blob/master/krabs/krabs/schema_locator.hpp).
/// See also the code of `SchemaKey` for more info
#[derive(Default)]
pub struct SchemaLocator {
    schemas: Mutex<FxHashMap<SchemaKey, Arc<Schema>>>,
}

/// Upper bound on the number of cached schemas.
///
/// Without it, a long-running process collecting many distinct event kinds
/// (especially TraceLogging events, whose dynamic names all get their own key)
/// would grow the cache forever. Once full, new schemas are still built and
/// returned, they are just not cached anymore.
const MAX_CACHED_SCHEMAS: usize = 4096;
// The test suite iterates the cache bound as a u16 key
const _: () = assert!(MAX_CACHED_SCHEMAS <= u16::MAX as usize);

impl std::fmt::Debug for SchemaLocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchemaLocator")
            .field("len", &self.schemas.try_lock().map(|guard| guard.len()))
            .finish()
    }
}

impl SchemaLocator {
    pub(crate) fn new() -> Self {
        SchemaLocator {
            schemas: Mutex::new(FxHashMap::default()),
        }
    }

    /// Retrieve the Schema of an ETW Event
    ///
    /// # Arguments
    /// * `event` - The [EventRecord] that's passed to the callback
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::EventRecord;
    /// # use ferrisetw::schema_locator::SchemaLocator;
    /// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    /// };
    /// ```
    pub fn event_schema(&self, event: &EventRecord) -> SchemaResult<Arc<Schema>> {
        let key = SchemaKey::new(event);

        if let Some(s) = self.schemas.lock().unwrap().get(&key) {
            return Ok(Arc::clone(s));
        }

        // Building the schema involves a (potentially slow, manifest-parsing)
        // TDH call: don't hold the lock while doing so, as the events of a
        // real-time session may be delivered from several threads.
        let tei = TraceEventInfo::build_from_event(event)?;
        let new_schema = Arc::new(Schema::new(tei));

        Ok(self.store(key, new_schema))
    }

    /// Caches `built` under `key` and returns the schema to use from now on
    ///
    /// If another thread stored a schema with the same key in the meantime,
    /// that one wins and is returned instead (both describe the same event
    /// kind, so they are interchangeable).
    fn store(&self, key: SchemaKey, built: Arc<Schema>) -> Arc<Schema> {
        let mut schemas = self.schemas.lock().unwrap();
        if let Some(existing) = schemas.get(&key) {
            return Arc::clone(existing);
        }
        if schemas.len() < MAX_CACHED_SCHEMAS {
            schemas.insert(key, Arc::clone(&built));
        }
        built
    }
}

#[cfg(test)]
mod tests {
    use std::alloc::Layout;

    use windows::Win32::System::Diagnostics::Etw;

    use super::*;

    fn synthetic_tei() -> TraceEventInfo {
        // An all-zero TRACE_EVENT_INFO: the schema content does not matter here
        let size = size_of::<Etw::TRACE_EVENT_INFO>();
        let layout = Layout::from_size_align(size, align_of::<Etw::TRACE_EVENT_INFO>())
            .expect("valid layout");
        unsafe {
            let buffer = std::alloc::alloc(layout);
            std::ptr::write_bytes(buffer, 0, size);
            TraceEventInfo::from_raw_parts(buffer, layout)
        }
    }

    fn key(n: u16) -> SchemaKey {
        SchemaKey {
            provider: GUID::from_u128(u128::from(n)),
            id: n,
            opcode: 0,
            version: 0,
            level: 0,
            event_name: String::new(),
        }
    }

    #[test]
    fn cache_is_bounded() {
        let locator = SchemaLocator::new();
        let schema = Arc::new(Schema::new(synthetic_tei()));

        // Compile-time-checked to fit in a u16 (see the const assertion below)
        #[allow(clippy::cast_possible_truncation)]
        for n in 0..MAX_CACHED_SCHEMAS as u16 {
            let stored = locator.store(key(n), Arc::clone(&schema));
            assert!(Arc::ptr_eq(&stored, &schema));
        }
        assert_eq!(locator.schemas.lock().unwrap().len(), MAX_CACHED_SCHEMAS);

        // Once full, a new schema is still handed out, but not cached
        let extra = locator.store(key(u16::MAX), Arc::clone(&schema));
        assert!(Arc::ptr_eq(&extra, &schema));
        assert_eq!(locator.schemas.lock().unwrap().len(), MAX_CACHED_SCHEMAS);
    }

    #[test]
    fn concurrent_insert_of_the_same_key_wins_over_the_loser() {
        let locator = SchemaLocator::new();
        let winner = Arc::new(Schema::new(synthetic_tei()));
        let loser = Arc::new(Schema::new(synthetic_tei()));

        let first = locator.store(key(1), Arc::clone(&winner));
        let second = locator.store(key(1), Arc::clone(&loser));

        assert!(Arc::ptr_eq(&first, &winner));
        // The second storer gets back the first-inserted schema
        assert!(Arc::ptr_eq(&second, &winner));
    }
}
