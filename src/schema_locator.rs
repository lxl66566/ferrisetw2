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

/// The part of an event descriptor that identifies a [`Schema`]
///
/// From the [docs](https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor):
/// > For manifest-based ETW, the combination Provider.DecodeGuid + Event.Id + Event.Version should
/// > uniquely identify an event,
/// > i.e. all events with the same DecodeGuid, Id, and Version should have the same set of fields
/// > with no changes in field names, field types, or field ordering.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct SchemaKey {
    provider: GUID,
    /// From the [docs](https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor): A 16-bit number used to identify manifest-based events
    id: u16,
    /// From the [docs](https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor): An 8-bit number used to specify the version of a manifest-based event.
    // The version indicates a revision to the definition of an event with a particular Id.
    // All events with a given Id should have similar semantics, but a change in version
    // can be used to indicate a minor modification of the event details, e.g. a change to the
    // type of a field or the addition of a new field.
    version: u8,

    // Required for classic (MOF-decoded) events: they carry no Id, and TDH
    // selects their decoded MOF class from the event class GUID, version and
    // event type, so two events differing only by opcode/level can decode to
    // different property tables. For manifest and TraceLogging events these
    // fields are redundant (schemas depend only on Id+Version, resp. the
    // in-event metadata), so a template written at several levels/opcodes
    // occupies one cache entry per variant: harmless duplication, bounded by
    // MAX_CACHED_SCHEMAS.
    // See https://github.com/microsoft/krabsetw/issues/195 (krabsetw keys its
    // cache on these fields too, and its schema equality ignores them).
    opcode: u8,
    level: u8,
}

impl SchemaKey {
    pub fn new(event: &EventRecord) -> Self {
        SchemaKey {
            provider: event.provider_id(),
            id: event.event_id(),
            opcode: event.opcode(),
            version: event.version(),
            level: event.level(),
        }
    }
}

/// The cached [`Schema`]s, keyed by event descriptor then by event name
///
/// From MS documentation `evntprov.h`:
/// > For manifest-free events (i.e. TraceLogging), Event.Id and Event.Version are not useful
/// > and should be ignored. Use Event name, level, keyword, and opcode for event filtering and
/// > identification.
///
/// Hence the two levels:
/// * manifest events have a descriptor of their own and never carry a name (see
///   [`EventRecord::event_name`]): their schema is stored under the empty name
/// * manifest-free (TraceLogging) events share an empty descriptor (`Id == 0`): their schema is
///   stored under the event name, parsed from the metadata embedded in each event. That name is
///   only materialized as an `Arc<str>` when a schema is cached: probing the cache re-parses it as
///   a borrow of the event metadata, without any allocation.
#[derive(Default)]
struct SchemaCache {
    schemas: FxHashMap<SchemaKey, FxHashMap<Arc<str>, Arc<Schema>>>,
    /// Total number of cached schemas (the bound applies to this sum)
    len: usize,
}

/// Represents a cache of Schemas already located
///
/// This cache is implemented as a [FxHashMap] where the (two-level) key is a combination of the
/// following elements of an [Event Record](https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record)
/// * EventHeader.ProviderId
/// * EventHeader.EventDescriptor.Id
/// * EventHeader.EventDescriptor.Opcode
/// * EventHeader.EventDescriptor.Version
/// * EventHeader.EventDescriptor.Level
/// * Event name (manifest-free events only)
///
/// The hasher is FxHash rather than the default SipHash: the keys are trusted
/// fixed-size data (built by this crate), and this lookup runs once per event.
///
/// Credits: [KrabsETW::schema_locator](https://github.com/microsoft/krabsetw/blob/master/krabs/krabs/schema_locator.hpp).
/// See also the code of `SchemaKey` for more info
#[derive(Default)]
pub struct SchemaLocator {
    schemas: Mutex<SchemaCache>,
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
            .field("len", &self.schemas.try_lock().map(|guard| guard.len))
            .finish()
    }
}

impl SchemaLocator {
    pub(crate) fn new() -> Self {
        SchemaLocator {
            schemas: Mutex::new(SchemaCache::default()),
        }
    }

    /// Retrieve the Schema of an ETW Event
    ///
    /// # Arguments
    /// * `event` - The [EventRecord] that's passed to the callback
    ///
    /// # Example
    /// ```
    /// # use ferrisetw2::EventRecord;
    /// # use ferrisetw2::schema_locator::SchemaLocator;
    /// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    /// };
    /// ```
    pub fn event_schema(&self, event: &EventRecord) -> SchemaResult<Arc<Schema>> {
        let key = SchemaKey::new(event);

        // Only manifest-free events are told apart by name: parsing it
        // re-reads the metadata embedded in the event, so skip it otherwise.
        // The borrow kept below is what makes cache hits allocation-free.
        let event_name = (key.id == 0).then(|| event.event_name_cow());

        if let Some(by_name) = self.schemas.lock().unwrap().schemas.get(&key) {
            // Manifest events are all stored under the empty name
            if let Some(s) = by_name.get(event_name.as_deref().unwrap_or("")) {
                return Ok(Arc::clone(s));
            }
        }

        // Building the schema involves a (potentially slow, manifest-parsing)
        // TDH call: don't hold the lock while doing so, as the events of a
        // real-time session may be delivered from several threads.
        let tei = TraceEventInfo::build_from_event(event)?;
        let new_schema = Arc::new(Schema::new(tei));

        let name = match event_name {
            Some(event_name) => Arc::from(&*event_name),
            None => Arc::from(""),
        };
        Ok(self.store(key, name, new_schema))
    }

    /// Caches `built` under (`key`, `name`) and returns the schema to use from now on
    ///
    /// If another thread stored a schema with the same key in the meantime,
    /// that one wins and is returned instead (both describe the same event
    /// kind, so they are interchangeable).
    fn store(&self, key: SchemaKey, name: Arc<str>, built: Arc<Schema>) -> Arc<Schema> {
        // Destructure the guard: the two fields are then borrowed independently
        let SchemaCache { schemas, len } = &mut *self.schemas.lock().unwrap();
        let by_name = schemas.entry(key).or_default();
        if let Some(existing) = by_name.get(&name) {
            return Arc::clone(existing);
        }
        if *len < MAX_CACHED_SCHEMAS {
            by_name.insert(name, Arc::clone(&built));
            *len += 1;
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
        }
    }

    #[test]
    fn cache_is_bounded() {
        let locator = SchemaLocator::new();
        let schema = Arc::new(Schema::new(synthetic_tei()));

        // Compile-time-checked to fit in a u16 (see the const assertion below)
        #[allow(clippy::cast_possible_truncation)]
        for n in 0..MAX_CACHED_SCHEMAS as u16 {
            let stored = locator.store(key(n), Arc::from(""), Arc::clone(&schema));
            assert!(Arc::ptr_eq(&stored, &schema));
        }
        assert_eq!(locator.schemas.lock().unwrap().len, MAX_CACHED_SCHEMAS);

        // Once full, a new schema is still handed out, but not cached
        let extra = locator.store(key(u16::MAX), Arc::from(""), Arc::clone(&schema));
        assert!(Arc::ptr_eq(&extra, &schema));
        assert_eq!(locator.schemas.lock().unwrap().len, MAX_CACHED_SCHEMAS);
    }

    #[test]
    fn several_names_under_the_same_descriptor_all_count() {
        // TraceLogging events of one provider often share the same descriptor:
        // every event name cached under it counts towards the bound
        let locator = SchemaLocator::new();
        let schema = Arc::new(Schema::new(synthetic_tei()));
        let key = key(0);

        for n in 0..3u16 {
            let stored = locator.store(key, Arc::from(format!("Event{n}")), Arc::clone(&schema));
            assert!(Arc::ptr_eq(&stored, &schema));
        }
        assert_eq!(locator.schemas.lock().unwrap().len, 3);

        // Same name as an existing entry: no duplicate is stored
        let again = locator.store(key, Arc::from("Event1"), Arc::clone(&schema));
        assert!(Arc::ptr_eq(&again, &schema));
        assert_eq!(locator.schemas.lock().unwrap().len, 3);
    }

    #[test]
    fn concurrent_insert_of_the_same_key_wins_over_the_loser() {
        let locator = SchemaLocator::new();
        let winner = Arc::new(Schema::new(synthetic_tei()));
        let loser = Arc::new(Schema::new(synthetic_tei()));

        let first = locator.store(key(1), Arc::from(""), Arc::clone(&winner));
        let second = locator.store(key(1), Arc::from(""), Arc::clone(&loser));

        assert!(Arc::ptr_eq(&first, &winner));
        // The second storer gets back the first-inserted schema
        assert!(Arc::ptr_eq(&second, &winner));
    }

    // ---- TraceLogging (self-describing) events decoded through the real TDH ----

    /// Owns the buffers a synthetic TraceLogging [`EventRecord`] points to:
    /// the record must be used before the guard is dropped
    struct TlgRecord {
        record: EventRecord,
        _provider_blob: Vec<u8>,
        _event_blob: Vec<u8>,
        _user_data: Vec<u8>,
        _ext_items: Box<[Etw::EVENT_HEADER_EXTENDED_DATA_ITEM; 2]>,
    }

    /// A synthetic TraceLogging event, decoded through the real TDH: the
    /// layout of an event whose provider registered its traits, so the
    /// metadata travels in extended data items rather than in the user data
    ///
    /// * user data: the field values only
    /// * extended data: an `EVENT_HEADER_EXT_TYPE_PROV_TRAITS` item (provider name) and an
    ///   `EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL` item (the event metadata blob from which the event
    ///   name is read: `u16` size, one tag byte, NUL-terminated name, then the field descriptors)
    ///
    /// The event has one `UInt16` field: `field_name`, NUL-terminated, with TLG
    /// in type 6
    fn tlg_record(event_name: &str, field_name: &str) -> TlgRecord {
        let sized = |payload: &[u8]| -> Vec<u8> {
            (u16::try_from(payload.len() + 2).unwrap())
                .to_le_bytes()
                .into_iter()
                .chain(payload.iter().copied())
                .collect()
        };

        // Canonical event metadata blob: `u16` total size, one tag byte (high
        // bit clear: end of the tags), NUL-terminated event name, then the
        // field descriptors
        let mut event_meta = vec![0u8]; // tags
        event_meta.extend_from_slice(event_name.as_bytes());
        event_meta.push(0);
        event_meta.extend_from_slice(field_name.as_bytes());
        event_meta.push(0);
        event_meta.push(6); // TLG in type: UInt16
        let event_blob = sized(&event_meta);

        // Canonical provider traits blob: `u16` total size, NUL-terminated
        // provider name, then the terminating trait byte
        let mut provider_traits = b"ferrisETW.TraceLoggingTest".to_vec();
        provider_traits.push(0);
        provider_traits.push(0); // no trait
        let provider_blob = sized(&provider_traits);

        // When the metadata travels in extended data items, the user data
        // holds the field values only
        let user_data: Vec<u8> = vec![80, 0]; // the UInt16 field value

        // Test data uses known-small ext type constants
        #[allow(clippy::cast_possible_truncation)]
        let schema_ext_type = Etw::EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL as u16;
        #[allow(clippy::cast_possible_truncation)]
        let traits_ext_type = Etw::EVENT_HEADER_EXT_TYPE_PROV_TRAITS as u16;
        let ext_items = Box::new([
            Etw::EVENT_HEADER_EXTENDED_DATA_ITEM {
                ExtType: traits_ext_type,
                DataSize: u16::try_from(provider_blob.len()).unwrap(),
                DataPtr: provider_blob.as_ptr() as u64,
                ..Default::default()
            },
            Etw::EVENT_HEADER_EXTENDED_DATA_ITEM {
                ExtType: schema_ext_type,
                DataSize: u16::try_from(event_blob.len()).unwrap(),
                DataPtr: event_blob.as_ptr() as u64,
                ..Default::default()
            },
        ]);

        // Header size and user data length always fit: synthetic test data
        #[allow(clippy::cast_possible_truncation)]
        let header_size = size_of::<Etw::EVENT_HEADER>() as u16;
        let record = EventRecord(Etw::EVENT_RECORD {
            EventHeader: Etw::EVENT_HEADER {
                Size: header_size,
                Flags: 0x0002, // EVENT_HEADER_FLAG_TRACE_MESSAGE
                EventDescriptor: Etw::EVENT_DESCRIPTOR {
                    Channel: 11, // TraceLogging channel
                    ..Default::default()
                },
                ProviderId: GUID::from_u128(0x8f0e2f62_5b7d_4d1a_9e58_5a0c1b2d3e4f),
                ..Default::default()
            },
            BufferContext: Etw::ETW_BUFFER_CONTEXT::default(),
            ExtendedDataCount: 2,
            ExtendedData: std::ptr::from_ref(&*ext_items)
                .cast::<Etw::EVENT_HEADER_EXTENDED_DATA_ITEM>()
                .cast_mut(),
            UserData: user_data.as_ptr().cast_mut().cast(),
            UserDataLength: u16::try_from(user_data.len()).unwrap(),
            UserContext: std::ptr::null_mut(),
        });

        TlgRecord {
            record,
            _provider_blob: provider_blob,
            _event_blob: event_blob,
            _user_data: user_data,
            _ext_items: ext_items,
        }
    }

    #[test]
    fn tlg_level_opcode_variants_share_schema_content() {
        // TDH decodes TraceLogging events from the metadata embedded in the
        // event: the descriptor's level/opcode take no part in it, so variants
        // of the same template carry identical schema content. The cache still
        // keys them apart (level/opcode must stay in the key for classic MOF
        // events, see `SchemaKey`), one entry per variant
        let locator = SchemaLocator::new();

        let event1 = tlg_record("Event1", "Port");
        let mut event2 = tlg_record("Event1", "Port");
        event2.record.0.EventHeader.EventDescriptor.Level = 5;
        event2.record.0.EventHeader.EventDescriptor.Opcode = 10;

        let s1 = locator.event_schema(&event1.record).unwrap();
        let s2 = locator.event_schema(&event2.record).unwrap();

        // Distinct cache entries (distinct keys), each holding the same
        // property table (Property has no PartialEq: compare the Debug dump,
        // which covers names, in/out types, lengths and structure members)
        assert!(!Arc::ptr_eq(&s1, &s2));
        assert_eq!(locator.schemas.lock().unwrap().len, 2);
        assert_eq!(
            format!("{:?}", s1.properties()),
            format!("{:?}", s2.properties())
        );
    }

    #[test]
    fn tracelogging_schemas_are_keyed_by_name() {
        // Two TraceLogging events with the same descriptor but different names
        // must get distinct schemas; repeated events must hit the cache
        // through the borrowed name (no re-built schema)
        let locator = SchemaLocator::new();

        let event1 = tlg_record("Event1", "Port");
        let first = locator.event_schema(&event1.record).unwrap();
        let second = locator.event_schema(&event1.record).unwrap();
        assert!(Arc::ptr_eq(&first, &second));

        let event2 = tlg_record("Event2", "Port");
        let other = locator.event_schema(&event2.record).unwrap();
        assert!(!Arc::ptr_eq(&first, &other));
        assert_eq!(locator.schemas.lock().unwrap().len, 2);
    }
}
