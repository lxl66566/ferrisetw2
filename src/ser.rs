//! Integrates with [serde](https://serde.rs/) enabling ['EventRecord`](crate::EventRecord) to be serialized to various formats.
//!
//! Requires the `serde` feature be enabled.
//!
//! If the `time_rs` feature is enabled, then time stamps are serialized per the serialization
//! format of the time crate. Otherwise, if `time_rs` is not enabled, then timestamps are serialized
//! as 64bit unix timestamps.
//!
//! ```
//! use ferrisetw::{EventRecord, EventSerializer, schema_locator::SchemaLocator};
//! extern crate serde_json;
//!
//! fn event_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
//!     match schema_locator.event_schema(record) {
//!         Err(err) => println!("Error {:?}", err),
//!         Ok(schema) => {
//!             // Generate a serializer for the record using the schema
//!             let ser = EventSerializer::new(record, &schema, Default::default());
//!             // Pass the serializer to any serde compatible serializer
//!             match serde_json::to_value(ser) {
//!                 Err(err) => println!("Error {:?}", err),
//!                 Ok(json) => println!("{}", json),
//!             }
//!         },
//!     }
//! }
//! ```
#![cfg(feature = "serde")]

use std::net::IpAddr;

use serde::ser::{SerializeMap, SerializeSeq, SerializeStruct};
use windows::Win32::System::Diagnostics::Etw::{EVENT_DESCRIPTOR, EVENT_HEADER};

use crate::{
    GUID,
    native::{
        EVENT_EXTENDED_ITEM_INSTANCE, EventHeaderExtendedDataItem, ExtendedDataItem,
        etw_types::event_record::EventRecord,
        tdh_types::{Property, PropertyCount, PropertyInfo, TdhInType, TdhOutType},
        time::{FileTime, SystemTime},
    },
    parser::{Parser, TdhSocketAddress},
    schema::Schema,
};

/// Serialization options for EventSerializer
// Named option fields: the bools are self-documenting
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy)]
pub struct EventSerializerOptions {
    /// Includes information from the schema in the serialized output such as the provider, opcode,
    /// and task names.
    pub include_schema: bool,
    /// Includes the [EVENT_HEADER](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/fa4f7836-06ee-4ab6-8688-386a5a85f8c5) in the serialized output.
    pub include_header: bool,
    /// Includes the set of [EVENT_HEADER_EXTENDED_DATA_ITEM](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header_extended_data_item) in the serialized output,
    /// as an `Extended` array of `{"Type", "Data"}` entries.
    pub include_extended_data: bool,
    /// When `true` unimplemented serialization fails with an error, otherwise unimplemented
    /// serialization is skipped and will not be present in the serialized output.
    pub fail_unimplemented: bool,
}

impl Default for EventSerializerOptions {
    fn default() -> Self {
        Self {
            include_schema: true,
            include_header: true,
            include_extended_data: false,
            fail_unimplemented: false,
        }
    }
}

/// Used to serialize ['EventRecord`](crate::EventRecord) using [serde](https://serde.rs/)
pub struct EventSerializer<'a> {
    pub(crate) record: &'a EventRecord,
    pub(crate) schema: &'a Schema,
    pub(crate) parser: Parser<'a, 'a>,
    pub(crate) options: EventSerializerOptions,
}

impl<'a> EventSerializer<'a> {
    /// Creates an event serializer object.
    pub fn new(
        record: &'a EventRecord,
        schema: &'a Schema,
        options: EventSerializerOptions,
    ) -> Self {
        Self {
            record,
            schema,
            parser: Parser::create(record, schema),
            options,
        }
    }
}

impl serde::ser::Serialize for EventSerializer<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("Record", 4)?;

        if self.options.include_schema {
            let schema = SchemaSer::new(self.schema);
            state.serialize_field("Schema", &schema)?;
        } else {
            state.skip_field("Schema")?;
        }

        if self.options.include_header {
            let header = HeaderSer::new(&self.record.0.EventHeader);
            state.serialize_field("Header", &header)?;
        } else {
            state.skip_field("Header")?;
        }

        if self.options.include_extended_data {
            let extended =
                ExtendedSer::new(self.record.extended_data(), self.options.fail_unimplemented);
            state.serialize_field("Extended", &extended)?;
        } else {
            state.skip_field("Extended")?;
        }

        // The property list is bound to the schema lifetime (`'x`, same as the
        // parser's `Parser<'x, 'x>`): Parser is invariant over that parameter,
        // so structure members can only be decoded when both agree. Accessing
        // the schema through `self.schema` (a copied `&'x Schema`) keeps that
        // lifetime; going through a shorter reborrow would not.
        let props = match self.schema.try_properties() {
            Ok(p) => p,
            Err(e) if self.options.fail_unimplemented => return Err(serde::ser::Error::custom(e)),
            Err(_) => &[],
        };
        let event = EventSer::new(self.record, props, &self.parser, &self.options);
        state.serialize_field("Event", &event)?;

        state.end()
    }
}

struct GUIDExt(GUID);

/// Formats a GUID as its `Debug` representation (uppercase, hyphenated),
/// into a stack buffer instead of a heap-allocated String
fn guid_to_ascii_upper(guid: &GUID) -> [u8; 36] {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut bytes = [0u8; 16];
    // Data1/2/3 are serialized big-endian (MSB first)
    bytes[0..4].copy_from_slice(&guid.data1.to_be_bytes());
    bytes[4..6].copy_from_slice(&guid.data2.to_be_bytes());
    bytes[6..8].copy_from_slice(&guid.data3.to_be_bytes());
    bytes[8..].copy_from_slice(&guid.data4);
    // hex groups of 4-2-2-2-6 bytes, separated by hyphens (8-4-4-4-12 digits)
    let mut out = [0u8; 36];
    let mut byte_index = 0;
    let mut out_index = 0;
    for (group, &len) in [4usize, 2, 2, 2, 6].iter().enumerate() {
        if group > 0 {
            out[out_index] = b'-';
            out_index += 1;
        }
        for &b in &bytes[byte_index..byte_index + len] {
            out[out_index] = HEX[(b >> 4) as usize];
            out[out_index + 1] = HEX[(b & 0xf) as usize];
            out_index += 2;
        }
        byte_index += len;
    }
    out
}

impl serde::ser::Serialize for GUIDExt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        if serializer.is_human_readable() {
            let ascii = guid_to_ascii_upper(&self.0);
            // All written bytes are ASCII (hex digits and hyphens), so this cannot fail
            let s = std::str::from_utf8(&ascii).expect("GUID buffer is valid UTF-8");
            return serializer.serialize_str(s);
        }

        (self.0.data1, self.0.data2, self.0.data3, self.0.data4).serialize(serializer)
    }
}

struct SchemaSer<'a> {
    schema: &'a Schema,
}

impl<'a> SchemaSer<'a> {
    fn new(schema: &'a Schema) -> Self {
        Self { schema }
    }
}

impl serde::ser::Serialize for SchemaSer<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // The cached getters avoid re-decoding the UTF-16 names of the
        // TRACE_EVENT_INFO on every serialized event
        let mut state = serializer.serialize_struct("Schema", 3)?;
        state.serialize_field("Provider", &self.schema.provider_name_cached().trim())?;
        state.serialize_field("Opcode", &self.schema.opcode_name_cached().trim())?;
        state.serialize_field("Task", &self.schema.task_name_cached().trim())?;
        state.end()
    }
}

struct HeaderSer<'a> {
    header: &'a EVENT_HEADER,
}

impl<'a> HeaderSer<'a> {
    fn new(header: &'a EVENT_HEADER) -> Self {
        Self { header }
    }
}

impl serde::ser::Serialize for HeaderSer<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("Header", 10)?;
        state.serialize_field("Size", &self.header.Size)?;
        state.serialize_field("HeaderType", &self.header.HeaderType)?;
        state.serialize_field("Flags", &self.header.Flags)?;
        state.serialize_field("EventProperty", &self.header.EventProperty)?;
        state.serialize_field("ThreadId", &self.header.ThreadId)?;
        state.serialize_field("ProcessId", &self.header.ProcessId)?;
        state.serialize_field("TimeStamp", &FileTime::from_quad(self.header.TimeStamp))?;
        state.serialize_field("ProviderId", &GUIDExt(self.header.ProviderId))?;
        state.serialize_field("ActivityId", &GUIDExt(self.header.ActivityId))?;
        let descriptor = DescriptorSer::new(&self.header.EventDescriptor);
        state.serialize_field("Descriptor", &descriptor)?;
        state.end()
    }
}

struct DescriptorSer<'a> {
    descriptor: &'a EVENT_DESCRIPTOR,
}

impl<'a> DescriptorSer<'a> {
    fn new(descriptor: &'a EVENT_DESCRIPTOR) -> Self {
        Self { descriptor }
    }
}

impl serde::ser::Serialize for DescriptorSer<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("Descriptor", 7)?;
        state.serialize_field("Id", &self.descriptor.Id)?;
        state.serialize_field("Version", &self.descriptor.Version)?;
        state.serialize_field("Channel", &self.descriptor.Channel)?;
        state.serialize_field("Level", &self.descriptor.Level)?;
        state.serialize_field("Opcode", &self.descriptor.Opcode)?;
        state.serialize_field("Task", &self.descriptor.Task)?;
        state.serialize_field("Keyword", &self.descriptor.Keyword)?;
        state.end()
    }
}

/// Serializes the extended data items of an event as an array
///
/// Unsupported items are skipped, or fail the serialization when `fail_unimplemented` is set,
/// mirroring how unimplemented event properties are handled.
struct ExtendedSer<'a> {
    items: &'a [EventHeaderExtendedDataItem],
    fail_unimplemented: bool,
}

impl<'a> ExtendedSer<'a> {
    fn new(items: &'a [EventHeaderExtendedDataItem], fail_unimplemented: bool) -> Self {
        Self {
            items,
            fail_unimplemented,
        }
    }
}

impl serde::ser::Serialize for ExtendedSer<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_seq(None)?;
        for item in self.items {
            // to_extended_data_item is called exactly once per item: it may
            // allocate (SID copy, stack trace, event name), don't repeat it
            let data = item.to_extended_data_item();
            if matches!(data, ExtendedDataItem::Unsupported) {
                if self.fail_unimplemented {
                    return Err(serde::ser::Error::custom(format!(
                        "not implemented extended data ExtType {}",
                        item.data_type()
                    )));
                }
                continue;
            }
            state.serialize_element(&ExtendedDataItemSer(&data))?;
        }
        state.end()
    }
}

/// Serializes one [`ExtendedDataItem`] as `{"Type": <variant name>, "Data": <payload>}`
struct ExtendedDataItemSer<'a>(&'a ExtendedDataItem);

impl serde::ser::Serialize for ExtendedDataItemSer<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("ExtendedDataItem", 2)?;
        match self.0 {
            // Only reachable outside ExtendedSer's filtering: emit a marker
            ExtendedDataItem::Unsupported => {
                state.serialize_field("Type", "Unsupported")?;
                let none: Option<u8> = None;
                state.serialize_field("Data", &none)?;
            },
            ExtendedDataItem::RelatedActivityId(guid) => {
                state.serialize_field("Type", "RelatedActivityId")?;
                state.serialize_field("Data", &GUIDExt(*guid))?;
            },
            ExtendedDataItem::Sid(sid) => {
                state.serialize_field("Type", "Sid")?;
                let sddl = sid.to_sddl_string().map_err(serde::ser::Error::custom)?;
                state.serialize_field("Data", &sddl)?;
            },
            ExtendedDataItem::TsId(id) => {
                state.serialize_field("Type", "TsId")?;
                state.serialize_field("Data", id)?;
            },
            ExtendedDataItem::InstanceInfo(info) => {
                state.serialize_field("Type", "InstanceInfo")?;
                state.serialize_field("Data", &InstanceInfoSer(*info))?;
            },
            ExtendedDataItem::StackTrace32(trace) => {
                state.serialize_field("Type", "StackTrace32")?;
                state.serialize_field("Data", &StackTraceSer {
                    match_id: trace.match_id(),
                    addresses: trace.addresses(),
                })?;
            },
            ExtendedDataItem::StackTrace64(trace) => {
                state.serialize_field("Type", "StackTrace64")?;
                state.serialize_field("Data", &StackTraceSer {
                    match_id: trace.match_id(),
                    addresses: trace.addresses(),
                })?;
            },
            ExtendedDataItem::TraceLogging(name) => {
                state.serialize_field("Type", "TraceLogging")?;
                state.serialize_field("Data", name)?;
            },
            ExtendedDataItem::ProvTraits(bytes) => {
                state.serialize_field("Type", "ProvTraits")?;
                state.serialize_field("Data", &bytes.as_slice())?;
            },
            ExtendedDataItem::ContainerId(guid) => {
                state.serialize_field("Type", "ContainerId")?;
                state.serialize_field("Data", &GUIDExt(*guid))?;
            },
            ExtendedDataItem::EventKey(key) => {
                state.serialize_field("Type", "EventKey")?;
                state.serialize_field("Data", key)?;
            },
            ExtendedDataItem::ProcessStartKey(key) => {
                state.serialize_field("Type", "ProcessStartKey")?;
                state.serialize_field("Data", key)?;
            },
        }
        state.end()
    }
}

struct InstanceInfoSer(EVENT_EXTENDED_ITEM_INSTANCE);

impl serde::ser::Serialize for InstanceInfoSer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("InstanceInfo", 3)?;
        state.serialize_field("InstanceId", &self.0.InstanceId)?;
        state.serialize_field("ParentInstanceId", &self.0.ParentInstanceId)?;
        state.serialize_field("ParentGuid", &GUIDExt(self.0.ParentGuid))?;
        state.end()
    }
}

struct StackTraceSer<'a, Address> {
    match_id: u64,
    addresses: &'a [Address],
}

impl<Address: serde::ser::Serialize> serde::ser::Serialize for StackTraceSer<'_, Address> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("StackTrace", 2)?;
        state.serialize_field("MatchId", &self.match_id)?;
        state.serialize_field("Addresses", self.addresses)?;
        state.end()
    }
}

struct EventSer<'a, 'b> {
    record: &'a EventRecord,
    /// Top-level properties, resolved by the caller at the schema lifetime so
    /// the parser can decode structure members (Parser is invariant over its
    /// schema lifetime, both must agree)
    props: &'b [Property],
    parser: &'a Parser<'b, 'b>,
    options: &'a EventSerializerOptions,
}

impl<'a, 'b> EventSer<'a, 'b> {
    fn new(
        record: &'a EventRecord,
        props: &'b [Property],
        parser: &'a Parser<'b, 'b>,
        options: &'a EventSerializerOptions,
    ) -> Self {
        Self {
            record,
            props,
            parser,
            options,
        }
    }
}

impl serde::ser::Serialize for EventSer<'_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut len: usize = 0;
        for prop in self.props {
            if prop.get_parser().is_some() {
                len += 1;
            } else if self.options.fail_unimplemented {
                return Err(serde::ser::Error::custom(format!(
                    "not implemented {} info: {:?}",
                    prop.name, prop.info
                )));
            }
        }

        let mut state = serializer.serialize_map(Some(len))?;
        for (index, prop) in self.props.iter().enumerate() {
            // Positional access: a name-based lookup would hand every
            // same-named property the bytes of the first one
            let buffer = self
                .parser
                .property_bytes_at(index)
                .map_err(serde::ser::Error::custom)?;
            ser_property::<S>(&mut state, prop, buffer, self.parser, self.record)?;
        }
        state.end()
    }
}

struct PropSer(PropHandler);

#[cfg(test)]
mod test {
    use windows::Win32::System::Diagnostics::Etw::{
        EVENT_HEADER_EXT_TYPE_PEBS_INDEX, EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID,
        EVENT_HEADER_EXT_TYPE_SID, EVENT_HEADER_EXT_TYPE_STACK_TRACE64,
        EVENT_HEADER_EXT_TYPE_TS_ID,
    };

    use super::*;
    use crate::native::{etw_types::extended_data::guid_bytes, tdh_types::PropertyLength};

    #[test]
    fn guid_serializes_like_its_debug_representation() {
        // GUIDExt used to format!("{:?}") on every serialization: the manual
        // hex writer must stay byte-for-byte identical
        for guid in [
            GUID::zeroed(),
            GUID::from_u128(0x56781234_abcd_4609_0102_030405060708),
            GUID::from_u128(u128::MAX),
            GUID::from_u128(0x00000000_0000_0000_0000_0000000000ff),
        ] {
            assert_eq!(
                serde_json::to_value(GUIDExt(guid)).unwrap(),
                serde_json::Value::String(format!("{guid:?}"))
            );
        }
    }

    #[test]
    fn header_serializes_flags_and_event_property_separately() {
        let header = EVENT_HEADER {
            Flags: 0x0001,
            EventProperty: 0x0002,
            ..Default::default()
        };

        let value = serde_json::to_value(HeaderSer::new(&header)).unwrap();
        assert_eq!(value["Flags"], serde_json::json!(0x0001));
        assert_eq!(value["EventProperty"], serde_json::json!(0x0002));
    }

    #[test]
    fn struct_properties_serialize_as_nested_objects() {
        use crate::parser::test_support::{PropSpec, synthetic_record, synthetic_schema};

        static NESTED_MEMBERS: [PropSpec; 1] =
            [PropSpec::new("inner_x", TdhInType::InTypeUInt32, 4)];
        static MEMBERS: [PropSpec; 3] = [
            PropSpec::new("x", TdhInType::InTypeUInt32, 4),
            PropSpec::structure("inner", &NESTED_MEMBERS),
            // Fixed-length string member: NUL-padded to 8 bytes (4 UTF-16 units)
            PropSpec::new("label", TdhInType::InTypeUnicodeString, 8),
        ];
        static PROPS: [PropSpec; 1] = [PropSpec::structure("s", &MEMBERS)];

        let schema = synthetic_schema(&PROPS);
        let mut data = Vec::new();
        data.extend_from_slice(&0xaabb_ccdd_u32.to_le_bytes());
        data.extend_from_slice(&7u32.to_le_bytes());
        for unit in [u16::from(b'h'), u16::from(b'i'), 0, 0] {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        let record = synthetic_record(&data);

        let ser = EventSerializer::new(&record, &schema, EventSerializerOptions {
            include_schema: false,
            include_header: false,
            ..Default::default()
        });
        let value = serde_json::to_value(ser).unwrap();
        assert_eq!(
            value["Event"],
            serde_json::json!({
                "s": {
                    "x": 0xAABB_CCDD_u32,
                    "inner": {"inner_x": 7},
                    "label": "hi",
                },
            })
        );
    }

    #[test]
    fn struct_arrays_serialize_as_element_arrays() {
        use crate::{
            native::tdh_types::PropertyFlags,
            parser::test_support::{PropSpec, synthetic_record, synthetic_schema},
        };

        static MEMBERS: [PropSpec; 2] = [
            PropSpec::new("a", TdhInType::InTypeUInt32, 4),
            PropSpec::new("b", TdhInType::InTypeUInt16, 2),
        ];
        static PROPS: [PropSpec; 2] = [
            PropSpec::new("count", TdhInType::InTypeUInt32, 4),
            // A constant-count array of structures. Dynamically-counted
            // arrays (`structure_array`, count held by another property)
            // need TDH to size the whole property, which requires a real
            // event; the parser tests cover their schema shape
            PropSpec {
                flags: PropertyFlags::PROPERTY_STRUCT.bits(),
                count: 2,
                structure: Some(&MEMBERS),
                ..PropSpec::new("items", TdhInType::InTypeNull, 0)
            },
        ];

        let schema = synthetic_schema(&PROPS);
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes()); // count
        for (a, b) in [(1u32, 10u16), (2, 20)] {
            data.extend_from_slice(&a.to_le_bytes());
            data.extend_from_slice(&b.to_le_bytes());
        }
        let record = synthetic_record(&data);

        let ser = EventSerializer::new(&record, &schema, EventSerializerOptions {
            include_schema: false,
            include_header: false,
            ..Default::default()
        });
        let value = serde_json::to_value(ser).unwrap();
        assert_eq!(
            value["Event"],
            serde_json::json!({
                "count": 2,
                "items": [
                    {"a": 1, "b": 10},
                    {"a": 2, "b": 20},
                ],
            })
        );
    }

    #[test]
    fn duplicate_property_names_serialize_in_schema_order() {
        // Manifests allow several properties with the same name; resolving
        // bytes by name used to emit the first match's value for all of them
        use crate::parser::test_support::{PropSpec, synthetic_record, synthetic_schema};

        let props = [
            PropSpec::new("a", TdhInType::InTypeUInt32, 4),
            PropSpec::new("b", TdhInType::InTypeUInt32, 4),
            PropSpec::new("a", TdhInType::InTypeUInt32, 4),
        ];
        let mut data = Vec::new();
        for v in [1u32, 2, 3] {
            data.extend_from_slice(&v.to_le_bytes());
        }
        let record = synthetic_record(&data);
        let schema = synthetic_schema(&props);

        let ser = EventSerializer::new(&record, &schema, EventSerializerOptions {
            include_schema: false,
            include_header: false,
            ..Default::default()
        });
        // serde_json::to_value would collapse the duplicate "a" keys: compare
        // the streamed output instead
        let json = serde_json::to_vec(&ser).unwrap();
        assert_eq!(json, br#"{"Event":{"a":1,"b":2,"a":3}}"#);
    }

    #[test]
    fn extended_data_serializes_supported_items() {
        let guid = GUID::from_u128(0x56781234_abcd_4609_0102_030405060708);
        // S-1-5-18 (Local System): revision 1, 1 sub-authority, authority 5, RID 18
        let mut sid_blob = vec![1u8, 1, 0, 0, 0, 0, 0, 5];
        sid_blob.extend_from_slice(&18u32.to_le_bytes());
        let mut stack_blob = 42u64.to_le_bytes().to_vec(); // MatchId
        stack_blob.extend_from_slice(&0x1000u64.to_le_bytes());
        stack_blob.extend_from_slice(&0x2000u64.to_le_bytes());
        let items = vec![
            EventHeaderExtendedDataItem::from_raw_parts(
                EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID,
                &guid_bytes(guid),
            ),
            EventHeaderExtendedDataItem::from_raw_parts(EVENT_HEADER_EXT_TYPE_SID, &sid_blob),
            EventHeaderExtendedDataItem::from_raw_parts(
                EVENT_HEADER_EXT_TYPE_TS_ID,
                &7u32.to_le_bytes(),
            ),
            EventHeaderExtendedDataItem::from_raw_parts(
                EVENT_HEADER_EXT_TYPE_STACK_TRACE64,
                &stack_blob,
            ),
        ];

        let value = serde_json::to_value(ExtendedSer::new(&items, false)).unwrap();
        assert_eq!(
            value,
            serde_json::json!([
                {"Type": "RelatedActivityId", "Data": "56781234-ABCD-4609-0102-030405060708"},
                {"Type": "Sid", "Data": "S-1-5-18"},
                {"Type": "TsId", "Data": 7},
                {"Type": "StackTrace64", "Data": {"MatchId": 42, "Addresses": [0x1000, 0x2000]}},
            ])
        );
    }

    #[test]
    fn unsupported_extended_data_is_skipped_or_fails() {
        // PEBS indexes are not parsed into an ExtendedDataItem variant
        let items = [EventHeaderExtendedDataItem::from_raw_parts(
            EVENT_HEADER_EXT_TYPE_PEBS_INDEX,
            &[0u8; 8],
        )];

        let value = serde_json::to_value(ExtendedSer::new(&items, false)).unwrap();
        assert_eq!(value, serde_json::json!([]));

        assert!(serde_json::to_value(ExtendedSer::new(&items, true)).is_err());
    }

    fn value_info(in_type: TdhInType) -> PropertyInfo {
        PropertyInfo::Value {
            in_type,
            out_type: TdhOutType::OutTypeNull,
            length: PropertyLength::Length(0),
        }
    }

    fn value_info_with_out(in_type: TdhInType, out_type: TdhOutType) -> PropertyInfo {
        PropertyInfo::Value {
            in_type,
            out_type,
            length: PropertyLength::Length(0),
        }
    }

    #[test]
    fn counted_strings_serialize_as_string() {
        // The WBEM (300+) and manifest (22/23) counted string variants share the
        // same layout, and must all go through the String handler
        for in_type in [
            TdhInType::InTypeManifestCountedString,
            TdhInType::InTypeCountedString,
            TdhInType::InTypeManifestCountedAnsiString,
            TdhInType::InTypeCountedAnsiString,
        ] {
            let info = value_info(in_type);
            assert_eq!(info.get_parser().map(|p| p.0), Some(PropHandler::String));
        }
    }

    #[test]
    fn socket_address_serializes_via_dedicated_handler() {
        let info = value_info_with_out(TdhInType::InTypeBinary, TdhOutType::OutTypeSocketAddress);
        assert_eq!(
            info.get_parser().map(|p| p.0),
            Some(PropHandler::SocketAddress)
        );
    }

    #[test]
    fn utf8_out_type_serializes_as_string() {
        // TraceLogging str8 fields: counted ANSI in type + Utf8 out type
        let info = value_info_with_out(TdhInType::InTypeCountedAnsiString, TdhOutType::OutTypeUtf8);
        assert_eq!(info.get_parser().map(|p| p.0), Some(PropHandler::String));
    }

    #[test]
    fn hex_int_fields_serialize_as_hex_strings() {
        // Manifest-style hex fields: the hex semantics come from the in type
        for (in_type, handler) in [
            (TdhInType::InTypeHexInt32, PropHandler::HexInt32),
            (TdhInType::InTypeHexInt64, PropHandler::HexInt64),
        ] {
            assert_eq!(value_info(in_type).get_parser().map(|p| p.0), Some(handler));
        }

        // TraceLogging hex fields: plain integer in type + hex out type
        for (out_type, handler) in [
            (TdhOutType::OutTypeHexInt32, PropHandler::HexInt32),
            (TdhOutType::OutTypeHexInt64, PropHandler::HexInt64),
        ] {
            let info = value_info_with_out(TdhInType::InTypeUInt32, out_type);
            assert_eq!(info.get_parser().map(|p| p.0), Some(handler));
        }

        assert_eq!(
            serde_json::to_value(HexDisplay(0x8007_0005u32)).unwrap(),
            serde_json::json!("0x80070005")
        );
        assert_eq!(
            serde_json::to_value(HexDisplay(u64::MAX)).unwrap(),
            serde_json::json!("0xffffffffffffffff")
        );
    }
}

trait PropSerable {
    fn get_parser(&self) -> Option<PropSer>;
}

#[derive(Debug, PartialEq)]
enum PropHandler {
    Null,
    Bool,
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    HexInt32,
    HexInt64,
    Pointer,
    Float,
    Double,
    String,
    FileTime,
    SystemTime,
    Guid,
    Binary,
    IpAddr,
    SocketAddress,
    Struct,
    StructArray,
    ArrayInt16,
    ArrayUInt16,
    ArrayInt32,
    ArrayUInt32,
    ArrayInt64,
    ArrayUInt64,
    ArrayPointer,
}

/// Serializes an integer with a hex out type as a `"0x..."` string, keeping
/// the display semantics of `win:HexInt32`/`win:HexInt64` fields (krabsetw
/// parity) instead of a plain number
struct HexDisplay<T: std::fmt::LowerHex>(T);

impl<T: std::fmt::LowerHex> std::fmt::Display for HexDisplay<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

impl<T: std::fmt::LowerHex> serde::ser::Serialize for HexDisplay<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.collect_str(self)
    }
}

macro_rules! prop_ser_type {
    ($typ:ty, $map:expr, $prop:expr, $parser:expr, $buffer:expr) => {{
        let v = $parser
            .try_parse_member::<$typ>($prop, $buffer)
            .map_err(serde::ser::Error::custom)?;
        $map.serialize_entry(&$prop.name, &v)
    }};
}

/// Serializes one structure element as a nested map: fixed-size members are
/// sliced out of `bytes` and decoded through the parser, variable-length
/// members are skipped
struct StructSer<'a, 'b, 'p, 'r> {
    members: &'a [Property],
    bytes: &'b [u8],
    parser: &'p Parser<'a, 'b>,
    record: &'r EventRecord,
}

impl serde::ser::Serialize for StructSer<'_, '_, '_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.members.len()))?;
        let mut offset = 0;
        for member in self.members {
            let Some(size) = member.fixed_size(self.record.pointer_size()) else {
                // Variable-length member: cannot be located without TDH help
                continue;
            };
            let Some(buffer) = self.bytes.get(offset..offset + size) else {
                break;
            };
            offset += size;
            ser_property::<S>(&mut map, member, buffer, self.parser, self.record)?;
        }
        map.end()
    }
}

/// Serializes an array of structures as a nested array of maps. Elements are
/// `stride` bytes apart, starting at `bytes`
struct StructArraySer<'a, 'b, 'p, 'r> {
    members: &'a [Property],
    count: usize,
    stride: usize,
    bytes: &'b [u8],
    parser: &'p Parser<'a, 'b>,
    record: &'r EventRecord,
}

impl serde::ser::Serialize for StructArraySer<'_, '_, '_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.count))?;
        for i in 0..self.count {
            let Some(element) = self.bytes.get(i * self.stride..(i + 1) * self.stride) else {
                break;
            };
            seq.serialize_element(&StructSer {
                members: self.members,
                bytes: element,
                parser: self.parser,
                record: self.record,
            })?;
        }
        seq.end()
    }
}

/// Writes one property (or structure member) entry into `map`, decoding the
/// value from `buffer` through the parser
fn ser_property<'a, 'b, S>(
    map: &mut S::SerializeMap,
    prop: &'a Property,
    buffer: &'b [u8],
    parser: &Parser<'a, 'b>,
    record: &EventRecord,
) -> Result<(), S::Error>
where
    S: serde::ser::Serializer,
{
    // Structures recurse into nested serialization
    if let PropertyInfo::Struct { members } = &prop.info {
        return map.serialize_entry(&prop.name, &StructSer {
            members,
            bytes: buffer,
            parser,
            record,
        });
    }
    if let PropertyInfo::StructArray { members, count } = &prop.info {
        let resolved = resolve_struct_count(*count, parser);
        // TDH sizes the whole array; the stride follows from the element count
        let stride = resolved.filter(|&c| c > 0).map_or(0, |c| buffer.len() / c);
        return map.serialize_entry(&prop.name, &StructArraySer {
            members,
            count: resolved.unwrap_or(0),
            stride,
            bytes: buffer,
            parser,
            record,
        });
    }

    let Some(s) = prop.get_parser() else {
        return Ok(());
    };
    s.0.ser_from_bytes::<S>(map, prop, parser, record, buffer)
}

/// Resolves the element count of a structure array: either a constant, or the
/// value of the property `PropertyCount::Index` points at
fn resolve_struct_count(count: PropertyCount, parser: &Parser) -> Option<usize> {
    match count {
        PropertyCount::Count(c) => Some(c as usize),
        // The index is positional: a same-named property earlier in the
        // schema must not shadow the referenced one
        PropertyCount::Index(i) => {
            parser.top_level_properties().get(i as usize)?;
            let bytes = parser.property_bytes_at(i as usize).ok()?;
            match bytes.len() {
                1 => Some(bytes[0] as usize),
                2 => Some(u16::from_ne_bytes(bytes.try_into().ok()?) as usize),
                4 => Some(u32::from_ne_bytes(bytes.try_into().ok()?) as usize),
                8 => usize::try_from(u64::from_ne_bytes(bytes.try_into().ok()?)).ok(),
                _ => None,
            }
        },
    }
}

impl PropHandler {
    fn ser_from_bytes<'a, 'b, S>(
        &self,
        map: &mut S::SerializeMap,
        prop: &'a Property,
        parser: &Parser<'a, 'b>,
        record: &EventRecord,
        buffer: &'b [u8],
    ) -> Result<(), S::Error>
    where
        S: serde::ser::Serializer,
    {
        match self {
            PropHandler::Bool => prop_ser_type!(bool, map, prop, parser, buffer),
            PropHandler::Int8 => prop_ser_type!(i8, map, prop, parser, buffer),
            PropHandler::UInt8 => prop_ser_type!(u8, map, prop, parser, buffer),
            PropHandler::Int16 => prop_ser_type!(i16, map, prop, parser, buffer),
            PropHandler::UInt16 => prop_ser_type!(u16, map, prop, parser, buffer),
            PropHandler::Int32 => prop_ser_type!(i32, map, prop, parser, buffer),
            PropHandler::UInt32 => prop_ser_type!(u32, map, prop, parser, buffer),
            PropHandler::Int64 => prop_ser_type!(i64, map, prop, parser, buffer),
            PropHandler::UInt64 => prop_ser_type!(u64, map, prop, parser, buffer),
            PropHandler::HexInt32 => {
                let v = parser
                    .try_parse_member::<u32>(prop, buffer)
                    .map_err(serde::ser::Error::custom)?;
                map.serialize_entry(&prop.name, &HexDisplay(v))
            },
            PropHandler::HexInt64 => {
                let v = parser
                    .try_parse_member::<u64>(prop, buffer)
                    .map_err(serde::ser::Error::custom)?;
                map.serialize_entry(&prop.name, &HexDisplay(v))
            },
            PropHandler::Float => prop_ser_type!(f32, map, prop, parser, buffer),
            PropHandler::Double => prop_ser_type!(f64, map, prop, parser, buffer),
            PropHandler::String => prop_ser_type!(String, map, prop, parser, buffer),
            PropHandler::Binary => prop_ser_type!(Vec<u8>, map, prop, parser, buffer),
            PropHandler::IpAddr => prop_ser_type!(IpAddr, map, prop, parser, buffer),
            PropHandler::SocketAddress => {
                prop_ser_type!(TdhSocketAddress, map, prop, parser, buffer)
            },
            PropHandler::FileTime => prop_ser_type!(FileTime, map, prop, parser, buffer),
            PropHandler::SystemTime => prop_ser_type!(SystemTime, map, prop, parser, buffer),
            PropHandler::ArrayInt16 => prop_ser_type!(&[i16], map, prop, parser, buffer),
            PropHandler::ArrayUInt16 => prop_ser_type!(&[u16], map, prop, parser, buffer),
            PropHandler::ArrayInt32 => prop_ser_type!(&[i32], map, prop, parser, buffer),
            PropHandler::ArrayUInt32 => prop_ser_type!(&[u32], map, prop, parser, buffer),
            PropHandler::ArrayInt64 => prop_ser_type!(&[i64], map, prop, parser, buffer),
            PropHandler::ArrayUInt64 => prop_ser_type!(&[u64], map, prop, parser, buffer),
            PropHandler::Null => {
                let value: Option<usize> = None;
                map.serialize_entry(&prop.name, &value)
            },
            PropHandler::Pointer => {
                if record.pointer_size() == 4 {
                    prop_ser_type!(u32, map, prop, parser, buffer)
                } else {
                    prop_ser_type!(u64, map, prop, parser, buffer)
                }
            },
            PropHandler::ArrayPointer => {
                if record.pointer_size() == 4 {
                    prop_ser_type!(&[u32], map, prop, parser, buffer)
                } else {
                    prop_ser_type!(&[u64], map, prop, parser, buffer)
                }
            },
            PropHandler::Guid => {
                let guid = parser
                    .try_parse_member::<GUID>(prop, buffer)
                    .map_err(serde::ser::Error::custom)?;
                map.serialize_entry(&prop.name, &GUIDExt(guid))
            },
            // Structures are handled by `ser_property`, never dispatched here
            PropHandler::Struct | PropHandler::StructArray => {
                unreachable!("structure properties go through the nested serializers")
            },
        }
    }
}

impl PropSerable for PropertyInfo {
    fn get_parser(&self) -> Option<PropSer> {
        // give the output type parser first if there is one, otherwise use the input type
        match self {
            PropertyInfo::Value {
                in_type, out_type, ..
            } => {
                match out_type {
                    TdhOutType::OutTypeIpv4 | TdhOutType::OutTypeIpv6 => {
                        Some(PropSer(PropHandler::IpAddr))
                    },
                    TdhOutType::OutTypeSocketAddress => Some(PropSer(PropHandler::SocketAddress)),
                    // TraceLogging str8 fields: the payload is a counted
                    // string whose bytes are UTF-8 (see the parser tests for
                    // the TDH type mapping)
                    TdhOutType::OutTypeUtf8 => Some(PropSer(PropHandler::String)),
                    // TraceLogging `hex` fields: the hex semantic comes from
                    // the out type, the in type stays a plain integer
                    TdhOutType::OutTypeHexInt32 => Some(PropSer(PropHandler::HexInt32)),
                    TdhOutType::OutTypeHexInt64 => Some(PropSer(PropHandler::HexInt64)),
                    _ => match in_type {
                        TdhInType::InTypeNull => Some(PropSer(PropHandler::Null)),
                        // `try_parse::<String>` is implemented for the counted string
                        // in types (see parser.rs)
                        TdhInType::InTypeUnicodeString
                        | TdhInType::InTypeAnsiString
                        | TdhInType::InTypeSid
                        | TdhInType::InTypeManifestCountedString
                        | TdhInType::InTypeCountedString
                        | TdhInType::InTypeManifestCountedAnsiString
                        | TdhInType::InTypeCountedAnsiString => Some(PropSer(PropHandler::String)),
                        TdhInType::InTypeInt8 => Some(PropSer(PropHandler::Int8)),
                        TdhInType::InTypeUInt8 => Some(PropSer(PropHandler::UInt8)),
                        TdhInType::InTypeInt16 => Some(PropSer(PropHandler::Int16)),
                        TdhInType::InTypeUInt16 => Some(PropSer(PropHandler::UInt16)),
                        TdhInType::InTypeInt32 => Some(PropSer(PropHandler::Int32)),
                        TdhInType::InTypeUInt32 => Some(PropSer(PropHandler::UInt32)),
                        TdhInType::InTypeInt64 => Some(PropSer(PropHandler::Int64)),
                        TdhInType::InTypeUInt64 => Some(PropSer(PropHandler::UInt64)),
                        // Hex display semantics, whatever the width of the
                        // underlying integer
                        TdhInType::InTypeHexInt32 => Some(PropSer(PropHandler::HexInt32)),
                        TdhInType::InTypeHexInt64 => Some(PropSer(PropHandler::HexInt64)),
                        TdhInType::InTypeFloat => Some(PropSer(PropHandler::Float)),
                        TdhInType::InTypeDouble => Some(PropSer(PropHandler::Double)),
                        TdhInType::InTypeBoolean => Some(PropSer(PropHandler::Bool)),
                        TdhInType::InTypeBinary => Some(PropSer(PropHandler::Binary)),
                        TdhInType::InTypeGuid => Some(PropSer(PropHandler::Guid)),
                        TdhInType::InTypePointer => Some(PropSer(PropHandler::Pointer)),
                        TdhInType::InTypeFileTime => Some(PropSer(PropHandler::FileTime)),
                        TdhInType::InTypeSystemTime => Some(PropSer(PropHandler::SystemTime)),
                    },
                }
            },
            PropertyInfo::Array { in_type, .. } => {
                match in_type {
                    TdhInType::InTypeInt16 => Some(PropSer(PropHandler::ArrayInt16)),
                    TdhInType::InTypeUInt16 => Some(PropSer(PropHandler::ArrayUInt16)),
                    TdhInType::InTypeInt32 => Some(PropSer(PropHandler::ArrayInt32)),
                    TdhInType::InTypeUInt32 => Some(PropSer(PropHandler::ArrayUInt32)),
                    TdhInType::InTypeInt64 => Some(PropSer(PropHandler::ArrayInt64)),
                    TdhInType::InTypeUInt64 => Some(PropSer(PropHandler::ArrayUInt64)),
                    TdhInType::InTypePointer => Some(PropSer(PropHandler::ArrayPointer)),
                    _ => None, // TODO
                }
            },
            // Structures serialize as nested maps/arrays (see `ser_property`)
            PropertyInfo::Struct { .. } => Some(PropSer(PropHandler::Struct)),
            PropertyInfo::StructArray { .. } => Some(PropSer(PropHandler::StructArray)),
        }
    }
}

impl PropSerable for Property {
    fn get_parser(&self) -> Option<PropSer> {
        self.info.get_parser()
    }
}
