//! ETW Types Parser
//!
//! This module act as a helper to parse the Buffer from an ETW Event

use std::{
    cell::RefCell,
    convert::TryInto,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use windows::core::GUID;

use crate::{
    native::{
        DecodingSource,
        etw_types::event_record::EventRecord,
        sddl, tdh,
        tdh_types::{
            Property, PropertyCount, PropertyInfo, PropertyLength, TdhInType, TdhOutType,
            index_value_from_bytes,
        },
        time::{FileTime, SystemTime},
    },
    property::PropertySlice,
    schema::Schema,
};

/// Parser module errors
#[derive(Debug)]
pub enum ParserError {
    /// No property has this name
    NotFound,
    /// An invalid type
    InvalidType,
    /// Error parsing
    ParseError,
    /// Length mismatch when parsing a type
    LengthMismatch,
    PropertyError(String),
    /// An error while transforming an Utf-8 buffer into String
    Utf8Error(std::str::Utf8Error),
    /// An error trying to get an slice as an array
    SliceError(std::array::TryFromSliceError),
    /// Represents an internal [SddlNativeError](crate::native::SddlNativeError)
    SddlNativeError(crate::native::SddlNativeError),
    /// Represents an internal [TdhNativeError](crate::native::TdhNativeError)
    TdhNativeError(crate::native::TdhNativeError),
}

impl From<crate::native::TdhNativeError> for ParserError {
    fn from(err: crate::native::TdhNativeError) -> Self {
        ParserError::TdhNativeError(err)
    }
}

impl From<crate::native::SddlNativeError> for ParserError {
    fn from(err: crate::native::SddlNativeError) -> Self {
        ParserError::SddlNativeError(err)
    }
}

impl From<std::str::Utf8Error> for ParserError {
    fn from(err: std::str::Utf8Error) -> Self {
        ParserError::Utf8Error(err)
    }
}

impl From<std::array::TryFromSliceError> for ParserError {
    fn from(err: std::array::TryFromSliceError) -> Self {
        ParserError::SliceError(err)
    }
}

impl std::fmt::Display for ParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "not found"),
            Self::InvalidType => write!(f, "invalid type"),
            Self::ParseError => write!(f, "parse error"),
            Self::LengthMismatch => write!(f, "length mismatch"),
            Self::PropertyError(s) => write!(f, "property error {s}"),
            Self::Utf8Error(e) => write!(f, "utf-8 error {e}"),
            Self::SliceError(e) => write!(f, "slice error {e}"),
            Self::SddlNativeError(e) => write!(f, "sddl native error {e}"),
            Self::TdhNativeError(e) => write!(f, "tdh native error {e}"),
        }
    }
}

type ParserResult<T> = Result<T, ParserError>;

mod socket_address;

pub use socket_address::{AddressFamily, TdhSocketAddress};

#[derive(Default)]
/// Cache of the properties we've extracted already
///
/// This is useful because computing their offset can be costly
///
/// The slices are stored in schema order (one entry per parsed property, even
/// when names repeat), and looked up by probing from `next_probe` (right after
/// the last hit, wrapping around): property access usually follows schema
/// order, so this finds entries in O(1) without any hashing, and without
/// allocating a key per parsed property.
struct CachedSlices<'schema, 'record> {
    slices: Vec<PropertySlice<'schema, 'record>>,
    /// Where the next name lookup starts probing
    next_probe: usize,
    /// The user buffer index we've cached up to
    last_cached_offset: usize,
    /// Where the property values start within the user buffer, or `None`
    /// when the buffer layout is not supported
    data_start: Option<usize>,
}

/// Represents a Parser
///
/// This structure provides a way to parse an ETW event (= extract its properties).
/// Because properties may have variable length (e.g. strings), a `Parser` is only suited to a
/// single [`EventRecord`]
///
/// A `Parser` is meant to live on the callback stack for a single event: its cache uses
/// unsynchronized interior mutability (`RefCell`), so it is neither `Send` nor `Sync`
/// (it already could not be, as it borrows an [`EventRecord`]).
///
/// # Example
/// ```
/// # use ferrisetw::EventRecord;
/// # use ferrisetw::schema_locator::SchemaLocator;
/// # use ferrisetw::parser::Parser;
/// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
///     let schema = schema_locator.event_schema(record).unwrap();
///     let parser = Parser::create(record, &schema);
///
///     // There are several ways to define the type requested for `try_parse`
///     // It is possible to use type inference...
///     let property1: Option<String> = parser.try_parse("PropertyName").ok();
///
///     // ...or to use the turbofish operator
///     match parser.try_parse::<u32>("OtherPropertyName") {
///         Ok(_) => println!("OtherPropertyName is a valid u32"),
///         Err(_) => println!("OtherPropertyName is invalid"),
///     }
/// };
/// ```
#[allow(dead_code)]
pub struct Parser<'schema, 'record> {
    properties: &'schema [Property],
    record: &'record EventRecord,
    cache: RefCell<CachedSlices<'schema, 'record>>,
}

impl<'schema, 'record> Parser<'schema, 'record> {
    /// Use the `create` function to create an instance of a Parser
    ///
    /// # Arguments
    /// * `schema` - The [Schema] from the ETW Event we want to parse
    ///
    /// # Example
    /// ```
    /// # use ferrisetw::EventRecord;
    /// # use ferrisetw::schema_locator::SchemaLocator;
    /// # use ferrisetw::parser::Parser;
    /// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
    ///     let schema = schema_locator.event_schema(record).unwrap();
    ///     let parser = Parser::create(record, &schema);
    /// };
    /// ```
    pub fn create(event_record: &'record EventRecord, schema: &'schema Schema) -> Self {
        Parser {
            record: event_record,
            properties: schema.properties(),
            cache: RefCell::new(CachedSlices {
                data_start: property_values_start(event_record, schema),
                ..Default::default()
            }),
        }
    }

    #[allow(clippy::len_zero)]
    fn find_property_size(
        &self,
        property: &Property,
        parsed: &[PropertySlice<'schema, 'record>],
        remaining_user_buffer: &[u8],
    ) -> ParserResult<usize> {
        // Value of the property a countPropertyIndex/lengthPropertyIndex
        // points at. Only backward references into the already parsed
        // top-level properties resolve locally — the usual layout, the
        // carrier being declared before its user; anything else defers to
        // TDH
        let index_value = |index: u16| -> Option<usize> {
            index_value_from_bytes(parsed.get(usize::from(index))?.buffer)
        };

        match property.info {
            PropertyInfo::Value {
                in_type,
                out_type,
                length,
            } => {
                // For pointer input types we can immediately infer the size
                // based on the header flags (SIZET is the deprecated WBEM
                // pointer: same rule)
                if matches!(in_type, TdhInType::InTypePointer | TdhInType::InTypeSizeT) {
                    return Ok(self.record.pointer_size());
                }

                // EVENT_PROPERTY_INFO.length is a union: either a literal
                // size or (with `PropertyParamLength`) the index of the
                // property holding it, e.g. the WinInet provider manifest has
                // fields such as `<data name="Verb" inType="win:AnsiString"
                // length="_VerbLength"/>`. tdh.h: the index carries the size
                // in the same unit as a literal length (WCHARs/BYTEs per in
                // type), and fixed-size in types ignore the length property
                // entirely, whatever its form
                match length {
                    // A literal length is u16: the unit conversion cannot
                    // overflow. Content-sized in types determine their size
                    // from the field bytes themselves: tdh.h says their
                    // length property must be ignored, in either form
                    PropertyLength::Length(l) if l > 0 && !in_type.is_content_sized() => {
                        return Ok(in_type.literal_schema_length_bytes(l));
                    },
                    PropertyLength::Index(index) if !in_type.is_content_sized() => {
                        if let Some(size) = in_type.fixed_size() {
                            return Ok(size);
                        }
                        // The carrier value is raw event data: when the unit
                        // conversion overflows, defer to TDH (which rejects
                        // absurd sizes) instead of wrapping the size around —
                        // a wrapped size would silently misalign every
                        // following property
                        return match index_value(index)
                            .and_then(|len| in_type.schema_length_bytes(len))
                        {
                            Some(size) => Ok(size),
                            None => self.tdh_property_size(property),
                        };
                    },
                    // A zero literal length, or a content-sized type: the
                    // size follows from the type below
                    _ => (),
                }

                // No usable length. We'll have to ask TDH for the right length.
                // However, before doing so, there are some cases where we could determine
                // ourselves. The following _very_ common property types can be
                // short-circuited to prevent the expensive call. (that's taken from
                // krabsetw)

                match in_type {
                    TdhInType::InTypeAnsiString => {
                        // The property spans up to and including the NUL terminator
                        let Some(nul_index) = memchr::memchr(0, remaining_user_buffer) else {
                            return Err(ParserError::PropertyError(
                                "AnsiString property is not null-terminated".into(),
                            ));
                        };
                        return Ok(nul_index + 1);
                    },
                    TdhInType::InTypeUnicodeString => {
                        // The property spans up to and including the NUL terminator
                        let Some(nul_index) = remaining_user_buffer
                            .chunks_exact(2)
                            .position(|bytes| u16::from_ne_bytes(bytes.try_into().unwrap()) == 0)
                        else {
                            return Err(ParserError::PropertyError(
                                "UnicodeString property is not null-terminated".into(),
                            ));
                        };
                        return Ok((nul_index + 1) * 2);
                    },
                    TdhInType::InTypeManifestCountedString
                    | TdhInType::InTypeCountedString
                    | TdhInType::InTypeManifestCountedAnsiString
                    | TdhInType::InTypeCountedAnsiString
                    | TdhInType::InTypeReversedCountedString
                    | TdhInType::InTypeReversedCountedAnsiString
                    | TdhInType::InTypeManifestCountedBinary => {
                        // All counted variants share the same layout: a 16-bit
                        // byte count (little-endian, big-endian for the
                        // deprecated REVERSED twins) then the payload.
                        // (TraceLogging events leave the TDH length at 0, and
                        // TdhGetPropertySize is a costly round-trip)
                        let big_endian = matches!(
                            in_type,
                            TdhInType::InTypeReversedCountedString
                                | TdhInType::InTypeReversedCountedAnsiString
                        );
                        let byte_count = read_count_prefix(remaining_user_buffer, big_endian)?;
                        return Ok(size_of::<u16>() + byte_count);
                    },
                    TdhInType::InTypeNonNullTerminatedString
                    | TdhInType::InTypeNonNullTerminatedAnsiString => {
                        // tdh.h: the field spans "the remaining bytes of data
                        // in the event", so it can only be the last one
                        return Ok(remaining_user_buffer.len());
                    },
                    TdhInType::InTypeSid | TdhInType::InTypeWbemSid => {
                        // tdh.h: a SID's size "is determined by reading the
                        // first few bytes of the field value to determine the
                        // number of relative IDs": revision (1) + count (1) +
                        // authority (6) + 4 bytes per relative ID
                        let Some(sub_authority_count) = remaining_user_buffer.get(1) else {
                            return Err(ParserError::PropertyError(
                                "SID property is truncated".into(),
                            ));
                        };
                        return Ok(8 + 4 * usize::from(*sub_authority_count));
                    },
                    TdhInType::InTypeHexDump => {
                        // Deprecated WBEM TDH_INTYPE_HEXDUMP: a little-endian
                        // 32-bit byte count, then that many payload bytes
                        let Some(count_bytes) = remaining_user_buffer.get(..size_of::<u32>())
                        else {
                            return Err(ParserError::PropertyError(
                                "hexdump property is truncated".into(),
                            ));
                        };
                        // Guaranteed by the slice length above
                        let count = u32::from_le_bytes(count_bytes.try_into().unwrap());
                        return Ok(size_of::<u32>() + count as usize);
                    },
                    TdhInType::InTypeBinary if out_type == TdhOutType::OutTypeIpv6 => {
                        // tdh.h: a BINARY field with the IPV6 out type spans
                        // 16 bytes when no length applies
                        return Ok(16);
                    },
                    _ => (),
                }

                // Fixed-size in types carry their size in the in type itself:
                // tdh.h says the length property "can be ignored by decoders",
                // which also spares a TDH round-trip when a WBEM/MOF schema
                // leaves it at 0
                if let Some(size) = in_type.fixed_size() {
                    return Ok(size);
                }

                self.tdh_property_size(property)
            },
            PropertyInfo::Array {
                in_type,
                length,
                count,
                ..
            } => {
                // Element size: pointer input types follow the header flags,
                // an explicit nonzero length uses the per-in-type unit, a
                // length by index resolves like a literal one, and fixed-size
                // in types ignore the length entirely (tdh.h)
                let elem_size =
                    if matches!(in_type, TdhInType::InTypePointer | TdhInType::InTypeSizeT) {
                        Some(self.record.pointer_size())
                    } else {
                        match length {
                            PropertyLength::Length(0) => in_type.fixed_size(),
                            PropertyLength::Length(l) => {
                                Some(in_type.literal_schema_length_bytes(l))
                            },
                            PropertyLength::Index(index) => in_type.fixed_size().or_else(|| {
                                index_value(index).and_then(|len| in_type.schema_length_bytes(len))
                            }),
                        }
                    };

                let element_count = match count {
                    PropertyCount::Count(c) => c as usize,
                    PropertyCount::Index(index) => match index_value(index) {
                        Some(count) => count,
                        None => return self.tdh_property_size(property),
                    },
                };

                // The element count may be a raw carrier value: an overflow
                // defers to TDH (which rejects absurd sizes) instead of
                // wrapping the total size around
                match elem_size.and_then(|elem| elem.checked_mul(element_count)) {
                    Some(size) => Ok(size),
                    // An empty array occupies no bytes even when its elements
                    // are variable-length (e.g. NUL-terminated strings)
                    None if element_count == 0 => Ok(0),
                    // Variable-length elements (e.g. arrays of NUL-terminated
                    // strings with no schema length) still need TDH
                    None => self.tdh_property_size(property),
                }
            },
            // Structures span all of their members: when every member has a
            // fixed size the total follows from the schema, otherwise defer
            // to TDH (e.g. a count held by another property)
            PropertyInfo::Struct { .. } | PropertyInfo::StructArray { .. } => {
                if let Some(size) = property.fixed_size(self.record.pointer_size()) {
                    return Ok(size);
                }
                // A structure array whose element count travels by reference
                // is still fixed-size per element: resolve the count the same
                // way TDH would
                if let PropertyInfo::StructArray {
                    members,
                    count: PropertyCount::Index(index),
                } = &property.info
                {
                    if let (Some(elem), Some(count)) = (
                        members
                            .iter()
                            .map(|m| m.fixed_size(self.record.pointer_size()))
                            .sum::<Option<usize>>(),
                        index_value(*index),
                    ) {
                        // The count carrier is raw event data: an overflow defers
                        // to TDH instead of wrapping the size around
                        if let Some(size) = elem.checked_mul(count) {
                            return Ok(size);
                        }
                    }
                }
                self.tdh_property_size(property)
            },
            // A property this crate cannot decode still occupies its bytes: a
            // schema-declared length keeps the walk local, otherwise defer to
            // TDH (its size computation does not depend on our decoding
            // support)
            PropertyInfo::Unsupported { length } => match length {
                PropertyLength::Length(l) if l > 0 => Ok(usize::from(l)),
                PropertyLength::Length(_) => self.tdh_property_size(property),
                PropertyLength::Index(index) => match index_value(index) {
                    Some(len) => Ok(len),
                    None => self.tdh_property_size(property),
                },
            },
        }
    }

    /// The sizes that cannot be determined locally: a native
    /// `TdhGetPropertySize` round-trip per (property, event)
    fn tdh_property_size(&self, property: &Property) -> ParserResult<usize> {
        Ok(tdh::property_size(self.record, property)? as usize)
    }

    fn find_property(&self, name: &str) -> ParserResult<PropertySlice<'schema, 'record>> {
        let mut cache = self.cache.borrow_mut();

        // We may have extracted this property already: probe right after the
        // last hit first, as successive accesses usually advance in schema order
        for i in 0..cache.slices.len() {
            let idx = (cache.next_probe + i) % cache.slices.len();
            if cache.slices[idx].property.name == name {
                cache.next_probe = (idx + 1) % cache.slices.len();
                return Ok(cache.slices[idx]);
            }
        }

        // Parse properties in schema order until the name matches; a name
        // that survives the whole schema does not exist. Manifests may repeat
        // property names, so this keeps the "first same-named match"
        // semantics: the probe above finds the oldest cached entry first
        while cache.slices.len() < self.properties.len() {
            self.parse_next_property(&mut cache)?;
            let last = cache.slices.last().expect("a property was just pushed");
            if last.property.name == name {
                return Ok(*last);
            }
        }

        Err(ParserError::NotFound)
    }

    /// Parses the next unparsed top-level property into the cache, advancing
    /// `last_cached_offset` by its size.
    ///
    /// Shared by the name-based lookup ([`Parser::find_property`]) and the
    /// serializer's index-based access ([`Parser::property_bytes_at`]): parse
    /// order is schema order
    fn parse_next_property(&self, cache: &mut CachedSlices<'schema, 'record>) -> ParserResult<()> {
        let Some(property) = self.properties.get(cache.slices.len()) else {
            return Err(ParserError::NotFound);
        };
        let Some(data_start) = cache.data_start else {
            return Err(ParserError::PropertyError(
                "unsupported event layout: inline TraceLogging metadata".into(),
            ));
        };
        let Some(remaining_user_buffer) = self
            .record
            .user_buffer()
            .get(data_start + cache.last_cached_offset..)
        else {
            return Err(ParserError::PropertyError(
                "Invalid buffer bounds".to_owned(),
            ));
        };

        let prop_size = self.find_property_size(property, &cache.slices, remaining_user_buffer)?;
        let Some(property_buffer) = remaining_user_buffer.get(..prop_size) else {
            return Err(ParserError::PropertyError(
                "Property length out of buffer bounds".to_owned(),
            ));
        };

        cache.slices.push(PropertySlice {
            property,
            buffer: property_buffer,
        });
        cache.last_cached_offset += prop_size;
        Ok(())
    }

    /// Return a property from the event, or an error in case the parsing failed.
    ///
    /// You must explicitly define `T`, the type you want to parse the property into.<br/>
    /// In case this type is not compatible with the ETW type, [`ParserError::InvalidType`] is
    /// returned.
    pub fn try_parse<T>(&self, name: &str) -> ParserResult<T>
    where
        Parser<'schema, 'record>: private::TryParse<'schema, 'record, T>,
    {
        private::TryParse::<'schema, 'record, T>::try_parse_slice(self, self.find_property(name)?)
    }

    /// Bytes of the `index`-th top-level property (schema order), located
    /// through the parse cache.
    ///
    /// Unlike a name-based lookup this tells same-named properties apart:
    /// manifests may repeat a property name, and the serializer walks the
    /// properties in schema order.
    // Read by the serializer, which slices structures out of them
    #[allow(dead_code)] // Compiled out without the serde feature
    pub(crate) fn property_bytes_at(&self, index: usize) -> ParserResult<&'record [u8]> {
        {
            let mut cache = self.cache.borrow_mut();
            while cache.slices.len() <= index {
                self.parse_next_property(&mut cache)?;
            }
        }
        let cache = self.cache.borrow();
        Ok(cache.slices[index].buffer)
    }

    /// The top-level properties of the schema behind this parser
    // Read by the serializer, to resolve structure array element counts
    #[allow(dead_code)]
    pub(crate) fn top_level_properties(&self) -> &'schema [Property] {
        self.properties
    }

    /// Parse a structure member out of an already-located byte range.
    ///
    /// Structure members are not top-level properties, so they cannot be
    /// found by name like `try_parse` does: the caller (the serializer)
    /// slices them out of the enclosing structure's bytes and hands the
    /// slice over. Decoding works on that slice directly, so a member whose
    /// name matches a top-level property (manifests may repeat names) still
    /// reads its own bytes.
    #[allow(dead_code)] // Compiled out without the serde feature
    pub(crate) fn try_parse_member<T>(
        &self,
        member: &'schema Property,
        buffer: &'record [u8],
    ) -> ParserResult<T>
    where
        Parser<'schema, 'record>: private::TryParse<'schema, 'record, T>,
    {
        private::TryParse::<'schema, 'record, T>::try_parse_slice(self, PropertySlice {
            property: member,
            buffer,
        })
    }
}

/// Offset of the first property value within the event's user buffer, or
/// `None` for the unsupported inline TraceLogging metadata layout.
///
/// Self-describing (TraceLogging) events always carry their decoding metadata
/// with the event, in one of two forms:
///
/// * Extended data items (`EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL` and `PROV_TRAITS`), how the
///   logger delivers real-time sessions and ETL replays: the user buffer then holds the property
///   values only, starting at offset 0.
/// * Embedded at the start of the user buffer, when the metadata descriptors could not be hoisted
///   into extended data (raw descriptor layout): two tightly-packed blobs, each prefixed with its
///   total `u16` size (itself included) — provider metadata, then event metadata
///   (`_tlgProviderMetadata_t`/`_tlgEventMetadata_t` in TraceLoggingProvider.h) — followed by the
///   property values.
///
/// TDH decodes the schema of both forms (`DecodingSource` is `Tlg` for
/// either), but it only knows how to locate the metadata: `TdhGetProperty`
/// and `TdhGetPropertySize` always compute property offsets from the start
/// of the user buffer, i.e. they do not skip the embedded blobs either
/// (verified against the real TDH: on such events both APIs return the
/// metadata bytes as property data). Parsing values ourselves would silently
/// report those bytes as property values, so the embedded layout is rejected
/// with an explicit error instead of misread data.
///
/// The detection cannot misfire on a decodable event: a `Tlg` decoding
/// source without those extended data items means TDH could only have found
/// the schema in the embedded blobs (a record carrying the values alone
/// fails to decode, so there is no schema cache path either).
fn property_values_start(record: &EventRecord, schema: &Schema) -> Option<usize> {
    use windows::Win32::System::Diagnostics::Etw::{
        EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL, EVENT_HEADER_EXT_TYPE_PROV_TRAITS,
    };

    if !matches!(schema.decoding_source(), DecodingSource::DecodingSourceTlg) {
        return Some(0);
    }
    let metadata_in_extended_data = record.extended_data().iter().any(|item| {
        let ext_type = u32::from(item.data_type());
        ext_type == EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL
            || ext_type == EVENT_HEADER_EXT_TYPE_PROV_TRAITS
    });
    if metadata_in_extended_data {
        return Some(0);
    }

    None
}

mod private {
    use super::*;

    /// Trait to try and parse a type
    ///
    /// This trait has to be implemented in order to be able to parse a type we want to retrieve
    /// from within an Event.
    ///
    /// An implementation for most of the Primitive Types is created by using a Macro, any other
    /// needed type requires this trait to be implemented
    pub trait TryParse<'schema, 'record, T> {
        /// Decode `T` out of an already-located property slice, or return an
        /// error in case the type `T` can't be parsed
        ///
        /// Working on the slice (instead of a property name) keeps the
        /// decoding of same-named properties and of structure members on the
        /// exact bytes the caller located
        fn try_parse_slice(
            &self,
            prop_slice: PropertySlice<'schema, 'record>,
        ) -> Result<T, ParserError>;
    }
}

macro_rules! impl_try_parse_primitive {
    ($T:ident) => {
        impl<'schema, 'record> private::TryParse<'schema, 'record, $T>
            for Parser<'schema, 'record>
        {
            fn try_parse_slice(
                &self,
                prop_slice: PropertySlice<'schema, 'record>,
            ) -> ParserResult<$T> {
                match prop_slice.property.info {
                    PropertyInfo::Value { .. } => {
                        // TODO: Check In and Out type and do a better type checking
                        if std::mem::size_of::<$T>() != prop_slice.buffer.len() {
                            return Err(ParserError::LengthMismatch);
                        }
                        Ok($T::from_ne_bytes(prop_slice.buffer.try_into()?))
                    },
                    _ => Err(ParserError::InvalidType),
                }
            }
        }
    };
}

macro_rules! impl_try_parse_primitive_array {
    ($T:ident) => {
        impl<'schema, 'record> private::TryParse<'schema, 'record, &'record [$T]>
            for Parser<'schema, 'record>
        {
            fn try_parse_slice(
                &self,
                prop_slice: PropertySlice<'schema, 'record>,
            ) -> ParserResult<&'record [$T]> {
                match prop_slice.property.info {
                    PropertyInfo::Array { .. } => {
                        // TODO: Check In and Out type and do a better type checking

                        // This property type has not been tested yet as I don't have a
                        // provider that uses it. It's possible that the buffer is not
                        // aligned correctly, which would cause this to fail.
                        let size = std::mem::size_of::<$T>();
                        let align = std::mem::align_of::<$T>();

                        if prop_slice.buffer.len() % size != 0 {
                            return Err(ParserError::LengthMismatch);
                        }

                        let count = prop_slice.buffer.len() / size;

                        if prop_slice.buffer.as_ptr() as usize % align != 0 {
                            return Err(ParserError::PropertyError(
                                "buffer alignment mismatch".into(),
                            ));
                        }

                        if size.checked_mul(count).is_none() || (size * count) > isize::MAX as usize
                        {
                            return Err(ParserError::PropertyError("size overflow".into()));
                        }

                        let slice = unsafe {
                            // The alignment of the buffer was checked above
                            #[allow(clippy::cast_ptr_alignment)]
                            std::slice::from_raw_parts(
                                prop_slice.buffer.as_ptr().cast::<$T>(),
                                count,
                            )
                        };

                        Ok(slice)
                    },
                    _ => Err(ParserError::InvalidType),
                }
            }
        }
    };
}

impl_try_parse_primitive!(u8);
impl_try_parse_primitive!(i8);
impl_try_parse_primitive!(u16);
impl_try_parse_primitive!(i16);
impl_try_parse_primitive!(u32);
impl_try_parse_primitive!(i32);
impl_try_parse_primitive!(u64);
impl_try_parse_primitive!(i64);
impl_try_parse_primitive!(f32);
impl_try_parse_primitive!(f64);

impl_try_parse_primitive_array!(u16);
impl_try_parse_primitive_array!(i16);
impl_try_parse_primitive_array!(u32);
impl_try_parse_primitive_array!(i32);
impl_try_parse_primitive_array!(u64);
impl_try_parse_primitive_array!(i64);

/// Decodes the payload of a count-prefixed string: `byte_count` bytes of
/// UTF-16 (`wide`) or ANSI data following the count
fn decode_counted_payload(buffer: &[u8], byte_count: usize, wide: bool) -> ParserResult<String> {
    let count_len = size_of::<u16>();
    let Some(data) = buffer.get(count_len..count_len + byte_count) else {
        return Err(ParserError::PropertyError(
            "invalid counted string length".into(),
        ));
    };

    if wide {
        // tdh.h sizes counted strings as "the number of additional bytes (not
        // characters)": a trailing odd byte is a truncated final code unit,
        // which is dropped here
        Ok(widestring::decode_utf16_lossy(
            data.chunks_exact(2)
                .map(|c| u16::from_le_bytes(c.try_into().unwrap())),
        )
        .collect())
    } else {
        Ok(std::str::from_utf8(data)?.to_string())
    }
}

/// Reads the 16-bit byte count that prefixes a counted string
fn read_count_prefix(buffer: &[u8], big_endian: bool) -> ParserResult<usize> {
    let Some(count_bytes) = buffer.get(..size_of::<u16>()) else {
        return Err(ParserError::PropertyError(
            "counted string does not have length".into(),
        ));
    };
    // Guaranteed by the slice length above
    let count_bytes = count_bytes.try_into().unwrap();
    Ok((if big_endian {
        u16::from_be_bytes(count_bytes)
    } else {
        u16::from_le_bytes(count_bytes)
    }) as usize)
}

/// Parses a count-prefixed string: a little-endian `u16` byte count followed by
/// the payload (UTF-16 code units when `wide`, bytes otherwise)
fn parse_counted_string(buffer: &[u8], wide: bool) -> ParserResult<String> {
    let byte_count = read_count_prefix(buffer, false)?;
    decode_counted_payload(buffer, byte_count, wide)
}

/// [`parse_counted_string`] for the deprecated WBEM in types whose count
/// prefix is big-endian (TDH_INTYPE_REVERSEDCOUNTEDSTRING /
/// REVERSEDCOUNTEDANSISTRING)
fn parse_reversed_counted_string(buffer: &[u8], wide: bool) -> ParserResult<String> {
    let byte_count = read_count_prefix(buffer, true)?;
    decode_counted_payload(buffer, byte_count, wide)
}

/// Parses a string with neither count prefix nor NUL terminator (deprecated
/// WBEM TDH_INTYPE_NONNULLTERMINATEDSTRING / NONNULLTERMINATEDANSISTRING):
/// tdh.h sizes the field as "the remaining bytes of data in the event", so
/// the whole property payload is the string
fn parse_non_null_terminated_string(buffer: &[u8], wide: bool) -> ParserResult<String> {
    if wide {
        // A trailing odd byte is a truncated final code unit, dropped like
        // for the counted strings
        Ok(widestring::decode_utf16_lossy(
            buffer
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes(c.try_into().unwrap())),
        )
        .collect())
    } else {
        Ok(std::str::from_utf8(buffer)?.to_string())
    }
}

/// The `String` impl of the `TryParse` trait should be used to retrieve the following [TdhInTypes]:
///
/// * InTypeUnicodeString
/// * InTypeAnsiString
/// * InTypeCountedString (+ its manifest and deprecated big-endian twins)
/// * InTypeCountedAnsiString (+ its manifest and deprecated big-endian twins)
/// * InTypeNonNullTerminatedString / InTypeNonNullTerminatedAnsiString
/// * the deprecated WBEM single-char twins (TDH_INTYPE_UNICODECHAR / ANSICHAR) and
///   TDH_INTYPE_WBEMSID
/// * InTypeGuid
///
/// On success a `String` with the with the data from the `name` property will be returned
///
/// # Arguments
/// * `name` - Name of the property to be found in the Schema
///
/// # Example
/// ```
/// # use ferrisetw::EventRecord;
/// # use ferrisetw::schema_locator::SchemaLocator;
/// # use ferrisetw::parser::Parser;
/// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
///     let schema = schema_locator.event_schema(record).unwrap();
///     let parser = Parser::create(record, &schema);
///     let image_name: String = parser.try_parse("ImageName").unwrap();
/// };
/// ```
///
/// [TdhInTypes]: TdhInType
impl<'schema, 'record> private::TryParse<'schema, 'record, String> for Parser<'schema, 'record> {
    fn try_parse_slice(&self, prop_slice: PropertySlice<'schema, 'record>) -> ParserResult<String> {
        match prop_slice.property.info {
            PropertyInfo::Value { in_type, .. } => match in_type {
                TdhInType::InTypeUnicodeString => {
                    if prop_slice.buffer.len() % 2 != 0 {
                        return Err(ParserError::PropertyError(
                            "odd length in bytes for a wide string".into(),
                        ));
                    }

                    // C semantics: the string ends at its first NUL. Top-level
                    // strings are sized up to that NUL, fixed-length structure
                    // members may be NUL-padded past it. The code units are
                    // read straight from the event buffer: the event buffer
                    // cannot be reinterpreted as an aligned &[u16], but
                    // decode_utf16_lossy consumes an iterator, so no copy is
                    // needed either
                    let code_units = prop_slice
                        .buffer
                        .chunks_exact(2)
                        .map(|chunk| u16::from_ne_bytes(chunk.try_into().unwrap()))
                        .take_while(|&unit| unit != 0);

                    // Decode UTF-16 to String
                    Ok(widestring::decode_utf16_lossy(code_units).collect::<String>())
                },
                TdhInType::InTypeAnsiString => {
                    let string = std::str::from_utf8(prop_slice.buffer)?;
                    Ok(string.trim_matches(char::default()).to_string())
                },
                TdhInType::InTypeSid | TdhInType::InTypeWbemSid => {
                    // ConvertSidToStringSidA takes no length: it reads
                    // 8 + 4 * SubAuthorityCount bytes, so anything shorter
                    // than the header advertises must be rejected before the
                    // Win32 read runs past the property bytes
                    let expected = prop_slice
                        .buffer
                        .get(1)
                        .map_or(usize::MAX, |c| 8 + 4 * usize::from(*c));
                    if prop_slice.buffer.len() < expected {
                        return Err(ParserError::PropertyError(
                            "SID property is truncated".into(),
                        ));
                    }
                    let string = sddl::convert_sid_to_string(prop_slice.buffer.as_ptr().cast())?;
                    Ok(string)
                },
                TdhInType::InTypeUnicodeChar => {
                    // Deprecated WBEM TDH_INTYPE_UNICODECHAR: one little-endian
                    // WCHAR, decoded as a one-character string
                    let unit = u16::from_le_bytes(prop_slice.buffer.try_into()?);
                    Ok(widestring::decode_utf16_lossy([unit]).collect())
                },
                TdhInType::InTypeAnsiChar => {
                    // Deprecated WBEM TDH_INTYPE_ANSICHAR: one CHAR byte, held
                    // to the same strict UTF-8 rule as the ANSI strings (a
                    // lone non-ASCII byte cannot be mapped without assuming a
                    // codepage)
                    let string = std::str::from_utf8(prop_slice.buffer)?;
                    Ok(string.to_owned())
                },
                TdhInType::InTypeManifestCountedString | TdhInType::InTypeCountedString => {
                    parse_counted_string(prop_slice.buffer, true)
                },
                TdhInType::InTypeManifestCountedAnsiString | TdhInType::InTypeCountedAnsiString => {
                    parse_counted_string(prop_slice.buffer, false)
                },
                TdhInType::InTypeReversedCountedString => {
                    parse_reversed_counted_string(prop_slice.buffer, true)
                },
                TdhInType::InTypeReversedCountedAnsiString => {
                    parse_reversed_counted_string(prop_slice.buffer, false)
                },
                TdhInType::InTypeNonNullTerminatedString => {
                    parse_non_null_terminated_string(prop_slice.buffer, true)
                },
                TdhInType::InTypeNonNullTerminatedAnsiString => {
                    parse_non_null_terminated_string(prop_slice.buffer, false)
                },
                _ => Err(ParserError::InvalidType),
            },
            PropertyInfo::Array { .. }
            | PropertyInfo::Struct { .. }
            | PropertyInfo::StructArray { .. }
            | PropertyInfo::Unsupported { .. } => Err(ParserError::InvalidType),
        }
    }
}

impl<'schema, 'record> private::TryParse<'schema, 'record, GUID> for Parser<'schema, 'record> {
    fn try_parse_slice(
        &self,
        prop_slice: PropertySlice<'schema, 'record>,
    ) -> Result<GUID, ParserError> {
        match prop_slice.property.info {
            PropertyInfo::Value { in_type, .. } => {
                if in_type != TdhInType::InTypeGuid {
                    return Err(ParserError::InvalidType);
                }

                if prop_slice.buffer.len() != 16 {
                    return Err(ParserError::LengthMismatch);
                }

                Ok(GUID {
                    // win:GUID is laid out in memory just like the GUID struct:
                    // Data1/2/3 are all little-endian
                    data1: u32::from_ne_bytes(prop_slice.buffer[0..4].try_into()?),
                    data2: u16::from_ne_bytes(prop_slice.buffer[4..6].try_into()?),
                    data3: u16::from_ne_bytes(prop_slice.buffer[6..8].try_into()?),
                    data4: prop_slice.buffer[8..].try_into()?,
                })
            },
            PropertyInfo::Array { .. }
            | PropertyInfo::Struct { .. }
            | PropertyInfo::StructArray { .. }
            | PropertyInfo::Unsupported { .. } => Err(ParserError::InvalidType),
        }
    }
}

impl<'schema, 'record> private::TryParse<'schema, 'record, IpAddr> for Parser<'schema, 'record> {
    fn try_parse_slice(&self, prop_slice: PropertySlice<'schema, 'record>) -> ParserResult<IpAddr> {
        match prop_slice.property.info {
            PropertyInfo::Value { out_type, .. } => {
                if out_type != TdhOutType::OutTypeIpv4 && out_type != TdhOutType::OutTypeIpv6 {
                    return Err(ParserError::InvalidType);
                }

                // Hardcoded values for now
                let res = match prop_slice.buffer.len() {
                    16 => {
                        let tmp: [u8; 16] = prop_slice.buffer.try_into()?;
                        IpAddr::V6(Ipv6Addr::from(tmp))
                    },
                    4 => {
                        let tmp: [u8; 4] = prop_slice.buffer.try_into()?;
                        IpAddr::V4(Ipv4Addr::from(tmp))
                    },
                    _ => return Err(ParserError::LengthMismatch),
                };

                Ok(res)
            },
            PropertyInfo::Array { .. }
            | PropertyInfo::Struct { .. }
            | PropertyInfo::StructArray { .. }
            | PropertyInfo::Unsupported { .. } => Err(ParserError::InvalidType),
        }
    }
}

impl<'schema, 'record> private::TryParse<'schema, 'record, bool> for Parser<'schema, 'record> {
    fn try_parse_slice(&self, prop_slice: PropertySlice<'schema, 'record>) -> ParserResult<bool> {
        match prop_slice.property.info {
            PropertyInfo::Value { in_type, .. } => {
                if in_type != TdhInType::InTypeBoolean {
                    return Err(ParserError::InvalidType);
                }

                match prop_slice.buffer.len() {
                    1 => Ok(prop_slice.buffer[0] != 0),
                    4 => Ok(u32::from_ne_bytes(prop_slice.buffer.try_into()?) != 0),
                    8 => Ok(u64::from_ne_bytes(prop_slice.buffer.try_into()?) != 0),
                    _ => Err(ParserError::LengthMismatch),
                }
            },
            PropertyInfo::Array { .. }
            | PropertyInfo::Struct { .. }
            | PropertyInfo::StructArray { .. }
            | PropertyInfo::Unsupported { .. } => Err(ParserError::InvalidType),
        }
    }
}

/// The `TdhSocketAddress` impl of the `TryParse` trait should be used to retrieve
/// a `win:SocketAddress` property (OutType = [`TdhOutType::OutTypeSocketAddress`])
///
/// # Example
/// ```
/// # use ferrisetw::EventRecord;
/// # use ferrisetw::parser::{Parser, TdhSocketAddress};
/// # use ferrisetw::schema_locator::SchemaLocator;
/// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
///     let schema = schema_locator.event_schema(record).unwrap();
///     let parser = Parser::create(record, &schema);
///     let addr: TdhSocketAddress = parser.try_parse("RemoteAddress").unwrap();
/// };
/// ```
impl<'schema, 'record> private::TryParse<'schema, 'record, TdhSocketAddress>
    for Parser<'schema, 'record>
{
    fn try_parse_slice(
        &self,
        prop_slice: PropertySlice<'schema, 'record>,
    ) -> ParserResult<TdhSocketAddress> {
        match prop_slice.property.info {
            PropertyInfo::Value { out_type, .. } => {
                if out_type != TdhOutType::OutTypeSocketAddress {
                    return Err(ParserError::InvalidType);
                }

                TdhSocketAddress::from_property_buffer(prop_slice.buffer)
            },
            PropertyInfo::Array { .. }
            | PropertyInfo::Struct { .. }
            | PropertyInfo::StructArray { .. }
            | PropertyInfo::Unsupported { .. } => Err(ParserError::InvalidType),
        }
    }
}

impl<'schema, 'record> private::TryParse<'schema, 'record, FileTime> for Parser<'schema, 'record> {
    fn try_parse_slice(
        &self,
        prop_slice: PropertySlice<'schema, 'record>,
    ) -> ParserResult<FileTime> {
        match prop_slice.property.info {
            PropertyInfo::Value { in_type, .. } => {
                if in_type != TdhInType::InTypeFileTime {
                    return Err(ParserError::InvalidType);
                }

                Ok(FileTime::from_slice(prop_slice.buffer.try_into()?))
            },
            PropertyInfo::Array { .. }
            | PropertyInfo::Struct { .. }
            | PropertyInfo::StructArray { .. }
            | PropertyInfo::Unsupported { .. } => Err(ParserError::InvalidType),
        }
    }
}

impl<'schema, 'record> private::TryParse<'schema, 'record, SystemTime>
    for Parser<'schema, 'record>
{
    fn try_parse_slice(
        &self,
        prop_slice: PropertySlice<'schema, 'record>,
    ) -> ParserResult<SystemTime> {
        match prop_slice.property.info {
            PropertyInfo::Value { in_type, .. } => {
                if in_type != TdhInType::InTypeSystemTime {
                    return Err(ParserError::InvalidType);
                }

                Ok(SystemTime::from_slice(prop_slice.buffer.try_into()?))
            },
            PropertyInfo::Array { .. }
            | PropertyInfo::Struct { .. }
            | PropertyInfo::StructArray { .. }
            | PropertyInfo::Unsupported { .. } => Err(ParserError::InvalidType),
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct Pointer(usize);

impl std::ops::Deref for Pointer {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Pointer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::fmt::LowerHex for Pointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val = self.0;

        std::fmt::LowerHex::fmt(&val, f) // delegate to u32/u64 implementation
    }
}

impl std::fmt::UpperHex for Pointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val = self.0;

        std::fmt::UpperHex::fmt(&val, f) // delegate to u32/u64 implementation
    }
}

impl std::fmt::Display for Pointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val = self.0;

        std::fmt::Display::fmt(&val, f) // delegate to u32/u64 implementation
    }
}

impl<'schema, 'record> private::TryParse<'schema, 'record, Pointer> for Parser<'schema, 'record> {
    fn try_parse_slice(
        &self,
        prop_slice: PropertySlice<'schema, 'record>,
    ) -> ParserResult<Pointer> {
        let mut res = Pointer::default();
        // Pointers wider than usize (i.e. on 16-bit targets) are truncated
        #[allow(clippy::cast_possible_truncation)]
        if prop_slice.buffer.len() == size_of::<u32>() {
            res.0 = private::TryParse::<'schema, 'record, u32>::try_parse_slice(self, prop_slice)?
                as usize;
        } else {
            res.0 = private::TryParse::<'schema, 'record, u64>::try_parse_slice(self, prop_slice)?
                as usize;
        }

        Ok(res)
    }
}

impl<'schema, 'record> private::TryParse<'schema, 'record, Vec<u8>> for Parser<'schema, 'record> {
    fn try_parse_slice(
        &self,
        prop_slice: PropertySlice<'schema, 'record>,
    ) -> Result<Vec<u8>, ParserError> {
        match prop_slice.property.info {
            // The property bytes include the leading count: the payload starts
            // after it
            PropertyInfo::Value {
                in_type: TdhInType::InTypeManifestCountedBinary,
                ..
            } => {
                // TDH_INTYPE_MANIFEST_COUNTEDBINARY: u16 byte count
                count_prefixed_binary(prop_slice.buffer, size_of::<u16>())
            },
            PropertyInfo::Value {
                in_type: TdhInType::InTypeHexDump,
                ..
            } => {
                // Deprecated WBEM TDH_INTYPE_HEXDUMP: u32 byte count
                count_prefixed_binary(prop_slice.buffer, size_of::<u32>())
            },
            _ => Ok(prop_slice.buffer.to_vec()),
        }
    }
}

/// Payload of a count-prefixed binary field: a `width`-byte little-endian byte
/// count followed by that many raw bytes
fn count_prefixed_binary(buffer: &[u8], width: usize) -> ParserResult<Vec<u8>> {
    let count_bytes = buffer.get(..width).ok_or(ParserError::PropertyError(
        "counted binary does not have length".into(),
    ))?;
    // Guaranteed by the slice length above
    let count = match width {
        2 => u16::from_le_bytes(count_bytes.try_into().unwrap()) as usize,
        _ => u32::from_le_bytes(count_bytes.try_into().unwrap()) as usize,
    };
    Ok(buffer
        .get(width..width + count)
        .ok_or(ParserError::PropertyError(
            "invalid counted binary length".into(),
        ))?
        .to_vec())
}

// TODO: Study if we can use primitive types for HexInt64, HexInt32 and Pointer

/// Synthetic `TRACE_EVENT_INFO` / `EVENT_RECORD` builders, shared by the
/// parser and serializer unit tests: they exercise the parsing logic without
/// a real ETW session (which would require administrator rights)
#[cfg(test)]
pub(crate) mod test_support {
    use std::alloc::Layout;

    use windows::Win32::System::Diagnostics::Etw;

    use super::*;
    use crate::{
        native::{tdh::TraceEventInfo, tdh_types::PropertyFlags},
        schema::Schema,
    };

    /// Description of one synthetic property of a schema
    pub(crate) struct PropSpec {
        pub(crate) name: &'static str,
        pub(crate) in_type: TdhInType,
        pub(crate) out_type: TdhOutType,
        /// `EVENT_PROPERTY_INFO.Flags` (e.g. `PropertyParamCount`)
        pub(crate) flags: u32,
        /// Value written to the count/countPropertyIndex union member
        pub(crate) count: u16,
        /// Value written to the length/lengthPropertyIndex union member
        pub(crate) length: u16,
        /// Members, when the property describes a structure
        pub(crate) structure: Option<&'static [PropSpec]>,
    }

    impl PropSpec {
        pub(crate) const fn new(name: &'static str, in_type: TdhInType, length: u16) -> Self {
            Self {
                name,
                in_type,
                out_type: TdhOutType::OutTypeNull,
                flags: 0,
                count: 0,
                length,
                structure: None,
            }
        }

        pub(crate) const fn with_out_type(mut self, out_type: TdhOutType) -> Self {
            self.out_type = out_type;
            self
        }

        /// A property the crate cannot decode (`PROPERTY_HAS_CUSTOM_SCHEMA`),
        /// of the given fixed length
        pub(crate) const fn custom_schema(name: &'static str, length: u16) -> Self {
            Self {
                flags: PropertyFlags::PROPERTY_HAS_CUSTOM_SCHEMA.bits(),
                ..Self::new(name, TdhInType::InTypeNull, length)
            }
        }

        /// A structure property with the given members
        pub(crate) const fn structure(name: &'static str, members: &'static [PropSpec]) -> Self {
            Self {
                flags: PropertyFlags::PROPERTY_STRUCT.bits(),
                structure: Some(members),
                ..Self::new(name, TdhInType::InTypeNull, 0)
            }
        }

        /// An array of structures whose element count is held by the property
        /// at `count_property_index` (PropertyParamCount, as in the .NET
        /// GCBulk events)
        pub(crate) const fn structure_array(
            name: &'static str,
            members: &'static [PropSpec],
            count_property_index: u16,
        ) -> Self {
            Self {
                flags: PropertyFlags::PROPERTY_STRUCT.bits()
                    | PropertyFlags::PROPERTY_PARAM_COUNT.bits(),
                count: count_property_index,
                ..Self::structure(name, members)
            }
        }
    }

    /// A flattened synthetic `EVENT_PROPERTY_INFO` entry
    struct RawProp {
        name: &'static str,
        flags: u32,
        in_type: TdhInType,
        out_type: TdhOutType,
        count: u16,
        length: u16,
        /// First member entry index, for structures
        member_start: u16,
        /// Number of member entries, for structures
        member_count: u16,
    }

    impl RawProp {
        fn scalar(spec: &PropSpec) -> Self {
            Self {
                name: spec.name,
                flags: spec.flags,
                in_type: spec.in_type,
                out_type: spec.out_type,
                count: spec.count,
                length: spec.length,
                member_start: 0,
                member_count: 0,
            }
        }
    }

    /// Flattens the spec tree the way TDH does: every level's direct entries
    /// first, then their members (each structure's member block stays
    /// contiguous, at the recorded start index)
    fn flatten_props(specs: &[PropSpec], entries: &mut Vec<RawProp>) {
        // Direct entries of this level, remembering where the structures are
        let mut structures = Vec::new();
        for spec in specs {
            let entry_index = entries.len();
            entries.push(RawProp::scalar(spec));
            if let Some(members) = spec.structure {
                structures.push((entry_index, members));
            }
        }
        for (entry_index, members) in structures {
            // Test property counts are tiny: they always fit a u16
            let start = u16::try_from(entries.len()).expect("property count fits u16");
            let entry = &mut entries[entry_index];
            entry.member_start = start;
            entry.member_count = u16::try_from(members.len()).expect("member count fits u16");
            flatten_props(members, entries);
        }
    }

    /// Builds a `Schema` wrapping a synthetic `TRACE_EVENT_INFO` describing `props`
    pub(crate) fn synthetic_schema(props: &[PropSpec]) -> Schema {
        let mut entries = Vec::new();
        flatten_props(props, &mut entries);

        let size_of_info = size_of::<Etw::TRACE_EVENT_INFO>();
        let size_of_prop = size_of::<Etw::EVENT_PROPERTY_INFO>();
        let mut names_size = 0;
        for prop in &entries {
            names_size += (prop.name.len() + 1) * 2; // utf-16 code units, NUL included
        }
        let size = size_of_info + entries.len().saturating_sub(1) * size_of_prop + names_size;
        let layout = Layout::from_size_align(size, align_of::<Etw::TRACE_EVENT_INFO>())
            .expect("valid layout");

        let buffer = unsafe {
            // Safety: size is non-zero (at least the size of a TRACE_EVENT_INFO fixed part)
            let buffer = std::alloc::alloc(layout);
            std::ptr::write_bytes(buffer, 0, size);
            buffer
        };

        let names_offset = u32::try_from(size - names_size).unwrap();
        unsafe {
            // The buffer is allocated with the alignment of TRACE_EVENT_INFO
            #[allow(clippy::cast_ptr_alignment)]
            let info = buffer.cast::<Etw::TRACE_EVENT_INFO>();
            (*info).PropertyCount = u32::try_from(entries.len()).unwrap();
            (*info).TopLevelPropertyCount = u32::try_from(props.len()).unwrap();

            let mut name_offset = names_offset;
            for (index, prop) in entries.iter().enumerate() {
                // Test flags are small bit patterns: they never wrap around
                #[allow(clippy::cast_possible_wrap)]
                let flags = Etw::PROPERTY_FLAGS(prop.flags as i32);
                let entry = (*info).EventPropertyInfoArray.as_mut_ptr().add(index);
                (*entry).Flags = flags;
                (*entry).NameOffset = name_offset;
                if prop.flags & PropertyFlags::PROPERTY_STRUCT.bits() != 0 {
                    (*entry).Anonymous1.structType.StructStartIndex = prop.member_start;
                    (*entry).Anonymous1.structType.NumOfStructMembers = prop.member_count;
                    // Aliases countPropertyIndex in the union
                    (*entry).Anonymous2.count = prop.count;
                } else {
                    (*entry).Anonymous1.nonStructType.InType = prop.in_type as u16;
                    (*entry).Anonymous1.nonStructType.OutType = prop.out_type as u16;
                    (*entry).Anonymous2.count = prop.count;
                    (*entry).Anonymous3.length = prop.length;
                }

                // Names are written unaligned, which the read side mirrors
                #[allow(clippy::cast_ptr_alignment)]
                let name = buffer.cast::<u16>().add(name_offset as usize / 2);
                for (i, unit) in prop
                    .name
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .enumerate()
                {
                    name.add(i).write_unaligned(unit);
                }
                name_offset += u32::try_from((prop.name.len() + 1) * 2).unwrap();
            }
        }

        Schema::new(TraceEventInfo::from_raw_parts(buffer, layout))
    }

    /// Builds an `EventRecord` whose user data is `user_data`
    pub(crate) fn synthetic_record(user_data: &[u8]) -> EventRecord {
        EventRecord(Etw::EVENT_RECORD {
            UserData: user_data.as_ptr() as *mut _,
            UserDataLength: u16::try_from(user_data.len()).unwrap(),
            ..Default::default()
        })
    }

    /// Builds the user data of a TraceLogging event: the two metadata blobs
    /// TDH expects (provider then event metadata), each with a `u16` size
    /// prefix, followed by the field values
    pub(crate) fn tlg_user_data(event_meta: &[u8], values: &[u8]) -> Vec<u8> {
        let sized = |payload: &[u8]| -> Vec<u8> {
            (u16::try_from(payload.len() + 2).unwrap())
                .to_le_bytes()
                .into_iter()
                .chain(payload.iter().copied())
                .collect()
        };

        let provider_name = b"ferrisETW.TraceLoggingTest";
        let mut provider = provider_name.to_vec();
        provider.push(0);

        let mut event_name = b"Event1".to_vec();
        event_name.push(0);
        event_name.extend_from_slice(event_meta);

        sized(&provider)
            .into_iter()
            .chain(sized(&event_name))
            .chain(values.iter().copied())
            .collect()
    }

    /// Decodes a synthetic TraceLogging event through the real
    /// `TdhGetEventInformation`, no ETW session or admin rights required:
    /// these events are self-describing, TDH reads the schema from the
    /// metadata embedded in the user data. Also returns the record, whose
    /// buffer must stay alive with the schema (for tests parsing or
    /// serializing the event)
    pub(crate) fn tlg_schema(user_data: &[u8]) -> (Schema, EventRecord) {
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
                ..Default::default()
            },
            UserData: user_data.as_ptr() as *mut _,
            UserDataLength: u16::try_from(user_data.len()).unwrap(),
            ..Default::default()
        });
        let info = TraceEventInfo::build_from_event(&record)
            .expect("TDH should decode the synthetic TraceLogging event");
        (Schema::new(info), record)
    }
}

#[cfg(test)]
mod tests {
    use windows::Win32::System::Diagnostics::Etw;

    use super::*;
    use crate::{
        native::{tdh::TraceEventInfo, tdh_types::PropertyFlags},
        parser::test_support::{PropSpec, synthetic_record, synthetic_schema},
    };

    #[test]
    fn parse_guid_property() {
        // A GUID as laid out in ETW user data: Data1/2/3 are all little-endian
        let user_data: [u8; 16] = [
            0x34, 0x12, 0x78, 0x56, // data1: 0x56781234
            0xcd, 0xab, // data2: 0xabcd
            0x09, 0x46, // data3: 0x4609
            1, 2, 3, 4, 5, 6, 7, 8, // data4
        ];
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&[PropSpec::new("guid_prop", TdhInType::InTypeGuid, 16)]);
        let parser = Parser::create(&record, &schema);

        let guid = parser
            .try_parse::<GUID>("guid_prop")
            .expect("GUID should parse");
        assert_eq!(
            guid,
            GUID::from_u128(0x56781234_abcd_4609_0102_030405060708)
        );
    }

    #[test]
    fn struct_properties_parse_as_nested_trees() {
        static NESTED_MEMBERS: [PropSpec; 1] =
            [PropSpec::new("inner_x", TdhInType::InTypeUInt32, 4)];
        static MEMBERS: [PropSpec; 3] = [
            PropSpec::new("x", TdhInType::InTypeUInt32, 4),
            PropSpec::structure("inner", &NESTED_MEMBERS),
            PropSpec::new("y", TdhInType::InTypeUInt16, 2),
        ];
        static PROPS: [PropSpec; 3] = [
            PropSpec::new("before", TdhInType::InTypeUInt32, 4),
            PropSpec::structure("s", &MEMBERS),
            PropSpec::new("after", TdhInType::InTypeUInt32, 4),
        ];
        let schema = synthetic_schema(&PROPS);

        let top = schema.properties();
        // Structures are yielded as single top-level properties: their members
        // must not leak into the top-level list
        assert_eq!(
            top.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            vec!["before", "s", "after"]
        );

        let PropertyInfo::Struct { members } = &top[1].info else {
            panic!("'s' should parse as a structure");
        };
        assert_eq!(
            members.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            vec!["x", "inner", "y"]
        );
        // Nested structures are trees, not flat lists
        let PropertyInfo::Struct {
            members: nested_members,
        } = &members[1].info
        else {
            panic!("'inner' should parse as a nested structure");
        };
        assert_eq!(nested_members.len(), 1);
        assert_eq!(nested_members[0].name, "inner_x");
        assert!(matches!(nested_members[0].info, PropertyInfo::Value { .. }));
    }

    #[test]
    fn struct_arrays_carry_their_element_count() {
        // Layout of the .NET GCBulk events: a count property followed by an
        // array of structures referencing it
        static MEMBERS: [PropSpec; 1] = [PropSpec::new("v", TdhInType::InTypeUInt32, 4)];
        static PROPS: [PropSpec; 2] = [
            PropSpec::new("Count", TdhInType::InTypeUInt32, 4),
            PropSpec::structure_array("Values", &MEMBERS, 0),
        ];
        let schema = synthetic_schema(&PROPS);

        let top = schema.properties();
        assert_eq!(top.len(), 2);
        let PropertyInfo::StructArray {
            members,
            count: PropertyCount::Index(index),
        } = &top[1].info
        else {
            panic!("'Values' should parse as a structure array");
        };
        assert_eq!(*index, 0);
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].name, "v");
    }

    #[test]
    fn parser_advances_correctly_with_duplicate_property_names() {
        // Manifests allow several properties with the same name
        let props = [
            PropSpec::new("dup", TdhInType::InTypeUInt32, 4),
            PropSpec::new("dup", TdhInType::InTypeUInt32, 4),
            PropSpec::new("third", TdhInType::InTypeUInt32, 4),
            PropSpec::new("fourth", TdhInType::InTypeUInt32, 4),
        ];
        let user_data: [u8; 16] = [
            1, 0, 0, 0, // dup
            2, 0, 0, 0, // dup
            3, 0, 0, 0, // third
            4, 0, 0, 0, // fourth
        ];
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&props);
        let parser = Parser::create(&record, &schema);

        // "third" requires parsing through both "dup" properties
        assert_eq!(parser.try_parse::<u32>("third").unwrap(), 3);

        // The cache must remember that 3 properties were parsed (not just the
        // 2 distinct names), otherwise "fourth" would be looked up at the wrong
        // buffer offset
        assert_eq!(parser.try_parse::<u32>("fourth").unwrap(), 4);

        // An absent property must be reported as NotFound, not as a spurious
        // out-of-bounds error caused by re-parsing consumed properties
        assert!(matches!(
            parser.try_parse::<u32>("missing"),
            Err(ParserError::NotFound)
        ));
    }

    #[test]
    fn property_bytes_at_tells_same_named_properties_apart() {
        // Manifests allow several properties with the same name: the
        // positional accessor must yield each one's own bytes, where a
        // name-based lookup would return the first match for all of them
        let props = [
            PropSpec::new("dup", TdhInType::InTypeUInt32, 4),
            PropSpec::new("b", TdhInType::InTypeUInt32, 4),
            PropSpec::new("dup", TdhInType::InTypeUInt32, 4),
        ];
        let user_data: [u8; 12] = [
            1, 0, 0, 0, // dup #1
            2, 0, 0, 0, // b
            3, 0, 0, 0, // dup #2
        ];
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&props);
        let parser = Parser::create(&record, &schema);

        for (index, expected) in [1u32, 2, 3].into_iter().enumerate() {
            let bytes = parser.property_bytes_at(index).unwrap();
            assert_eq!(u32::from_ne_bytes(bytes.try_into().unwrap()), expected);
        }

        // Beyond the schema there is nothing left to parse
        assert!(matches!(
            parser.property_bytes_at(3),
            Err(ParserError::NotFound)
        ));
    }

    #[test]
    fn custom_schema_property_keeps_the_rest_locatable() {
        // A property the crate cannot decode used to discard the whole
        // property list: it must stay in place (it occupies its bytes) so
        // the surrounding properties keep their buffer offsets
        let props = [
            PropSpec::new("before", TdhInType::InTypeUInt32, 4),
            PropSpec::custom_schema("custom", 8),
            PropSpec::new("after", TdhInType::InTypeUInt32, 4),
        ];
        let mut user_data = 1u32.to_ne_bytes().to_vec();
        user_data.resize(12, 0xaa); // the opaque custom-schema payload
        user_data.extend_from_slice(&2u32.to_ne_bytes());
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&props);

        let top = schema.properties();
        assert_eq!(
            top.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            vec!["before", "custom", "after"]
        );
        assert!(matches!(&top[1].info, PropertyInfo::Unsupported {
            length: PropertyLength::Length(8),
        }));

        let parser = Parser::create(&record, &schema);
        assert_eq!(parser.try_parse::<u32>("before").unwrap(), 1);
        // The walk crosses the 8 custom-schema bytes to reach "after"
        assert_eq!(parser.try_parse::<u32>("after").unwrap(), 2);
        // The unsupported property itself does not decode
        assert!(matches!(
            parser.try_parse::<u32>("custom"),
            Err(ParserError::InvalidType)
        ));
    }

    /// tdh.h: for fixed-size in types "the length property of the
    /// EVENT_PROPERTY_INFO structure can be ignored by decoders" — a
    /// WBEM/MOF schema that leaves it at 0 must size the property from the
    /// in type instead of asking TDH (which fails outright on these
    /// synthetic records, as it used to)
    #[test]
    fn scalars_without_schema_length_fall_back_to_the_in_type_size() {
        let user_data: Vec<u8> = 1u32
            .to_ne_bytes()
            .into_iter()
            .chain(2u64.to_ne_bytes())
            .collect();
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&[
            PropSpec::new("a", TdhInType::InTypeUInt32, 0),
            PropSpec::new("b", TdhInType::InTypeUInt64, 0),
        ]);
        let parser = Parser::create(&record, &schema);

        assert_eq!(parser.try_parse::<u32>("a").unwrap(), 1);
        assert_eq!(parser.try_parse::<u64>("b").unwrap(), 2);
    }

    /// tdh.h: with `PropertyParamLength`, `lengthPropertyIndex` points at the
    /// property holding the field size, in the same unit as a literal length
    /// (WCHARs for UnicodeString). Resolving it against the already parsed
    /// prefix keeps the walk local: TdhGetPropertySize fails outright on
    /// these synthetic records, so any fallback would fail the test
    #[test]
    fn length_by_reference_resolves_from_the_parsed_prefix() {
        static PROPS: [PropSpec; 3] = [
            PropSpec::new("len", TdhInType::InTypeUInt16, 2),
            PropSpec {
                flags: PropertyFlags::PROPERTY_PARAM_LENGTH.bits(),
                length: 0, // aliases lengthPropertyIndex
                ..PropSpec::new("s", TdhInType::InTypeUnicodeString, 0)
            },
            PropSpec::new("n", TdhInType::InTypeUInt32, 4),
        ];
        let mut user_data: Vec<u8> = 3u16.to_ne_bytes().to_vec();
        user_data.extend(b"abc".iter().flat_map(|b| [*b, 0]));
        user_data.extend_from_slice(&0x1122_3344u32.to_ne_bytes());
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&PROPS);
        let parser = Parser::create(&record, &schema);

        // 3 WCHARs, not 3 bytes: the u32 sits right after the 6 string bytes
        assert_eq!(parser.try_parse::<String>("s").unwrap(), "abc");
        assert_eq!(parser.try_parse::<u32>("n").unwrap(), 0x1122_3344);
    }

    /// tdh.h: with `PropertyParamCount`, `countPropertyIndex` points at the
    /// property holding the element count, which the walk resolves from the
    /// parsed prefix
    #[test]
    fn count_by_reference_resolves_from_the_parsed_prefix() {
        static PROPS: [PropSpec; 3] = [
            PropSpec::new("count", TdhInType::InTypeUInt16, 2),
            PropSpec {
                count: 0, // aliases countPropertyIndex
                flags: PropertyFlags::PROPERTY_PARAM_COUNT.bits(),
                ..PropSpec::new("arr", TdhInType::InTypeUInt32, 4)
            },
            PropSpec::new("n", TdhInType::InTypeUInt32, 4),
        ];
        let user_data: Vec<u8> = 2u16
            .to_ne_bytes()
            .into_iter()
            .chain(7u32.to_ne_bytes())
            .chain(9u32.to_ne_bytes())
            .chain(0x1122_3344u32.to_ne_bytes())
            .collect();
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&PROPS);
        let parser = Parser::create(&record, &schema);

        // Both array elements lie before the u32: the count resolved to 2
        assert_eq!(parser.property_bytes_at(1).unwrap().len(), 8);
        assert_eq!(parser.try_parse::<u32>("n").unwrap(), 0x1122_3344);
    }

    /// The GCBulk-style layout: a structure array whose element count travels
    /// by reference, sized as (fixed members) x (resolved count)
    #[test]
    fn struct_array_count_by_reference_resolves_from_the_parsed_prefix() {
        static MEMBERS: [PropSpec; 1] = [PropSpec::new("v", TdhInType::InTypeUInt32, 4)];
        static PROPS: [PropSpec; 3] = [
            PropSpec::new("count", TdhInType::InTypeUInt16, 2),
            PropSpec::structure_array("items", &MEMBERS, 0),
            PropSpec::new("n", TdhInType::InTypeUInt32, 4),
        ];
        let user_data: Vec<u8> = 2u16
            .to_ne_bytes()
            .into_iter()
            .chain(0x33u32.to_ne_bytes())
            .chain(0x44u32.to_ne_bytes())
            .chain(0x1122_3344u32.to_ne_bytes())
            .collect();
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&PROPS);
        let parser = Parser::create(&record, &schema);

        assert_eq!(parser.property_bytes_at(1).unwrap().len(), 8);
        assert_eq!(parser.try_parse::<u32>("n").unwrap(), 0x1122_3344);
    }

    /// A reference the parsed prefix cannot resolve (a forward reference
    /// here) defers to TDH — which fails outright on synthetic records,
    /// pinning that no local guess is made in its place
    #[test]
    fn unresolvable_references_still_defer_to_tdh() {
        static PROPS: [PropSpec; 2] = [
            PropSpec {
                count: 1, // countPropertyIndex: the count comes AFTER the array
                flags: PropertyFlags::PROPERTY_PARAM_COUNT.bits(),
                ..PropSpec::new("arr", TdhInType::InTypeUInt32, 4)
            },
            PropSpec::new("count", TdhInType::InTypeUInt16, 2),
        ];
        let user_data: Vec<u8> = 7u32
            .to_ne_bytes()
            .into_iter()
            .chain(2u16.to_ne_bytes())
            .collect();
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&PROPS);
        let parser = Parser::create(&record, &schema);

        assert!(matches!(
            parser.try_parse::<u32>("arr"),
            Err(ParserError::TdhNativeError(_))
        ));
    }

    /// A carrier value so large that the unit conversion overflows must defer
    /// to TDH (which fails on synthetic records) instead of wrapping the size
    /// around: a wrapped size would silently misalign every following property
    #[test]
    fn overflowing_length_reference_defers_to_tdh() {
        static PROPS: [PropSpec; 2] =
            [PropSpec::new("len", TdhInType::InTypeUInt64, 8), PropSpec {
                flags: PropertyFlags::PROPERTY_PARAM_LENGTH.bits(),
                length: 0, // aliases lengthPropertyIndex
                ..PropSpec::new("s", TdhInType::InTypeUnicodeString, 0)
            }];
        // len * 2 wraps around to 0 on a 64-bit usize
        let record = synthetic_record(&0x8000_0000_0000_0000u64.to_ne_bytes());
        let schema = synthetic_schema(&PROPS);
        let parser = Parser::create(&record, &schema);

        assert!(matches!(
            parser.try_parse::<String>("s"),
            Err(ParserError::TdhNativeError(_))
        ));
    }

    /// Same contract for an array whose element count travels by reference:
    /// the element-size-by-count product must not wrap around
    #[test]
    fn overflowing_count_reference_defers_to_tdh() {
        static PROPS: [PropSpec; 2] = [
            PropSpec::new("count", TdhInType::InTypeUInt64, 8),
            PropSpec {
                count: 0, // aliases countPropertyIndex
                flags: PropertyFlags::PROPERTY_PARAM_COUNT.bits(),
                ..PropSpec::new("arr", TdhInType::InTypeUInt64, 8)
            },
        ];
        // 8 * u64::MAX overflows the usize total
        let record = synthetic_record(&u64::MAX.to_ne_bytes());
        let schema = synthetic_schema(&PROPS);
        let parser = Parser::create(&record, &schema);

        assert!(matches!(
            parser.property_bytes_at(1),
            Err(ParserError::TdhNativeError(_))
        ));
    }

    /// Same contract for a GCBulk-style structure array whose element count
    /// travels by reference
    #[test]
    fn overflowing_struct_array_count_defers_to_tdh() {
        static MEMBERS: [PropSpec; 1] = [PropSpec::new("v", TdhInType::InTypeUInt64, 8)];
        static PROPS: [PropSpec; 2] = [
            PropSpec::new("count", TdhInType::InTypeUInt64, 8),
            PropSpec::structure_array("items", &MEMBERS, 0),
        ];
        // 8 (member size) * u64::MAX overflows the usize total
        let record = synthetic_record(&u64::MAX.to_ne_bytes());
        let schema = synthetic_schema(&PROPS);
        let parser = Parser::create(&record, &schema);

        assert!(matches!(
            parser.property_bytes_at(1),
            Err(ParserError::TdhNativeError(_))
        ));
    }

    /// tdh.h: the counted families determine their size from their count
    /// prefix, and their length property "must be ignored": a declared
    /// length (only a malformed WBEM/MOF schema can carry one) must not
    /// desync the walk from the content size
    #[test]
    fn counted_string_ignores_the_declared_length() {
        static PROPS: [PropSpec; 2] = [
            PropSpec::new("cs", TdhInType::InTypeCountedString, 4),
            PropSpec::new("n", TdhInType::InTypeUInt32, 4),
        ];
        // Prefix says 6 payload bytes ("abc" in UTF-16), the schema says 4
        let mut user_data: Vec<u8> = 6u16.to_ne_bytes().to_vec();
        user_data.extend(b"abc".iter().flat_map(|b| [*b, 0]));
        user_data.extend_from_slice(&0x1122_3344u32.to_ne_bytes());
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&PROPS);
        let parser = Parser::create(&record, &schema);

        // The walk consumed the 2-byte prefix + 6 payload bytes: the u32
        // behind them stays aligned
        assert_eq!(parser.try_parse::<String>("cs").unwrap(), "abc");
        assert_eq!(parser.try_parse::<u32>("n").unwrap(), 0x1122_3344);
    }

    /// Same tdh.h rule for SID fields: the size comes from the header (8 +
    /// 4 bytes per sub-authority), a declared length must not shrink the
    /// walk and misalign the following property
    #[test]
    fn sid_ignores_the_declared_length() {
        static PROPS: [PropSpec; 2] = [
            PropSpec::new("sid", TdhInType::InTypeSid, 16),
            PropSpec::new("n", TdhInType::InTypeUInt32, 4),
        ];
        // S-1-5-21-100-200-300: revision, 4 sub-authorities, 24 bytes —
        // the schema claims 16
        let sid = [
            0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x64, 0x00,
            0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x2c, 0x01, 0x00, 0x00,
        ];
        let mut user_data = sid.to_vec();
        user_data.extend_from_slice(&0x1122_3344u32.to_ne_bytes());
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&PROPS);
        let parser = Parser::create(&record, &schema);

        assert_eq!(
            parser.try_parse::<String>("sid").unwrap(),
            "S-1-5-21-100-200-300"
        );
        assert_eq!(parser.try_parse::<u32>("n").unwrap(), 0x1122_3344);
    }

    /// A SID slice shorter than its header claims must be rejected before
    /// `ConvertSidToStringSidA` reads past it. The walk sizes content-defined
    /// fields from their bytes, so this guard covers slices carved out
    /// elsewhere, e.g. array elements with a declared stride
    #[test]
    fn sid_slice_shorter_than_its_header_is_rejected() {
        let record = synthetic_record(&[]);
        let schema = synthetic_schema(&[PropSpec::new("sid", TdhInType::InTypeSid, 0)]);
        let parser = Parser::create(&record, &schema);

        // The header claims 2 sub-authorities (16 bytes), only 8 are present
        let bytes = [0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
        assert!(matches!(
            parser.try_parse_member::<String>(&schema.properties()[0], &bytes),
            Err(ParserError::PropertyError(_))
        ));
    }

    #[test]
    fn cached_properties_are_found_out_of_order() {
        // Parsing "c" first has to walk through "a" and "b"; asking for them
        // afterwards must hit the cache (a re-parse would consume the buffer
        // again and return the values of the wrong properties)
        let props = [
            PropSpec::new("a", TdhInType::InTypeUInt32, 4),
            PropSpec::new("b", TdhInType::InTypeUInt32, 4),
            PropSpec::new("c", TdhInType::InTypeUInt32, 4),
        ];
        let user_data: [u8; 12] = [
            1, 0, 0, 0, // a
            2, 0, 0, 0, // b
            3, 0, 0, 0, // c
        ];
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&props);
        let parser = Parser::create(&record, &schema);

        assert_eq!(parser.try_parse::<u32>("c").unwrap(), 3);
        assert_eq!(parser.try_parse::<u32>("a").unwrap(), 1);
        assert_eq!(parser.try_parse::<u32>("b").unwrap(), 2);
        // Repeated accesses are served from the cache as well
        assert_eq!(parser.try_parse::<u32>("c").unwrap(), 3);
        assert_eq!(parser.try_parse::<u32>("a").unwrap(), 1);
    }

    #[test]
    fn unterminated_strings_are_an_error() {
        // AnsiString without a NUL terminator: reporting the whole remaining
        // buffer as the property size would corrupt the parsing of everything
        // that follows
        let user_data = b"no terminator".to_vec();
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&[PropSpec::new("s", TdhInType::InTypeAnsiString, 0)]);
        let parser = Parser::create(&record, &schema);
        assert!(parser.try_parse::<String>("s").is_err());

        // Same for UnicodeString (wide NUL = 2 null bytes)
        let user_data = vec![0x68u8, 0, 0x69, 0]; // "hi" without the wide terminator
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&[PropSpec::new("w", TdhInType::InTypeUnicodeString, 0)]);
        let parser = Parser::create(&record, &schema);
        assert!(parser.try_parse::<String>("w").is_err());
    }

    #[test]
    fn terminated_strings_parse_and_advance_the_offset() {
        let user_data: Vec<u8> = Vec::from("ab\0")
            .into_iter()
            .chain(0x1122_3344u32.to_ne_bytes())
            .collect();
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&[
            PropSpec::new("s", TdhInType::InTypeAnsiString, 0),
            PropSpec::new("n", TdhInType::InTypeUInt32, 4),
        ]);
        let parser = Parser::create(&record, &schema);

        assert_eq!(parser.try_parse::<String>("s").unwrap(), "ab");
        // The u32 sits right after the 3-byte string: this verifies the string
        // size computation (NUL included)
        assert_eq!(parser.try_parse::<u32>("n").unwrap(), 0x1122_3344);
    }

    #[test]
    fn counted_strings_parse_and_advance_the_offset() {
        // Layout: little-endian u16 BYTE count, then the payload
        let wide: Vec<u8> = "hï".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let ansi = b"hi".to_vec();

        // The WBEM (300+) and manifest (22/23) variants share the same layout
        let cases = [
            (
                TdhInType::InTypeManifestCountedString,
                wide.as_slice(),
                "hï",
            ),
            (TdhInType::InTypeCountedString, wide.as_slice(), "hï"),
            (
                TdhInType::InTypeManifestCountedAnsiString,
                ansi.as_slice(),
                "hi",
            ),
            (TdhInType::InTypeCountedAnsiString, ansi.as_slice(), "hi"),
        ];

        for (in_type, payload, expected) in cases {
            let user_data: Vec<u8> = u16::try_from(payload.len())
                .unwrap()
                .to_le_bytes()
                .into_iter()
                .chain(payload.iter().copied())
                .chain(0x1122_3344u32.to_ne_bytes())
                .collect();

            let record = synthetic_record(&user_data);
            let schema = synthetic_schema(&[
                PropSpec::new("s", in_type, u16::try_from(2 + payload.len()).unwrap()),
                PropSpec::new("n", TdhInType::InTypeUInt32, 4),
            ]);
            let parser = Parser::create(&record, &schema);

            assert_eq!(parser.try_parse::<String>("s").unwrap(), expected);
            // The u32 sits right after the counted string: this verifies the
            // property size computation
            assert_eq!(parser.try_parse::<u32>("n").unwrap(), 0x1122_3344);
        }
    }

    #[test]
    fn counted_strings_with_invalid_length_are_an_error() {
        // The byte count exceeds what the buffer holds
        let user_data = 42u16.to_le_bytes();
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&[PropSpec::new("s", TdhInType::InTypeCountedString, 2)]);
        let parser = Parser::create(&record, &schema);
        assert!(parser.try_parse::<String>("s").is_err());
    }

    /// The deprecated WBEM string twins: 302/303 prefix their payload with a
    /// big-endian byte count, 304/305 span the whole remaining buffer with
    /// neither count nor NUL terminator
    ///
    /// The real TDH cannot validate these: TraceLogging event metadata only
    /// carries in-type values 0..=31 (TlgIn_t in TraceLoggingProvider.h), far
    /// below the 300-series, so these stay byte-level tests against the
    /// documented layouts
    #[test]
    fn deprecated_wbem_string_types_parse_and_advance_the_offset() {
        let wide: Vec<u8> = "hï".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let ansi = b"hi".to_vec();

        // 302/303: big-endian count prefix, then the payload
        let counted_cases = [
            (
                TdhInType::InTypeReversedCountedString,
                wide.as_slice(),
                "hï",
            ),
            (
                TdhInType::InTypeReversedCountedAnsiString,
                ansi.as_slice(),
                "hi",
            ),
        ];
        for (in_type, payload, expected) in counted_cases {
            let user_data: Vec<u8> = u16::try_from(payload.len())
                .unwrap()
                .to_be_bytes()
                .into_iter()
                .chain(payload.iter().copied())
                .chain(0x1122_3344u32.to_ne_bytes())
                .collect();
            let record = synthetic_record(&user_data);
            let schema = synthetic_schema(&[
                PropSpec::new("s", in_type, u16::try_from(2 + payload.len()).unwrap()),
                PropSpec::new("n", TdhInType::InTypeUInt32, 4),
            ]);
            let parser = Parser::create(&record, &schema);

            assert_eq!(parser.try_parse::<String>("s").unwrap(), expected);
            // The u32 sits right after the counted string: this verifies the
            // property size computation
            assert_eq!(parser.try_parse::<u32>("n").unwrap(), 0x1122_3344);
        }

        // 304/305: the field is the whole remaining buffer (zero schema
        // length exercises that sizing), so it must come last
        let unterminated_cases = [
            (
                TdhInType::InTypeNonNullTerminatedString,
                wide.as_slice(),
                "hï",
            ),
            (
                TdhInType::InTypeNonNullTerminatedAnsiString,
                ansi.as_slice(),
                "hi",
            ),
        ];
        for (in_type, payload, expected) in unterminated_cases {
            let record = synthetic_record(payload);
            let schema = synthetic_schema(&[PropSpec::new("s", in_type, 0)]);
            let parser = Parser::create(&record, &schema);
            assert_eq!(parser.try_parse::<String>("s").unwrap(), expected);
        }

        // 303: the big-endian count is read as such — 0x0002 as a
        // little-endian count would claim 512 bytes and fail
        let user_data: Vec<u8> = 2u16
            .to_be_bytes()
            .into_iter()
            .chain(b"hi".iter().copied())
            .collect();
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&[PropSpec::new(
            "s",
            TdhInType::InTypeReversedCountedAnsiString,
            4,
        )]);
        let parser = Parser::create(&record, &schema);
        assert_eq!(parser.try_parse::<String>("s").unwrap(), "hi");
    }

    /// The deprecated WBEM UNICODECHAR (306) / ANSICHAR (307) twins: a
    /// single WCHAR/CHAR decoded as a one-character string, occupying
    /// exactly its fixed size (2/1 bytes)
    #[test]
    fn deprecated_wbem_single_char_types_parse_and_advance_the_offset() {
        // UNICODECHAR: one little-endian WCHAR ('é', a lone surrogate would
        // degrade through the lossy decode)
        let user_data: Vec<u8> = 0x00e9u16
            .to_le_bytes()
            .into_iter()
            .chain(0x1122_3344u32.to_ne_bytes())
            .collect();
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&[
            PropSpec::new("c", TdhInType::InTypeUnicodeChar, 0),
            PropSpec::new("n", TdhInType::InTypeUInt32, 4),
        ]);
        let parser = Parser::create(&record, &schema);
        assert_eq!(parser.try_parse::<String>("c").unwrap(), "é");
        assert_eq!(parser.try_parse::<u32>("n").unwrap(), 0x1122_3344);

        // ANSICHAR: one CHAR byte
        let user_data: Vec<u8> = b"A"
            .to_vec()
            .into_iter()
            .chain(0x1122_3344u32.to_ne_bytes())
            .collect();
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&[
            PropSpec::new("c", TdhInType::InTypeAnsiChar, 0),
            PropSpec::new("n", TdhInType::InTypeUInt32, 4),
        ]);
        let parser = Parser::create(&record, &schema);
        assert_eq!(parser.try_parse::<String>("c").unwrap(), "A");
        assert_eq!(parser.try_parse::<u32>("n").unwrap(), 0x1122_3344);
    }

    /// The deprecated WBEM SIZET (308) / HEXDUMP (309) / WBEMSID (310)
    /// values: layouts and sizing follow tdh.h (which TDH cannot confirm on
    /// synthetic records — TraceLogging metadata only carries in types
    /// 0..=31), so the u32 marker after each property verifies the sizing
    #[test]
    fn deprecated_wbem_sizet_hexdump_wbemsid_parse_and_advance_the_offset() {
        // SIZET: sized from the header flags like a pointer (8 bytes here)
        let user_data: Vec<u8> = 0x1122_3344_5566_7788u64
            .to_ne_bytes()
            .into_iter()
            .chain(0x1122_3344u32.to_ne_bytes())
            .collect();
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&[
            PropSpec::new("sz", TdhInType::InTypeSizeT, 0),
            PropSpec::new("n", TdhInType::InTypeUInt32, 4),
        ]);
        let parser = Parser::create(&record, &schema);
        assert_eq!(
            *parser.try_parse::<Pointer>("sz").unwrap(),
            0x1122_3344_5566_7788
        );
        assert_eq!(parser.try_parse::<u32>("n").unwrap(), 0x1122_3344);

        // HEXDUMP: little-endian u32 byte count, then the payload
        let user_data: Vec<u8> = 3u32
            .to_le_bytes()
            .into_iter()
            .chain([0xaa, 0xbb, 0xcc])
            .chain(0x1122_3344u32.to_ne_bytes())
            .collect();
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&[
            PropSpec::new("dump", TdhInType::InTypeHexDump, 0),
            PropSpec::new("n", TdhInType::InTypeUInt32, 4),
        ]);
        let parser = Parser::create(&record, &schema);
        assert_eq!(parser.try_parse::<Vec<u8>>("dump").unwrap(), vec![
            0xaa, 0xbb, 0xcc
        ]);
        assert_eq!(parser.try_parse::<u32>("n").unwrap(), 0x1122_3344);

        // WBEMSID: the SID S-1-5-20 as it sits in an event (revision,
        // sub-authority count, 6-byte identifier authority, one relative
        // ID), rendered through the same SDDL conversion as InTypeSid
        let user_data: Vec<u8> = [1u8, 1, 0, 0, 0, 0, 0, 5, 20, 0, 0, 0]
            .into_iter()
            .chain(0x1122_3344u32.to_ne_bytes())
            .collect();
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&[
            PropSpec::new("sid", TdhInType::InTypeWbemSid, 0),
            PropSpec::new("n", TdhInType::InTypeUInt32, 4),
        ]);
        let parser = Parser::create(&record, &schema);
        assert_eq!(parser.try_parse::<String>("sid").unwrap(), "S-1-5-20");
        assert_eq!(parser.try_parse::<u32>("n").unwrap(), 0x1122_3344);
    }

    #[test]
    fn manifest_counted_binary_parses_and_advances_the_offset() {
        // TDH_INTYPE_MANIFEST_COUNTEDBINARY: little-endian u16 byte count,
        // then the raw payload (the count prefix is not part of the value)
        let user_data: Vec<u8> = 3u16
            .to_le_bytes()
            .into_iter()
            .chain([0xaa, 0xbb, 0xcc])
            .chain(0x1122_3344u32.to_ne_bytes())
            .collect();
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&[
            PropSpec::new("blob", TdhInType::InTypeManifestCountedBinary, 0),
            PropSpec::new("n", TdhInType::InTypeUInt32, 4),
        ]);
        let parser = Parser::create(&record, &schema);

        assert_eq!(parser.try_parse::<Vec<u8>>("blob").unwrap(), vec![
            0xaa, 0xbb, 0xcc
        ]);
        // The u32 sits right after the counted binary: this verifies the
        // property size computation
        assert_eq!(parser.try_parse::<u32>("n").unwrap(), 0x1122_3344);
    }

    #[test]
    fn manifest_counted_binary_with_invalid_length_is_an_error() {
        // The byte count exceeds what the buffer holds
        let user_data = 42u16.to_le_bytes();
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&[PropSpec::new(
            "blob",
            TdhInType::InTypeManifestCountedBinary,
            2,
        )]);
        let parser = Parser::create(&record, &schema);
        assert!(parser.try_parse::<Vec<u8>>("blob").is_err());
    }

    #[test]
    fn socket_address_property_decodes_and_advances_the_offset() {
        // sockaddr_in (AF_INET, port 80, 127.0.0.1) padded to 16 bytes
        let mut sockaddr: Vec<u8> = Vec::new();
        sockaddr.extend_from_slice(&2u16.to_ne_bytes());
        sockaddr.extend_from_slice(&80u16.to_be_bytes());
        sockaddr.extend_from_slice(&[127, 0, 0, 1]);
        sockaddr.resize(16, 0);

        let user_data: Vec<u8> = sockaddr
            .into_iter()
            .chain(0x1122_3344u32.to_ne_bytes())
            .collect();
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&[
            PropSpec::new("addr", TdhInType::InTypeBinary, 16)
                .with_out_type(TdhOutType::OutTypeSocketAddress),
            PropSpec::new("n", TdhInType::InTypeUInt32, 4),
        ]);
        let parser = Parser::create(&record, &schema);

        let addr = parser
            .try_parse::<TdhSocketAddress>("addr")
            .expect("socket address should parse");
        assert_eq!(addr.to_string(), "127.0.0.1:80");
        // The u32 sits right after the 16-byte sockaddr
        assert_eq!(parser.try_parse::<u32>("n").unwrap(), 0x1122_3344);

        // A property without the SocketAddress out type is not a socket address
        let schema = synthetic_schema(&[PropSpec::new("addr", TdhInType::InTypeBinary, 16)]);
        let parser = Parser::create(&record, &schema);
        assert!(matches!(
            parser.try_parse::<TdhSocketAddress>("addr"),
            Err(ParserError::InvalidType)
        ));
    }

    // ---- TraceLogging (self-describing) events decoded through the real TDH ----

    /// TraceLogging in/out type codes, as encoded in the event metadata
    /// (values differ from the TDH enums for out types, e.g. Win32Error is 13 here)
    mod tlg {
        pub const IN_STR: u8 = 1;
        pub const IN_U16: u8 = 6;
        pub const IN_I32: u8 = 7;
        pub const IN_U32: u8 = 8;
        pub const IN_U64: u8 = 10;
        pub const IN_GUID: u8 = 15;
        pub const IN_BINARY: u8 = 14;
        pub const IN_FILETIME: u8 = 17;
        pub const IN_HEX64: u8 = 21;
        pub const IN_STR16: u8 = 22;
        pub const IN_STR8: u8 = 23;

        pub const OUT_HEX: u8 = 4;
        pub const OUT_SOCKADDR: u8 = 10;
        pub const OUT_WIN32ERROR: u8 = 13;
        pub const OUT_NTSTATUS: u8 = 14;
        pub const OUT_HRESULT: u8 = 15;
        pub const OUT_UTF8: u8 = 35;
        pub const OUT_CODEPOINTER: u8 = 37;
        pub const OUT_DATETIMEUTC: u8 = 38;
    }

    /// One field of a synthetic TraceLogging event: its metadata descriptor
    /// (NUL-terminated name, in type, optional out type with bit 0x80 set on
    /// the in type), its value bytes, and the TDH types it must decode to
    struct TlgField {
        name: &'static str,
        in_type: u8,
        out_type: Option<u8>,
        value: &'static [u8],
        expected: (TdhInType, TdhOutType),
    }

    /// The metadata descriptor of a [`TlgField`]: NUL-terminated name, then
    /// the in type with bit 0x80 set when an out type byte follows
    fn tlg_field_meta(field: &TlgField) -> Vec<u8> {
        let mut meta = field.name.as_bytes().to_vec();
        meta.push(0);
        meta.push(field.in_type | u8::from(field.out_type.is_some()) << 7);
        meta.extend(field.out_type);
        meta
    }

    // ---- TraceLogging metadata location: embedded in the user data vs extended data ----

    /// A synthetic TraceLogging event with its metadata embedded at the start
    /// of the user data ([`tlg_user_data`] layout), decoded through the real
    /// `TdhGetEventInformation`
    fn tlg_record_and_schema(user_data: &[u8]) -> (EventRecord, Schema) {
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
                ..Default::default()
            },
            UserData: user_data.as_ptr() as *mut _,
            UserDataLength: u16::try_from(user_data.len()).unwrap(),
            ..Default::default()
        });
        let info = TraceEventInfo::build_from_event(&record)
            .expect("TDH should decode the synthetic TraceLogging event");
        (record, Schema::new(info))
    }

    /// N32 (u32) then Str8 (counted ANSI string) field descriptors, and their
    /// values, as laid out by TraceLogging
    fn tlg_n32_str8() -> (Vec<u8>, Vec<u8>) {
        let mut meta = b"N32\0".to_vec();
        meta.push(tlg::IN_U32);
        meta.extend_from_slice(b"Str8\0");
        meta.push(tlg::IN_STR8 | 0x80);
        meta.push(tlg::OUT_UTF8);

        let mut values: Vec<u8> = 0x1122_3344u32.to_le_bytes().to_vec();
        values.extend_from_slice(&[2, 0, b'h', b'i']); // counted ansi "hi"
        (meta, values)
    }

    #[test]
    fn embedded_tlg_metadata_is_rejected_instead_of_misread() {
        use crate::parser::test_support::tlg_user_data;
        // The layout of raw TraceLogging descriptors: the metadata blobs sit
        // at the start of the user data. TDH decodes the schema but reads
        // property offsets from the buffer start, so the metadata bytes would
        // be silently reported as property values; parsing must fail loudly
        // instead
        let (meta, values) = tlg_n32_str8();
        let user_data = tlg_user_data(&meta, &values);
        let (record, schema) = tlg_record_and_schema(&user_data);

        assert!(
            matches!(schema.decoding_source(), DecodingSource::DecodingSourceTlg),
            "TDH must recognize the event as TraceLogging for the detection to apply"
        );

        let parser = Parser::create(&record, &schema);
        let err = parser
            .try_parse::<u32>("N32")
            .expect_err("the embedded metadata layout must not be parsed");
        assert!(
            matches!(err, ParserError::PropertyError(ref msg) if msg.contains("inline TraceLogging")),
            "unexpected error: {err}"
        );
        assert!(parser.property_bytes_at(0).is_err());
    }

    #[test]
    fn extended_data_tlg_metadata_parses_from_the_buffer_start() {
        // The layout of real-time sessions and ETL replays: the metadata
        // travels in extended data items and the user data holds the values
        // only. This must keep parsing (no false positive from the embedded
        // layout detection above)
        let mut meta = b"Port\0".to_vec();
        meta.push(tlg::IN_U16);
        let (record, schema) = tlg_ext_record(&meta, &[80, 0]);

        assert!(matches!(
            schema.decoding_source(),
            DecodingSource::DecodingSourceTlg
        ));

        let parser = Parser::create(&record, &schema);
        assert_eq!(parser.try_parse::<u16>("Port").unwrap(), 80);
    }

    /// Builds a TraceLogging event whose metadata travels in extended data
    /// items (how real-time sessions and ETL replays deliver it) and whose
    /// user data holds the property values only, decoded through the real
    /// `TdhGetEventInformation`: `meta` is the event metadata (field
    /// descriptors), `values` the property values
    fn tlg_ext_record(meta: &[u8], values: &[u8]) -> (EventRecord, Schema) {
        let sized = |payload: &[u8]| -> Vec<u8> {
            (u16::try_from(payload.len() + 2).unwrap())
                .to_le_bytes()
                .into_iter()
                .chain(payload.iter().copied())
                .collect()
        };
        let mut event_meta = Vec::new();
        event_meta.push(0u8); // tags
        event_meta.extend_from_slice(b"Event1\0");
        event_meta.extend_from_slice(meta);
        let event_blob = sized(&event_meta);
        let mut provider_blob = b"ferrisETW.TraceLoggingTest\0".to_vec();
        provider_blob.push(0);
        let provider_blob = sized(&provider_blob);

        // Test data uses known-small ext type constants
        #[allow(clippy::cast_possible_truncation)]
        let ext_items = Box::new([
            Etw::EVENT_HEADER_EXTENDED_DATA_ITEM {
                ExtType: Etw::EVENT_HEADER_EXT_TYPE_PROV_TRAITS as u16,
                DataSize: u16::try_from(provider_blob.len()).unwrap(),
                DataPtr: provider_blob.as_ptr() as u64,
                ..Default::default()
            },
            Etw::EVENT_HEADER_EXTENDED_DATA_ITEM {
                ExtType: Etw::EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL as u16,
                DataSize: u16::try_from(event_blob.len()).unwrap(),
                DataPtr: event_blob.as_ptr() as u64,
                ..Default::default()
            },
        ]);
        // The EVENT_RECORD keeps raw pointers to the blobs and the item
        // array: leak them so they outlive the event (a drop while TDH or
        // the parser still reads them made the tests flaky)
        let ext_items: &'static mut [Etw::EVENT_HEADER_EXTENDED_DATA_ITEM] = Box::leak(ext_items);
        // The DataPtr fields above point into the blobs: the leaked bindings
        // only keep the memory alive
        let _provider_blob: &'static [u8] = Box::leak(provider_blob.into_boxed_slice());
        let _event_blob: &'static [u8] = Box::leak(event_blob.into_boxed_slice());
        // Header size always fits: synthetic test data
        #[allow(clippy::cast_possible_truncation)]
        let header_size = size_of::<Etw::EVENT_HEADER>() as u16;
        let record = EventRecord(Etw::EVENT_RECORD {
            EventHeader: Etw::EVENT_HEADER {
                Size: header_size,
                Flags: 0x0002,
                EventDescriptor: Etw::EVENT_DESCRIPTOR {
                    Channel: 11,
                    ..Default::default()
                },
                ..Default::default()
            },
            ExtendedDataCount: 2,
            ExtendedData: ext_items.as_mut_ptr(),
            UserData: values.as_ptr() as *mut _,
            UserDataLength: u16::try_from(values.len()).unwrap(),
            ..Default::default()
        });
        let info = TraceEventInfo::build_from_event(&record)
            .expect("TDH should decode the extended-data TraceLogging event");
        (record, Schema::new(info))
    }

    /// Empirical pin for the InTypeUnicodeString length semantics: on a
    /// TraceLogging event TDH reports the NUL-terminated wide string with a
    /// zero schema length and sizes it by scanning for the NUL (6 bytes for
    /// "hï" plus terminator) — the explicit-length branch below is only
    /// reachable through manifest/WBEM schemas
    #[test]
    fn tracelogging_terminated_wide_string_has_no_schema_length() {
        let mut meta = b"S\0".to_vec();
        meta.push(tlg::IN_STR);
        let mut values: Vec<u8> = "hï".encode_utf16().flat_map(u16::to_le_bytes).collect();
        values.extend_from_slice(&[0, 0]); // wide NUL terminator

        let (record, schema) = tlg_ext_record(&meta, &values);
        let prop = schema
            .properties()
            .iter()
            .find(|p| p.name == "S")
            .expect("TDH should report the field");
        let PropertyInfo::Value { length, .. } = &prop.info else {
            panic!("'S' should be a scalar value");
        };
        assert_eq!(*length, PropertyLength::Length(0));
        assert_eq!(
            tdh::property_size(&record, prop).unwrap(),
            6,
            "TDH must size the string up to and including its NUL"
        );

        let parser = Parser::create(&record, &schema);
        assert_eq!(parser.try_parse::<String>("S").unwrap(), "hï");
    }

    /// Empirical pin for a wide counted string with an ODD byte count: the
    /// real TDH consumes count+2 bytes without rounding up to a whole number
    /// of code units, so the crate's identical sizing keeps the properties
    /// that follow aligned. The dangling half code unit only shows up in the
    /// decoded value, which drops it (see `decode_counted_payload`)
    #[test]
    fn tracelogging_counted_string_odd_byte_count_sizes_as_count_plus_prefix() {
        let mut meta = b"S16\0".to_vec();
        meta.push(tlg::IN_STR16);
        // count = 5 bytes: "a\0b\0c" — the trailing 'c' low byte is a
        // truncated final code unit
        let mut values: Vec<u8> = 5u16.to_le_bytes().to_vec();
        values.extend_from_slice(b"a\0b\0c");
        values.extend_from_slice(&0x1122_3344u32.to_le_bytes());

        let (record, schema) = tlg_ext_record(&meta, &values);
        let prop = schema
            .properties()
            .iter()
            .find(|p| p.name == "S16")
            .expect("TDH should report the field");
        assert_eq!(
            tdh::property_size(&record, prop).unwrap(),
            7,
            "TDH must take the odd count at face value"
        );

        let parser = Parser::create(&record, &schema);
        assert_eq!(parser.try_parse::<String>("S16").unwrap(), "ab");
    }

    /// Pin for the local count/length-by-reference resolution against the
    /// real TDH: a TraceLogging binary field's size travels in a synthesized
    /// ".Length" property declared ahead of it, and TDH sizes the field
    /// itself to the payload only (the u16 prefix belongs to the synthesized
    /// property). The local walk must read the same bytes
    #[test]
    fn tracelogging_binary_field_sizes_from_its_synthesized_length() {
        let mut meta = b"Blob\0".to_vec();
        meta.push(tlg::IN_BINARY);
        let mut values: Vec<u8> = 3u16.to_le_bytes().to_vec();
        values.extend_from_slice(&[0xaa, 0xbb, 0xcc]);

        let (record, schema) = tlg_ext_record(&meta, &values);
        let props = schema.properties();
        assert_eq!(
            props.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            vec!["Blob.Length", "Blob"],
            "TDH must synthesize the length property ahead of the field"
        );
        // Ground truth: the field itself is the payload only
        assert_eq!(tdh::property_size(&record, &props[1]).unwrap(), 3);

        // The local walk: 2 bytes of synthesized length, then the payload
        let parser = Parser::create(&record, &schema);
        assert_eq!(parser.property_bytes_at(0).unwrap().len(), 2);
        assert_eq!(parser.property_bytes_at(1).unwrap(), &[0xaa, 0xbb, 0xcc]);
    }

    /// Pin for the local resolution against the real TDH: a TraceLogging
    /// Vcount array's element count travels in a synthesized ".Count"
    /// property, and TDH sizes the array to elements x count (the count
    /// prefix belongs to the synthesized property)
    #[test]
    fn tracelogging_counted_array_sizes_from_its_synthesized_count() {
        let mut meta = b"Items\0".to_vec();
        meta.push(6 | 0x40); // UInt16 with Vcount: the count is serialized with the data
        let mut values: Vec<u8> = 2u16.to_le_bytes().to_vec();
        values.extend_from_slice(&[7, 0, 9, 0]);

        let (record, schema) = tlg_ext_record(&meta, &values);
        let props = schema.properties();
        let array_index = props
            .iter()
            .position(|p| p.name == "Items")
            .expect("TDH should report the array");
        assert_eq!(
            tdh::property_size(&record, &props[array_index]).unwrap(),
            4,
            "TDH must size the array to its elements only"
        );

        // The local walk resolves the same count from the parsed prefix
        let parser = Parser::create(&record, &schema);
        assert_eq!(parser.property_bytes_at(array_index).unwrap().len(), 4);
    }

    /// An explicit schema length for a UnicodeString counts WCHARs, not
    /// bytes (tdh.h: "the epi.length field contains number of WCHARs in the
    /// string"; eventman.xsd: "Length indicates the size (in characters)"):
    /// sizing it as bytes would steal half the field and shift everything
    /// that follows
    #[test]
    fn fixed_length_unicode_string_counts_wchars_not_bytes() {
        // "abc" exactly fills the 3 WCHARs; a NUL-padded member stops at
        // its first NUL but still spans the full 6 bytes
        for (payload, expected) in [(b"abc", "abc"), (b"ab\0", "ab")] {
            let mut user_data: Vec<u8> = payload.iter().flat_map(|b| [*b, 0]).collect();
            user_data.extend_from_slice(&0x1122_3344u32.to_ne_bytes());
            let record = synthetic_record(&user_data);
            let schema = synthetic_schema(&[
                PropSpec::new("s", TdhInType::InTypeUnicodeString, 3),
                PropSpec::new("n", TdhInType::InTypeUInt32, 4),
            ]);
            let parser = Parser::create(&record, &schema);

            assert_eq!(parser.try_parse::<String>("s").unwrap(), expected);
            // The u32 sits right after the 6 string bytes: this verifies the
            // property size computation
            assert_eq!(parser.try_parse::<u32>("n").unwrap(), 0x1122_3344);
        }
    }

    /// A fixed-length wide member with no NUL at all decodes up to its whole
    /// length (the terminator is optional within a fixed-size field)
    #[test]
    fn fixed_length_unicode_string_without_nul_decodes_to_its_full_length() {
        let mut user_data: Vec<u8> = "ab".encode_utf16().flat_map(u16::to_le_bytes).collect();
        user_data.extend_from_slice(&0x1122_3344u32.to_ne_bytes());
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&[
            PropSpec::new("s", TdhInType::InTypeUnicodeString, 2),
            PropSpec::new("n", TdhInType::InTypeUInt32, 4),
        ]);
        let parser = Parser::create(&record, &schema);

        assert_eq!(parser.try_parse::<String>("s").unwrap(), "ab");
        assert_eq!(parser.try_parse::<u32>("n").unwrap(), 0x1122_3344);
    }

    /// Array elements follow the same WCHAR-counting rule: length 3 with
    /// count 2 spans 12 bytes
    #[test]
    fn fixed_length_unicode_string_array_occupies_wchars_times_elements() {
        let mut user_data: Vec<u8> = "abcdef".encode_utf16().flat_map(u16::to_le_bytes).collect();
        user_data.extend_from_slice(&0x1122_3344u32.to_ne_bytes());
        let record = synthetic_record(&user_data);
        let schema = synthetic_schema(&[
            PropSpec {
                count: 2,
                ..PropSpec::new("s", TdhInType::InTypeUnicodeString, 3)
            },
            PropSpec::new("n", TdhInType::InTypeUInt32, 4),
        ]);
        assert!(matches!(schema.properties()[0].info, PropertyInfo::Array {
            count: PropertyCount::Count(2),
            ..
        }));

        // The array property itself does not decode as a String; the point
        // is that the u32 lands after the whole 12-byte array
        let parser = Parser::create(&record, &schema);
        assert!(matches!(
            parser.try_parse::<String>("s"),
            Err(ParserError::InvalidType)
        ));
        assert_eq!(parser.try_parse::<u32>("n").unwrap(), 0x1122_3344);
    }

    /// Pins down how TDH maps TraceLogging metadata to its own in/out types:
    /// this is the ground truth the parser and the serializer rely on
    /// (e.g. `str8` only becomes readable through the counted-Ansi in type)
    #[test]
    fn tracelogging_types_decode_through_tdh() {
        use tlg::*;

        use crate::parser::test_support::{tlg_schema, tlg_user_data};

        let cases = [
            TlgField {
                name: "Str8",
                in_type: IN_STR8,
                out_type: Some(OUT_UTF8),
                value: &[9, 0],
                expected: (TdhInType::InTypeCountedAnsiString, TdhOutType::OutTypeUtf8),
            },
            TlgField {
                name: "Str16",
                in_type: IN_STR16,
                out_type: None,
                value: &[4, 0],
                expected: (TdhInType::InTypeCountedString, TdhOutType::OutTypeNull),
            },
            TlgField {
                name: "Win32Error",
                in_type: IN_U32,
                out_type: Some(OUT_WIN32ERROR),
                value: &[5, 0, 0, 0],
                expected: (TdhInType::InTypeUInt32, TdhOutType::OutTypeWin32Error),
            },
            TlgField {
                name: "NtStatus",
                in_type: IN_U32,
                out_type: Some(OUT_NTSTATUS),
                value: &[0; 4],
                expected: (TdhInType::InTypeUInt32, TdhOutType::OutTypeNtStatus),
            },
            TlgField {
                name: "HResult",
                in_type: IN_I32,
                out_type: Some(OUT_HRESULT),
                value: &[5, 0, 7, 128], // 0x80070005
                expected: (TdhInType::InTypeInt32, TdhOutType::OutTypeHResult),
            },
            TlgField {
                name: "CodePointer",
                in_type: IN_HEX64,
                out_type: Some(OUT_CODEPOINTER),
                value: &[0; 8],
                expected: (TdhInType::InTypeHexInt64, TdhOutType::OutTypeCodePointer),
            },
            TlgField {
                name: "HexU32",
                in_type: IN_U32,
                out_type: Some(OUT_HEX),
                value: &[0x78, 0x56, 0x34, 0x12],
                expected: (TdhInType::InTypeUInt32, TdhOutType::OutTypeHexInt32),
            },
            TlgField {
                name: "DateTimeUtc",
                in_type: IN_FILETIME,
                out_type: Some(OUT_DATETIMEUTC),
                value: &[0; 8],
                expected: (TdhInType::InTypeFileTime, TdhOutType::OutTypeDatetimeUtc),
            },
            TlgField {
                name: "SockAddr",
                in_type: IN_BINARY,
                out_type: Some(OUT_SOCKADDR),
                value: &[16, 0],
                expected: (TdhInType::InTypeBinary, TdhOutType::OutTypeSocketAddress),
            },
            TlgField {
                name: "Port",
                in_type: IN_U16,
                out_type: None,
                value: &[80, 0],
                expected: (TdhInType::InTypeUInt16, TdhOutType::OutTypeNull),
            },
        ];

        let meta: Vec<u8> = cases.iter().flat_map(tlg_field_meta).collect();
        let values: Vec<u8> = cases.iter().flat_map(|f| f.value.iter().copied()).collect();

        let user_data = tlg_user_data(&meta, &values);
        let (schema, _record) = tlg_schema(&user_data);
        // TDH synthesizes extra properties (e.g. a "FieldName.Length"
        // companion for TraceLogging binary fields): match by name
        let props = schema.properties();

        for case in &cases {
            // Only the type mapping is pinned down: the reported length
            // varies (fixed sizes, 0 for counted strings, an index into a
            // synthesized count property for TraceLogging binary fields)
            let prop = props
                .iter()
                .find(|p| p.name == case.name)
                .expect("TDH should report the field");
            let PropertyInfo::Value {
                in_type: actual_in,
                out_type: actual_out,
                ..
            } = &prop.info
            else {
                panic!("{} should decode as a scalar value", case.name);
            };
            assert_eq!((*actual_in, *actual_out), case.expected);
        }
    }

    /// Pins down how TDH reports a TraceLogging array whose element count
    /// travels with the data (Vcount): TDH synthesizes a count property and
    /// makes the array's countPropertyIndex point at it. That index is the
    /// ground truth the serializer's structure-array count resolution is
    /// aligned with
    #[test]
    fn tracelogging_array_count_index_points_at_the_synthesized_count() {
        // metadata: "Items\0" + inType UINT16|Vcount (0x40: the element
        // count is serialized with the data)
        use crate::parser::test_support::{tlg_schema, tlg_user_data};

        let mut meta = b"Items\0".to_vec();
        meta.push(6 | 0x40);
        let values = 3u16.to_le_bytes().to_vec();
        let user_data = tlg_user_data(&meta, &values);
        let (schema, _record) = tlg_schema(&user_data);

        let props = schema.properties();
        assert_eq!(
            props.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            vec!["Items.Count", "Items"]
        );
        let PropertyInfo::Array {
            count: PropertyCount::Index(index),
            ..
        } = &props[1].info
        else {
            panic!("'Items' should be a counted array, got {:?}", props[1].info);
        };
        assert_eq!(*index, 0);
    }

    /// Empirical pin backing the fixed-size fallback: TraceLogging field
    /// metadata carries no length at all, and the real TDH still synthesizes
    /// exactly the fixed size of each scalar in type
    #[test]
    fn tracelogging_scalar_lengths_follow_the_in_type() {
        let mut meta: Vec<u8> = Vec::new();
        for (name, in_type) in [
            ("U16", tlg::IN_U16),
            ("U32", tlg::IN_U32),
            ("U64", tlg::IN_U64),
            ("FT", tlg::IN_FILETIME),
            ("G", tlg::IN_GUID),
        ] {
            meta.extend_from_slice(name.as_bytes());
            meta.push(0);
            meta.push(in_type);
        }
        let mut values: Vec<u8> = 1u16.to_le_bytes().to_vec();
        values.extend_from_slice(&2u32.to_le_bytes());
        values.extend_from_slice(&3u64.to_le_bytes());
        values.extend_from_slice(&[0; 8]); // filetime
        values.extend_from_slice(&[0; 16]); // guid

        let (_record, schema) = tlg_ext_record(&meta, &values);

        for (name, length) in [("U16", 2), ("U32", 4), ("U64", 8), ("FT", 8), ("G", 16)] {
            let prop = schema
                .properties()
                .iter()
                .find(|p| p.name == name)
                .unwrap_or_else(|| panic!("TDH should report {name}"));
            let PropertyInfo::Value {
                length: reported, ..
            } = &prop.info
            else {
                panic!("{name} should be a scalar value");
            };
            assert_eq!(*reported, PropertyLength::Length(length));
        }
    }
}
