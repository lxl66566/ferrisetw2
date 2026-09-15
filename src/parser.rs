//! ETW Types Parser
//!
//! This module act as a helper to parse the Buffer from an ETW Event

use std::{
    convert::TryInto,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Mutex,
};

use windows::core::GUID;

use crate::{
    native::{
        etw_types::event_record::EventRecord,
        sddl, tdh,
        tdh_types::{Property, PropertyCount, PropertyInfo, PropertyLength, TdhInType, TdhOutType},
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
}

/// Represents a Parser
///
/// This structure provides a way to parse an ETW event (= extract its properties).
/// Because properties may have variable length (e.g. strings), a `Parser` is only suited to a
/// single [`EventRecord`]
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
    cache: Mutex<CachedSlices<'schema, 'record>>,
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
            cache: Mutex::new(CachedSlices::default()),
        }
    }

    #[allow(clippy::len_zero)]
    fn find_property_size(
        &self,
        property: &Property,
        remaining_user_buffer: &[u8],
    ) -> ParserResult<usize> {
        match property.info {
            PropertyInfo::Value {
                in_type, length, ..
            } => {
                // There are several cases
                //  * regular case, where property.len() directly makes sense
                //  * but EVENT_PROPERTY_INFO.length is an union, and (in its lengthPropertyIndex
                //    form) can refeer to another field e.g.: the WinInet provider manifest has
                //    fields such as `<data name="Verb" inType="win:AnsiString"
                //    length="_VerbLength"/>` In this case, we defer to TDH to know the right
                //    length.

                // For pointer input type we can immediately infer the size based on the header
                // flags.
                if in_type == TdhInType::InTypePointer {
                    return Ok(self.record.pointer_size());
                }

                let prop_len = match length {
                    PropertyLength::Length(l) => l,
                    PropertyLength::Index(_) => {
                        // TODO optimize to cache the lookup, the problem is here this is called
                        // under an exclusive mutex, so attempting to
                        // extract and cache a related property will
                        // deadlock.
                        return Ok(tdh::property_size(self.record, &property.name)? as usize);
                    },
                };

                if prop_len > 0 {
                    return Ok(prop_len as usize);
                }

                // Length is not set. We'll have to ask TDH for the right length.
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
                    | TdhInType::InTypeCountedAnsiString => {
                        // All counted string variants share the same layout:
                        // a little-endian u16 byte count then the payload
                        // (TraceLogging events leave the TDH length at 0, and
                        // TdhGetPropertySize is a costly round-trip)
                        let Some(count) = remaining_user_buffer.get(..size_of::<u16>()) else {
                            return Err(ParserError::PropertyError(
                                "counted string does not have length".into(),
                            ));
                        };
                        // Guaranteed by the slice length above
                        let byte_count = u16::from_le_bytes(count.try_into().unwrap()) as usize;
                        return Ok(size_of::<u16>() + byte_count);
                    },
                    _ => (),
                }

                Ok(tdh::property_size(self.record, &property.name)? as usize)
            },
            PropertyInfo::Array {
                in_type,
                length,
                count,
                ..
            } => {
                // For pointer input type we can immediately infer the size based on the header
                // flags.
                let prop_len = if in_type == TdhInType::InTypePointer {
                    self.record.pointer_size()
                } else {
                    match length {
                        PropertyLength::Length(l) => l as usize,
                        PropertyLength::Index(_) => {
                            // TODO optimize to cache the lookup, the problem is here this is called
                            // under an exclusive mutex, so attempting
                            // to extract and cache a related property will
                            // deadlock.
                            return Ok(tdh::property_size(self.record, &property.name)? as usize);
                        },
                    }
                };

                let prop_count = match count {
                    PropertyCount::Count(c) => c as usize,
                    PropertyCount::Index(_) => {
                        // TODO optimize to cache the lookup, the problem is here this is called
                        // under an exclusive mutex, so attempting to
                        // extract and cache a related property will
                        // deadlock.
                        return Ok(tdh::property_size(self.record, &property.name)? as usize);
                    },
                };

                if prop_len > 0 {
                    return Ok(prop_len * prop_count);
                }

                Ok(tdh::property_size(self.record, &property.name)? as usize)
            },
        }
    }

    fn find_property(&self, name: &str) -> ParserResult<PropertySlice<'schema, 'record>> {
        let mut cache = self.cache.lock().unwrap();

        // We may have extracted this property already: probe right after the
        // last hit first, as successive accesses usually advance in schema order
        for i in 0..cache.slices.len() {
            let idx = (cache.next_probe + i) % cache.slices.len();
            if cache.slices[idx].property.name == name {
                cache.next_probe = (idx + 1) % cache.slices.len();
                return Ok(cache.slices[idx]);
            }
        }

        // If we've parsed every property already, that means no property matches this name
        let Some(properties_not_parsed_yet) = self.properties.get(cache.slices.len()..) else {
            return Err(ParserError::NotFound);
        };

        for property in properties_not_parsed_yet {
            let Some(remaining_user_buffer) =
                self.record.user_buffer().get(cache.last_cached_offset..)
            else {
                return Err(ParserError::PropertyError(
                    "Invalid buffer bounds".to_owned(),
                ));
            };

            let prop_size = self.find_property_size(property, remaining_user_buffer)?;
            let Some(property_buffer) = remaining_user_buffer.get(..prop_size) else {
                return Err(ParserError::PropertyError(
                    "Property length out of buffer bounds".to_owned(),
                ));
            };

            let prop_slice = PropertySlice {
                property,
                buffer: property_buffer,
            };
            cache.slices.push(prop_slice);
            cache.last_cached_offset += prop_size;

            if property.name == name {
                return Ok(prop_slice);
            }
        }

        Err(ParserError::NotFound)
    }

    /// Return a property from the event, or an error in case the parsing failed.
    ///
    /// You must explicitly define `T`, the type you want to parse the property into.<br/>
    /// In case this type is not compatible with the ETW type, [`ParserError::InvalidType`] is
    /// returned.
    pub fn try_parse<T>(&self, name: &str) -> ParserResult<T>
    where
        Parser<'schema, 'record>: private::TryParse<T>,
    {
        use crate::parser::private::TryParse;
        self.try_parse_impl(name)
    }
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
    pub trait TryParse<T> {
        /// Implement the `try_parse` function to provide a way to Parse `T` from an ETW event or
        /// return an Error in case the type `T` can't be parsed
        ///
        /// # Arguments
        /// * `name` - Name of the property to be found in the Schema
        fn try_parse_impl(&self, name: &str) -> Result<T, ParserError>;
    }
}

macro_rules! impl_try_parse_primitive {
    ($T:ident) => {
        impl private::TryParse<$T> for Parser<'_, '_> {
            fn try_parse_impl(&self, name: &str) -> ParserResult<$T> {
                let prop_slice = self.find_property(name)?;

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
        impl<'schema, 'record> private::TryParse<&'record [$T]> for Parser<'schema, 'record> {
            fn try_parse_impl(&self, name: &str) -> ParserResult<&'record [$T]> {
                let prop_slice = self.find_property(name)?;

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

/// Parses a count-prefixed string: a little-endian `u16` byte count followed by
/// the payload (UTF-16 code units when `wide`, bytes otherwise)
fn parse_counted_string(buffer: &[u8], wide: bool) -> ParserResult<String> {
    const COUNT_LEN: usize = size_of::<u16>();
    let Some(count_bytes) = buffer.get(..COUNT_LEN) else {
        return Err(ParserError::PropertyError(
            "counted string does not have length".into(),
        ));
    };
    // Guaranteed by the slice length above
    let byte_count = u16::from_le_bytes(count_bytes.try_into().unwrap()) as usize;
    let Some(data) = buffer.get(COUNT_LEN..COUNT_LEN + byte_count) else {
        return Err(ParserError::PropertyError(
            "invalid counted string length".into(),
        ));
    };

    if wide {
        Ok(widestring::decode_utf16_lossy(
            data.chunks_exact(2)
                .map(|c| u16::from_le_bytes(c.try_into().unwrap())),
        )
        .collect())
    } else {
        Ok(std::str::from_utf8(data)?.to_string())
    }
}

/// The `String` impl of the `TryParse` trait should be used to retrieve the following [TdhInTypes]:
///
/// * InTypeUnicodeString
/// * InTypeAnsiString
/// * InTypeCountedString (+ its manifest twin)
/// * InTypeCountedAnsiString (+ its manifest twin)
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
impl private::TryParse<String> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<String> {
        let prop_slice = self.find_property(name)?;

        match prop_slice.property.info {
            PropertyInfo::Value { in_type, .. } => match in_type {
                TdhInType::InTypeUnicodeString => {
                    if prop_slice.buffer.len() % 2 != 0 {
                        return Err(ParserError::PropertyError(
                            "odd length in bytes for a wide string".into(),
                        ));
                    }

                    // std::slice::from_raw_parts requires a pointer to be aligned, but we can't
                    // guarantee that the buffer is aligned. In testing, I found that the buffer
                    // is in fact never aligned appropriately, so a cheap workaround is to copy
                    // the buffer into a new Vec<u16> and use that as the source for the slice
                    // until we can find a better solution.
                    let mut aligned_buffer = Vec::with_capacity(prop_slice.buffer.len() / 2);
                    for chunk in prop_slice.buffer.chunks_exact(2) {
                        aligned_buffer.push(u16::from_ne_bytes(chunk.try_into().unwrap()));
                    }

                    let mut wide = aligned_buffer.as_slice();

                    match wide.last() {
                        // remove the null terminator from the slice
                        Some(c) if c == &0 => wide = &wide[..wide.len() - 1],
                        _ => (),
                    }

                    // Decode UTF-16 to String
                    Ok(widestring::decode_utf16_lossy(wide.iter().copied()).collect::<String>())
                },
                TdhInType::InTypeAnsiString => {
                    let string = std::str::from_utf8(prop_slice.buffer)?;
                    Ok(string.trim_matches(char::default()).to_string())
                },
                TdhInType::InTypeSid => {
                    let string = sddl::convert_sid_to_string(prop_slice.buffer.as_ptr().cast())?;
                    Ok(string)
                },
                TdhInType::InTypeManifestCountedString | TdhInType::InTypeCountedString => {
                    parse_counted_string(prop_slice.buffer, true)
                },
                TdhInType::InTypeManifestCountedAnsiString | TdhInType::InTypeCountedAnsiString => {
                    parse_counted_string(prop_slice.buffer, false)
                },
                _ => Err(ParserError::InvalidType),
            },
            PropertyInfo::Array { .. } => Err(ParserError::InvalidType),
        }
    }
}

impl private::TryParse<GUID> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> Result<GUID, ParserError> {
        let prop_slice = self.find_property(name)?;

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
            PropertyInfo::Array { .. } => Err(ParserError::InvalidType),
        }
    }
}

impl private::TryParse<IpAddr> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<IpAddr> {
        let prop_slice = self.find_property(name)?;

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
            PropertyInfo::Array { .. } => Err(ParserError::InvalidType),
        }
    }
}

impl private::TryParse<bool> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<bool> {
        let prop_slice = self.find_property(name)?;

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
            PropertyInfo::Array { .. } => Err(ParserError::InvalidType),
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
impl private::TryParse<TdhSocketAddress> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<TdhSocketAddress> {
        let prop_slice = self.find_property(name)?;

        match prop_slice.property.info {
            PropertyInfo::Value { out_type, .. } => {
                if out_type != TdhOutType::OutTypeSocketAddress {
                    return Err(ParserError::InvalidType);
                }

                TdhSocketAddress::from_property_buffer(prop_slice.buffer)
            },
            PropertyInfo::Array { .. } => Err(ParserError::InvalidType),
        }
    }
}

impl private::TryParse<FileTime> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<FileTime> {
        let prop_slice = self.find_property(name)?;

        match prop_slice.property.info {
            PropertyInfo::Value { in_type, .. } => {
                if in_type != TdhInType::InTypeFileTime {
                    return Err(ParserError::InvalidType);
                }

                Ok(FileTime::from_slice(prop_slice.buffer.try_into()?))
            },
            PropertyInfo::Array { .. } => Err(ParserError::InvalidType),
        }
    }
}

impl private::TryParse<SystemTime> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<SystemTime> {
        let prop_slice = self.find_property(name)?;

        match prop_slice.property.info {
            PropertyInfo::Value { in_type, .. } => {
                if in_type != TdhInType::InTypeSystemTime {
                    return Err(ParserError::InvalidType);
                }

                Ok(SystemTime::from_slice(prop_slice.buffer.try_into()?))
            },
            PropertyInfo::Array { .. } => Err(ParserError::InvalidType),
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

impl private::TryParse<Pointer> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> ParserResult<Pointer> {
        let prop_slice = self.find_property(name)?;

        let mut res = Pointer::default();
        // Pointers wider than usize (i.e. on 16-bit targets) are truncated
        #[allow(clippy::cast_possible_truncation)]
        if prop_slice.buffer.len() == size_of::<u32>() {
            res.0 = private::TryParse::<u32>::try_parse_impl(self, name)? as usize;
        } else {
            res.0 = private::TryParse::<u64>::try_parse_impl(self, name)? as usize;
        }

        Ok(res)
    }
}

impl private::TryParse<Vec<u8>> for Parser<'_, '_> {
    fn try_parse_impl(&self, name: &str) -> Result<Vec<u8>, ParserError> {
        let prop_slice = self.find_property(name)?;
        Ok(prop_slice.buffer.to_vec())
    }
}

// TODO: Study if we can use primitive types for HexInt64, HexInt32 and Pointer

#[cfg(test)]
mod tests {
    //! Unit tests built on synthetic `TRACE_EVENT_INFO` / `EVENT_RECORD` buffers,
    //! so that the parsing logic can be exercised without a real ETW session
    //! (which would require administrator rights).

    use std::alloc::Layout;

    use windows::Win32::System::Diagnostics::Etw;

    use super::*;
    use crate::{native::tdh::TraceEventInfo, schema::Schema};

    /// Description of one synthetic property of a schema
    struct PropSpec {
        name: &'static str,
        in_type: TdhInType,
        out_type: TdhOutType,
        /// `EVENT_PROPERTY_INFO.Flags` (e.g. `PropertyParamCount`)
        flags: u32,
        /// Value written to the count/countPropertyIndex union member
        count: u16,
        /// Value written to the length/lengthPropertyIndex union member
        length: u16,
    }

    impl PropSpec {
        const fn new(name: &'static str, in_type: TdhInType, length: u16) -> Self {
            Self {
                name,
                in_type,
                out_type: TdhOutType::OutTypeNull,
                flags: 0,
                count: 0,
                length,
            }
        }

        const fn with_out_type(mut self, out_type: TdhOutType) -> Self {
            self.out_type = out_type;
            self
        }
    }

    /// Builds a `Schema` wrapping a synthetic `TRACE_EVENT_INFO` describing `props`
    fn synthetic_schema(props: &[PropSpec]) -> Schema {
        let size_of_info = size_of::<Etw::TRACE_EVENT_INFO>();
        let size_of_prop = size_of::<Etw::EVENT_PROPERTY_INFO>();
        let mut names_size = 0;
        for prop in props {
            names_size += (prop.name.len() + 1) * 2; // utf-16 code units, NUL included
        }
        let size = size_of_info + props.len().saturating_sub(1) * size_of_prop + names_size;
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
            (*info).PropertyCount = u32::try_from(props.len()).unwrap();

            let mut name_offset = names_offset;
            for (index, spec) in props.iter().enumerate() {
                // Test flags are small bit patterns: they never wrap around
                #[allow(clippy::cast_possible_wrap)]
                let flags = Etw::PROPERTY_FLAGS(spec.flags as i32);
                let prop = (*info).EventPropertyInfoArray.as_mut_ptr().add(index);
                (*prop).Flags = flags;
                (*prop).NameOffset = name_offset;
                (*prop).Anonymous1.nonStructType.InType = spec.in_type as u16;
                (*prop).Anonymous1.nonStructType.OutType = spec.out_type as u16;
                (*prop).Anonymous2.count = spec.count;
                (*prop).Anonymous3.length = spec.length;

                // Names are written unaligned, which the read side mirrors
                #[allow(clippy::cast_ptr_alignment)]
                let name = buffer.cast::<u16>().add(name_offset as usize / 2);
                for (i, unit) in spec
                    .name
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .enumerate()
                {
                    name.add(i).write_unaligned(unit);
                }
                name_offset += u32::try_from((spec.name.len() + 1) * 2).unwrap();
            }
        }

        Schema::new(TraceEventInfo::from_raw_parts(buffer, layout))
    }

    /// Builds an `EventRecord` whose user data is `user_data`
    fn synthetic_record(user_data: &[u8]) -> EventRecord {
        EventRecord(Etw::EVENT_RECORD {
            UserData: user_data.as_ptr() as *mut _,
            UserDataLength: u16::try_from(user_data.len()).unwrap(),
            ..Default::default()
        })
    }

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
        pub const IN_U16: u8 = 6;
        pub const IN_I32: u8 = 7;
        pub const IN_U32: u8 = 8;
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

    /// Builds the user data of a TraceLogging event: the two metadata blobs
    /// TDH expects (provider then event metadata), each with a `u16` size
    /// prefix, followed by the field values. Values are irrelevant here: this
    /// only exercises schema decoding, but they must be present so that the
    /// total size is plausible.
    fn tlg_user_data(event_meta: &[u8], values: &[u8]) -> Vec<u8> {
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
    /// metadata embedded in the user data
    fn tlg_schema(user_data: &[u8]) -> Schema {
        // Header size and user data length always fit: synthetic test data
        #[allow(clippy::cast_possible_truncation)]
        let header_size = size_of::<Etw::EVENT_HEADER>() as u16;
        let header = Etw::EVENT_HEADER {
            Size: header_size,
            Flags: 0x0002, // EVENT_HEADER_FLAG_TRACE_MESSAGE
            EventDescriptor: Etw::EVENT_DESCRIPTOR {
                Channel: 11, // TraceLogging channel
                ..Default::default()
            },
            ..Default::default()
        };
        let record = EventRecord(Etw::EVENT_RECORD {
            EventHeader: header,
            UserData: user_data.as_ptr() as *mut _,
            UserDataLength: u16::try_from(user_data.len()).unwrap(),
            ..Default::default()
        });
        let info = TraceEventInfo::build_from_event(&record)
            .expect("TDH should decode the synthetic TraceLogging event");
        Schema::new(info)
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

    /// Pins down how TDH maps TraceLogging metadata to its own in/out types:
    /// this is the ground truth the parser and the serializer rely on
    /// (e.g. `str8` only becomes readable through the counted-Ansi in type)
    #[test]
    fn tracelogging_types_decode_through_tdh() {
        use tlg::*;

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

        let schema = tlg_schema(&tlg_user_data(&meta, &values));
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
}
