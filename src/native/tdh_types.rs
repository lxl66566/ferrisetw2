//! Basic TDH types
//!
//! The `tdh_type` module provides an abstraction over the basic TDH types, this module act as a
//! helper for the parser to determine which IN and OUT type are expected from a property within an
//! event
//!
//! This is a bit extra but is basically a redefinition of the In an Out TDH types following the
//! rust naming convention, it can also come in handy when implementing the `TryParse` trait for a
//! type to determine how to handle a [Property] based on this values
//!
//! [Property]: crate::native::tdh_types::Property
use num_traits::FromPrimitive;
use windows::Win32::System::Diagnostics::Etw;

/// Notes if the property count is a concrete length or an index into another property.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PropertyCount {
    Count(u16),
    Index(u16),
}

impl Default for PropertyCount {
    fn default() -> Self {
        PropertyCount::Count(0)
    }
}

/// Notes if the property length is a concrete length or an index to another property
/// which contains the length.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PropertyLength {
    Length(u16),
    Index(u16),
}

impl Default for PropertyLength {
    fn default() -> Self {
        PropertyLength::Length(0)
    }
}

/// A note on structures: TDH expresses a structure property through the
/// `PropertyStruct` flag. Its members are identified by
/// `structType.StructStartIndex` (index in `TRACE_EVENT_INFO.EventPropertyInfoArray`
/// of the first member) and `structType.NumOfStructMembers` (contiguous entry
/// count, possibly structures themselves). Top-level properties come before
/// all member properties in the array, so the schema iterator yields
/// top-level properties only: members are reachable only through
/// [`PropertyInfo::Struct`] / [`PropertyInfo::StructArray`], never mistaken
/// for top-level ones.
#[derive(Debug, Clone)]
pub enum PropertyInfo {
    Value {
        /// TDH In type of the property
        in_type: TdhInType,
        /// TDH Out type of the property
        out_type: TdhOutType,
        /// The length of the property
        length: PropertyLength,
    },
    Array {
        /// TDH In type of the property
        in_type: TdhInType,
        /// TDH Out type of the property
        // Read by the serializer: array elements honor the out type (e.g.
        // hex display) just like scalar values do
        out_type: TdhOutType,
        /// The length of the property
        length: PropertyLength,
        /// Number of elements.
        count: PropertyCount,
    },
    /// A structure: its members, in layout order.
    ///
    /// A structure occupies the concatenation of its members' bytes. The
    /// generic `try_parse` of a whole structure is not supported; with the
    /// `serde` feature, structures serialize as nested objects
    /// (variable-length members are sized from their leading bytes when
    /// possible, and members that cannot be sized serialize as null).
    Struct {
        /// Members of the structure, possibly structures themselves
        // Read by the parser's struct breakdown
        #[allow(dead_code)]
        members: Vec<Property>,
    },
    /// An array of structures: `count` elements, each laid out as `members`.
    ///
    /// `count` may reference the property holding the element count
    /// ([`PropertyCount::Index`]), as manifest struct arrays commonly do
    /// (e.g. the .NET `GCBulk*` events).
    StructArray {
        /// Members of one element, possibly structures themselves
        // Read by the parser's element count resolution
        #[allow(dead_code)]
        members: Vec<Property>,
        /// Number of elements
        // Read by the parser's element count resolution
        #[allow(dead_code)]
        count: PropertyCount,
    },
    /// A property this crate cannot decode (e.g. `PROPERTY_HAS_CUSTOM_SCHEMA`,
    /// whose layout is described by an out-of-band schema).
    ///
    /// It still occupies its bytes in the event buffer, so it stays in the
    /// property list in its original position: dropping it would shift the
    /// offsets of every later property. The serializer degrades it per its
    /// `fail_unimplemented` option.
    Unsupported {
        /// Schema-declared size, when fixed: a known size keeps the parser's
        /// buffer walk local (no TDH round-trip)
        length: PropertyLength,
    },
}

impl Default for PropertyInfo {
    fn default() -> Self {
        PropertyInfo::Value {
            in_type: TdhInType::default(),
            out_type: TdhOutType::default(),
            length: PropertyLength::default(),
        }
    }
}

/// Attributes of a property
#[derive(Debug, Clone, Default)]
pub struct Property {
    /// Name of the Property
    pub name: String,
    /// Information about the property.
    pub info: PropertyInfo,
}

impl Property {
    /// Size in bytes when the property has a fixed layout, or `None` when it
    /// is variable-length (strings without an explicit length, lengths or
    /// counts held by another property, ...)
    ///
    /// Structure sizes follow from the sum of their members' fixed sizes,
    /// which avoids a TDH round-trip in the common all-fixed case
    // Shared by the parser's buffer walk and the serializer's member slicing
    #[allow(dead_code)]
    pub(crate) fn fixed_size(&self, pointer_size: usize) -> Option<usize> {
        match &self.info {
            PropertyInfo::Value {
                in_type, length, ..
            } => {
                // SIZET is the deprecated WBEM pointer: same sizing rules
                if matches!(in_type, TdhInType::InTypePointer | TdhInType::InTypeSizeT) {
                    return Some(pointer_size);
                }
                match length {
                    PropertyLength::Length(l) if *l > 0 => Some(in_type.schema_length_bytes(*l)),
                    // A zero length means "ask TDH" for a top-level property;
                    // inside a structure it marks a variable-length member —
                    // unless the in type has a fixed size, which tdh.h says
                    // overrides the (ignorable) length
                    PropertyLength::Length(_) => in_type.fixed_size(),
                    PropertyLength::Index(_) => None,
                }
            },
            PropertyInfo::Array {
                in_type,
                length,
                count,
                ..
            } => {
                let elem = if matches!(in_type, TdhInType::InTypePointer | TdhInType::InTypeSizeT) {
                    pointer_size
                } else {
                    match length {
                        PropertyLength::Length(l) if *l > 0 => in_type.schema_length_bytes(*l),
                        PropertyLength::Length(_) => in_type.fixed_size()?,
                        PropertyLength::Index(_) => return None,
                    }
                };
                let count = match count {
                    PropertyCount::Count(c) => *c as usize,
                    PropertyCount::Index(_) => return None,
                };
                Some(elem * count)
            },
            PropertyInfo::Struct { members } => {
                members.iter().map(|m| m.fixed_size(pointer_size)).sum()
            },
            PropertyInfo::StructArray { members, count } => {
                let elem: usize = members
                    .iter()
                    .map(|m| m.fixed_size(pointer_size))
                    .sum::<Option<usize>>()?;
                let count = match count {
                    PropertyCount::Count(c) => *c as usize,
                    PropertyCount::Index(_) => return None,
                };
                Some(elem * count)
            },
            PropertyInfo::Unsupported { length } => match length {
                PropertyLength::Length(l) if *l > 0 => Some(*l as usize),
                _ => None,
            },
        }
    }
}

#[doc(hidden)]
impl Property {
    /// Parses a non-structure property entry.
    ///
    /// Structure entries need their member entries, which only the schema
    /// iterator has access to (see `native::tdh::PropertyIterator`): they
    /// never reach this function.
    pub fn new(name: String, property: &Etw::EVENT_PROPERTY_INFO) -> Self {
        let flags = PropertyFlags::from(property.Flags);

        if flags.contains(PropertyFlags::PROPERTY_HAS_CUSTOM_SCHEMA) {
            // The layout lives in an out-of-band custom schema this crate
            // does not decode: keep the property marked instead of dropping
            // it (it occupies its bytes in the buffer)
            let length = if flags.contains(PropertyFlags::PROPERTY_PARAM_LENGTH) {
                // The property length is stored in another property, this is
                // the index of that property
                // Safety: PropertyParamLength is set, the union holds
                // lengthPropertyIndex
                PropertyLength::Index(unsafe { property.Anonymous3.lengthPropertyIndex })
            } else {
                // Safety: no PropertyParamLength, the union holds the length
                PropertyLength::Length(unsafe { property.Anonymous3.length })
            };
            return Self {
                name,
                info: PropertyInfo::Unsupported { length },
            };
        }

        // The property is a non-struct type. It makes sense to access these fields of
        // the unions
        let ot = unsafe { property.Anonymous1.nonStructType.OutType };
        let it = unsafe { property.Anonymous1.nonStructType.InType };

        let length = if flags.contains(PropertyFlags::PROPERTY_PARAM_LENGTH) {
            // The property length is stored in another property, this is the index of that
            // property
            PropertyLength::Index(unsafe { property.Anonymous3.lengthPropertyIndex })
        } else {
            // The property has no param for its length, it makes sense to access this field of
            // the union
            PropertyLength::Length(unsafe { property.Anonymous3.length })
        };

        let count = if flags.contains(PropertyFlags::PROPERTY_PARAM_COUNT) {
            // The union holds countPropertyIndex: the 0-based index of the
            // property that contains the number of elements. It can
            // legitimately be 0 or 1, so always treat it as an index.
            Some(PropertyCount::Index(unsafe {
                property.Anonymous2.countPropertyIndex
            }))
        } else {
            // The union holds the literal number of elements. Note that TDH
            // reports 1 for properties that are not defined as an array
            // (see EVENT_PROPERTY_INFO's documentation), so only count > 1
            // unambiguously means "array"
            let count = unsafe { property.Anonymous2.count };
            if count > 1 {
                Some(PropertyCount::Count(count))
            } else {
                None
            }
        };

        let out_type = FromPrimitive::from_u16(ot).unwrap_or(TdhOutType::OutTypeNull);

        let in_type = FromPrimitive::from_u16(it).unwrap_or(TdhInType::InTypeNull);

        match count {
            Some(c) => Self {
                name,
                info: PropertyInfo::Array {
                    in_type,
                    out_type,
                    length,
                    count: c,
                },
            },
            None => Self {
                name,
                info: PropertyInfo::Value {
                    in_type,
                    out_type,
                    length,
                },
            },
        }
    }
}

/// Represent a TDH_IN_TYPE
#[repr(u16)]
#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive, PartialEq, Eq, Default)]
pub enum TdhInType {
    // Deprecated values are not defined
    #[default]
    InTypeNull,
    InTypeUnicodeString,
    InTypeAnsiString,
    InTypeInt8,    // Field size is 1 byte
    InTypeUInt8,   // Field size is 1 byte
    InTypeInt16,   // Field size is 2 bytes
    InTypeUInt16,  // Field size is 2 bytes
    InTypeInt32,   // Field size is 4 bytes
    InTypeUInt32,  // Field size is 4 bytes
    InTypeInt64,   // Field size is 8 bytes
    InTypeUInt64,  // Field size is 8 bytes
    InTypeFloat,   // Field size is 4 bytes
    InTypeDouble,  // Field size is 8 bytes
    InTypeBoolean, // Field size is 4 bytes
    InTypeBinary,  // Depends on the OutType
    InTypeGuid,
    InTypePointer,
    InTypeFileTime,   // Field size is 8 bytes
    InTypeSystemTime, // Field size is 16 bytes
    InTypeSid,        // Field size determined by the first few bytes of the field
    InTypeHexInt32,
    InTypeHexInt64,
    /// Little-endian 16-bit byte count followed by UTF-16 data
    /// (TDH_INTYPE_MANIFEST_COUNTEDSTRING, a.k.a. win:CountedUnicodeString)
    InTypeManifestCountedString,
    /// Little-endian 16-bit byte count followed by 8-bit characters
    /// (TDH_INTYPE_MANIFEST_COUNTEDANSISTRING, a.k.a. win:CountedAnsiString)
    InTypeManifestCountedAnsiString,
    /// Little-endian 16-bit byte count followed by raw bytes
    /// (TDH_INTYPE_MANIFEST_COUNTEDBINARY). TDH_INTYPE_RESERVED24 sits at 24,
    /// so the discriminant must be explicit
    InTypeManifestCountedBinary = 25,
    /// WBEM twin of [`TdhInType::InTypeManifestCountedString`], same layout
    InTypeCountedString = 300,
    /// WBEM twin of [`TdhInType::InTypeManifestCountedAnsiString`], same layout
    InTypeCountedAnsiString,
    /// Deprecated big-endian twin of [`TdhInType::InTypeCountedString`]
    /// (TDH_INTYPE_REVERSEDCOUNTEDSTRING): a big-endian 16-bit byte count
    /// followed by UTF-16 data
    InTypeReversedCountedString,
    /// Deprecated big-endian twin of [`TdhInType::InTypeCountedAnsiString`]
    /// (TDH_INTYPE_REVERSEDCOUNTEDANSISTRING): a big-endian 16-bit byte
    /// count followed by 8-bit characters
    InTypeReversedCountedAnsiString,
    /// Deprecated (TDH_INTYPE_NONNULLTERMINATEDSTRING): UTF-16 data with
    /// neither count prefix nor NUL terminator — tdh.h sizes the field as
    /// "the remaining bytes of data in the event"
    InTypeNonNullTerminatedString,
    /// ANSI twin of [`TdhInType::InTypeNonNullTerminatedString`]
    /// (TDH_INTYPE_NONNULLTERMINATEDANSISTRING)
    InTypeNonNullTerminatedAnsiString,
    /// Deprecated (TDH_INTYPE_UNICODECHAR): a single WCHAR. tdh.h: "Field
    /// size is 2 bytes", default OutType STRING
    InTypeUnicodeChar = 306,
    /// Deprecated (TDH_INTYPE_ANSICHAR): a single CHAR. tdh.h: "Field size
    /// is 1 byte", default OutType STRING
    InTypeAnsiChar,
    /// Deprecated (TDH_INTYPE_SIZET): a SIZE_T (UINT_PTR) value, sized from
    /// the event header flags exactly like [`TdhInType::InTypePointer`].
    /// Default OutType is HEXINT64
    InTypeSizeT,
    /// Deprecated (TDH_INTYPE_HEXDUMP): a little-endian 32-bit byte count
    /// followed by that many raw bytes. Default OutType is HEXBINARY
    InTypeHexDump,
    /// Deprecated (TDH_INTYPE_WBEMSID): a security identifier (SID), laid
    /// out like [`TdhInType::InTypeSid`]
    InTypeWbemSid,
}

impl TdhInType {
    /// Byte size of one element whose schema declares an explicit nonzero
    /// length (`EVENT_PROPERTY_INFO.length`).
    ///
    /// The unit of that length is documented per in type, and two Microsoft
    /// sources disagree:
    ///
    /// * `tdh.h` (SDK per-type rules): for `TDH_INTYPE_UNICODESTRING` "the epi.length field
    ///   contains number of WCHARs in the string" — its AnsiString twin counts BYTEs
    /// * the generic `EVENT_PROPERTY_INFO` documentation (MSDN): "Size of the property, in bytes"
    ///
    /// The manifest schema (eventman.xsd, shipped with the SDK) settles the
    /// contradiction in favor of tdh.h: "Length indicates the size (in
    /// characters) of the property value" for UnicodeString and AnsiString.
    /// Real TDH behavior cannot disprove it: on TraceLogging events TDH
    /// always reports length 0 for strings (NUL-terminated, see the parser
    /// test), so the explicit-length branch is only reachable through
    /// manifest/WBEM schemas, which cannot be installed without elevation.
    /// krabsetw, from which this crate's sizing code originally came, reads
    /// the length as bytes too and shares the issue.
    pub(crate) fn schema_length_bytes(self, length: u16) -> usize {
        match self {
            Self::InTypeUnicodeString => usize::from(length) * 2,
            _ => usize::from(length),
        }
    }

    /// Fixed byte size of the in types whose size follows from the in type
    /// alone, per the tdh.h comments ("Field size is N bytes").
    ///
    /// tdh.h: "Some InTypes have a fixed size. For these fields, the length
    /// property of the EVENT_PROPERTY_INFO structure can be ignored by
    /// decoders." Verified against the real TDH: TraceLogging field metadata
    /// carries no length at all, and TDH still synthesizes exactly these
    /// lengths from the in type alone (see the parser tests).
    pub(crate) fn fixed_size(self) -> Option<usize> {
        match self {
            Self::InTypeInt8 | Self::InTypeUInt8 | Self::InTypeAnsiChar => Some(1),
            Self::InTypeInt16 | Self::InTypeUInt16 | Self::InTypeUnicodeChar => Some(2),
            Self::InTypeInt32
            | Self::InTypeUInt32
            | Self::InTypeFloat
            | Self::InTypeBoolean
            | Self::InTypeHexInt32 => Some(4),
            Self::InTypeInt64
            | Self::InTypeUInt64
            | Self::InTypeDouble
            | Self::InTypeFileTime
            | Self::InTypeHexInt64 => Some(8),
            Self::InTypeGuid | Self::InTypeSystemTime => Some(16),
            _ => None,
        }
    }
}

/// Represent a TDH_OUT_TYPE
#[repr(u16)]
#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive, PartialEq, Eq, Default)]
pub enum TdhOutType {
    #[default]
    OutTypeNull,
    OutTypeString,
    OutTypeDateTime,
    OutTypeInt8,    // Field size is 1 byte
    OutTypeUInt8,   // Field size is 1 byte
    OutTypeInt16,   // Field size is 2 bytes
    OutTypeUInt16,  // Field size is 2 bytes
    OutTypeInt32,   // Field size is 4 bytes
    OutTypeUInt32,  // Field size is 4 bytes
    OutTypeInt64,   // Field size is 8 bytes
    OutTypeUInt64,  // Field size is 8 bytes
    OutTypeFloat,   // Field size is 4 bytes
    OutTypeDouble,  // Field size is 8 bytes
    OutTypeBoolean, // Field size is 4 bytes
    OutTypeGuid,
    OutTypeHexBinary,
    OutTypeHexInt8,
    OutTypeHexInt16,
    OutTypeHexInt32,
    OutTypeHexInt64,
    OutTypePid,
    OutTypeTid,
    OutTypePort,
    OutTypeIpv4,
    OutTypeIpv6,
    /// The field is a `SOCKADDR` structure (TDH_OUTTYPE_SOCKETADDRESS)
    OutTypeSocketAddress = 25,
    OutTypeWin32Error = 30,
    OutTypeNtStatus = 31,
    OutTypeHResult = 32,
    OutTypeJson = 34,
    OutTypeUtf8 = 35,
    OutTypePkcs7 = 36,
    OutTypeCodePointer = 37,
    OutTypeDatetimeUtc = 38,
}

bitflags! {
    /// Represents the Property flags
    ///
    /// See: [Property Flags enum](https://docs.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-property_flags)
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct PropertyFlags: u32 {
        const PROPERTY_STRUCT = 0x1;
        const PROPERTY_PARAM_LENGTH = 0x2;
        const PROPERTY_PARAM_COUNT = 0x4;
        const PROPERTY_WBEMXML_FRAGMENT = 0x8;
        const PROPERTY_PARAM_FIXED_LENGTH = 0x10;
        const PROPERTY_PARAM_FIXED_COUNT = 0x20;
        const PROPERTY_HAS_TAGS = 0x40;
        const PROPERTY_HAS_CUSTOM_SCHEMA = 0x80;
    }
}

impl From<Etw::PROPERTY_FLAGS> for PropertyFlags {
    fn from(val: Etw::PROPERTY_FLAGS) -> Self {
        let flags: i32 = val.0;
        // Safe cast: flags are a bit pattern, never a meaningful negative value
        #[allow(clippy::cast_sign_loss)]
        PropertyFlags::from_bits_truncate(flags as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an EVENT_PROPERTY_INFO describing a UInt32 of 4 bytes, with the
    /// given value in the count/countPropertyIndex union member
    fn property_with_count_union(flags: u32, count_union: u16) -> Property {
        let mut info = Etw::EVENT_PROPERTY_INFO {
            // Test flags are small bit patterns: they never wrap around
            #[allow(clippy::cast_possible_wrap)]
            Flags: Etw::PROPERTY_FLAGS(flags as i32),
            ..Default::default()
        };
        info.Anonymous1.nonStructType.InType = TdhInType::InTypeUInt32 as u16;
        info.Anonymous2.count = count_union;
        info.Anonymous3.length = 4;
        Property::new("prop".into(), &info)
    }

    #[test]
    fn param_count_with_small_property_index_is_an_array() {
        // With PROPERTY_PARAM_COUNT, the union holds the 0-based index of the
        // property holding the element count: 0 and 1 are valid indexes and
        // used to be mistaken for scalars, breaking dynamic arrays
        for index in [0u16, 1, 2] {
            let property =
                property_with_count_union(PropertyFlags::PROPERTY_PARAM_COUNT.bits(), index);
            match property.info {
                PropertyInfo::Array {
                    count: PropertyCount::Index(i),
                    ..
                } => assert_eq!(i, index),
                other => panic!("expected a dynamic array, got {other:?}"),
            }
        }
    }

    #[test]
    fn literal_count_classifies_arrays_and_scalars() {
        // TDH reports 1 for properties that are NOT arrays
        // (EVENT_PROPERTY_INFO.count documentation), so count == 1 cannot be
        // distinguished from an actual 1-element array
        let scalar = property_with_count_union(0, 1);
        assert!(matches!(scalar.info, PropertyInfo::Value { .. }));

        let zero = property_with_count_union(0, 0);
        assert!(matches!(zero.info, PropertyInfo::Value { .. }));

        let array = property_with_count_union(0, 3);
        assert!(matches!(array.info, PropertyInfo::Array {
            count: PropertyCount::Count(3),
            ..
        }));
    }

    #[test]
    fn custom_schema_property_is_kept_as_unsupported() {
        // A PROPERTY_HAS_CUSTOM_SCHEMA property used to fail the whole schema
        // property list: it must come back as a marked, in-place property
        // (dropping it would shift the offsets of every later property)
        let mut info = Etw::EVENT_PROPERTY_INFO {
            #[allow(clippy::cast_possible_wrap)]
            Flags: Etw::PROPERTY_FLAGS(PropertyFlags::PROPERTY_HAS_CUSTOM_SCHEMA.bits() as i32),
            ..Default::default()
        };
        info.Anonymous3.length = 8;
        let property = Property::new("custom".into(), &info);
        match property.info {
            PropertyInfo::Unsupported {
                length: PropertyLength::Length(8),
            } => {},
            other => panic!("expected an unsupported property of length 8, got {other:?}"),
        }
    }

    #[test]
    fn zero_length_falls_back_to_the_fixed_in_type_size() {
        // A WBEM/MOF schema may leave the length of fixed-size in types at 0
        fn property_with_length(in_type: TdhInType, length: u16) -> Property {
            let mut info = Etw::EVENT_PROPERTY_INFO::default();
            info.Anonymous1.nonStructType.InType = in_type as u16;
            info.Anonymous3.length = length;
            Property::new("prop".into(), &info)
        }

        assert_eq!(
            property_with_length(TdhInType::InTypeUInt16, 0).fixed_size(8),
            Some(2)
        );
        assert_eq!(
            property_with_length(TdhInType::InTypeGuid, 0).fixed_size(8),
            Some(16)
        );
        // An explicit length still wins
        assert_eq!(
            property_with_length(TdhInType::InTypeUInt16, 6).fixed_size(8),
            Some(6)
        );
        // A length held by another property is not ignorable
        let mut info = Etw::EVENT_PROPERTY_INFO {
            #[allow(clippy::cast_possible_wrap)]
            Flags: Etw::PROPERTY_FLAGS(PropertyFlags::PROPERTY_PARAM_LENGTH.bits() as i32),
            ..Default::default()
        };
        info.Anonymous1.nonStructType.InType = TdhInType::InTypeUInt16 as u16;
        info.Anonymous3.lengthPropertyIndex = 3;
        assert_eq!(Property::new("prop".into(), &info).fixed_size(8), None);
    }

    #[test]
    fn manifest_counted_binary_maps_from_its_tdh_discriminant() {
        // TDH_INTYPE_MANIFEST_COUNTEDBINARY = 25 (24 is RESERVED24): it used
        // to fall back to InTypeNull and serialize as a null property
        let mut info = Etw::EVENT_PROPERTY_INFO::default();
        info.Anonymous1.nonStructType.InType = TdhInType::InTypeManifestCountedBinary as u16;
        let property = Property::new("blob".into(), &info);
        assert!(matches!(property.info, PropertyInfo::Value {
            in_type: TdhInType::InTypeManifestCountedBinary,
            ..
        }));
    }
}
