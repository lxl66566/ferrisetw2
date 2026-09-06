//! Basic TDH types
//!
//! The `tdh_type` module provides an abstraction over the basic TDH types, this module act as a
//! helper for the parser to determine which IN and OUT type are expected from a property within an
//! event
//!
//! This is a bit extra but is basically a redefinition of the In an Out TDH types following the
//! rust naming convention, it can also come in handy when implementing the `TryParse` trait for a type
//! to determine how to handle a [Property] based on this values
//!
//! [Property]: crate::native::tdh_types::Property
use num_traits::FromPrimitive;

use windows::Win32::System::Diagnostics::Etw;

#[derive(Debug, Clone)]
pub enum PropertyError {
    /// Parsing complex types in properties is not supported in this crate
    /// (yet? See <https://github.com/n4r1b/ferrisetw/issues/76>)
    UnimplementedType(&'static str),
}

impl std::fmt::Display for PropertyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnimplementedType(s) => write!(f, "unimplemented type: {}", s),
        }
    }
}

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
        out_type: TdhOutType,
        /// The length of the property
        length: PropertyLength,
        /// Number of elements.
        count: PropertyCount,
    },
}

impl Default for PropertyInfo {
    fn default() -> Self {
        PropertyInfo::Value {
            in_type: Default::default(),
            out_type: Default::default(),
            length: Default::default(),
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

#[doc(hidden)]
impl Property {
    pub fn new(name: String, property: &Etw::EVENT_PROPERTY_INFO) -> Result<Self, PropertyError> {
        let flags = PropertyFlags::from(property.Flags);

        if flags.contains(PropertyFlags::PROPERTY_STRUCT) {
            Err(PropertyError::UnimplementedType("structure"))
        } else if flags.contains(PropertyFlags::PROPERTY_HAS_CUSTOM_SCHEMA) {
            Err(PropertyError::UnimplementedType("has custom schema"))
        } else {
            // The property is a non-struct type. It makes sense to access these fields of the unions
            let ot = unsafe { property.Anonymous1.nonStructType.OutType };
            let it = unsafe { property.Anonymous1.nonStructType.InType };

            let length = if flags.contains(PropertyFlags::PROPERTY_PARAM_LENGTH) {
                // The property length is stored in another property, this is the index of that property
                PropertyLength::Index(unsafe { property.Anonymous3.lengthPropertyIndex })
            } else {
                // The property has no param for its length, it makes sense to access this field of the union
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
                Some(c) => Ok(Property {
                    name,
                    info: PropertyInfo::Array {
                        in_type,
                        out_type,
                        length,
                        count: c,
                    },
                }),
                None => Ok(Property {
                    name,
                    info: PropertyInfo::Value {
                        in_type,
                        out_type,
                        length,
                    },
                }),
            }
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
    InTypeCountedString = 300,
    InTypeCountedAnsiString,
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
        // Should be a safe cast
        PropertyFlags::from_bits_truncate(flags as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an EVENT_PROPERTY_INFO describing a UInt32 of 4 bytes, with the
    /// given value in the count/countPropertyIndex union member
    fn property_with_count_union(flags: u32, count_union: u16) -> Result<Property, PropertyError> {
        let mut info = Etw::EVENT_PROPERTY_INFO {
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
                property_with_count_union(PropertyFlags::PROPERTY_PARAM_COUNT.bits(), index)
                    .unwrap();
            match property.info {
                PropertyInfo::Array {
                    count: PropertyCount::Index(i),
                    ..
                } => assert_eq!(i, index),
                other => panic!("expected a dynamic array, got {:?}", other),
            }
        }
    }

    #[test]
    fn literal_count_classifies_arrays_and_scalars() {
        // TDH reports 1 for properties that are NOT arrays
        // (EVENT_PROPERTY_INFO.count documentation), so count == 1 cannot be
        // distinguished from an actual 1-element array
        let scalar = property_with_count_union(0, 1).unwrap();
        assert!(matches!(scalar.info, PropertyInfo::Value { .. }));

        let zero = property_with_count_union(0, 0).unwrap();
        assert!(matches!(zero.info, PropertyInfo::Value { .. }));

        let array = property_with_count_union(0, 3).unwrap();
        assert!(matches!(
            array.info,
            PropertyInfo::Array {
                count: PropertyCount::Count(3),
                ..
            }
        ));
    }
}
