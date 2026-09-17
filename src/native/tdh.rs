//! Native API - Event Tracing tdh header
//!
//! The `tdh` module is an abstraction layer for the Windows tdh library. This module act as a
//! internal API that holds all `unsafe` calls to functions exported by the `tdh` Windows library.
//!
//! This module shouldn't be accessed directly. Modules from the the crate level provide a safe API
//! to interact with the crate
use std::alloc::Layout;

use widestring::U16CStr;
use windows::{
    Win32::{
        Foundation::ERROR_INSUFFICIENT_BUFFER,
        System::Diagnostics::Etw::{self, TRACE_EVENT_INFO},
    },
    core::GUID,
};

use super::etw_types::*;
use crate::{
    native::{
        etw_types::event_record::EventRecord,
        tdh_types::{Property, PropertyCount, PropertyFlags, PropertyInfo},
    },
    traits::*,
};

/// Tdh native module errors
#[derive(Debug)]
pub enum TdhNativeError {
    /// Represents an allocation error
    AllocationError,
    /// Represents an standard IO Error
    IoError(std::io::Error),
}

pub type TdhNativeResult<T> = Result<T, TdhNativeError>;

impl std::fmt::Display for TdhNativeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AllocationError => write!(f, "allocation error"),
            Self::IoError(e) => write!(f, "i/o error {e}"),
        }
    }
}

// Win32 error codes always fit in an i32
#[allow(clippy::cast_possible_wrap)]
fn io_error_from_win32(status: u32) -> TdhNativeError {
    TdhNativeError::IoError(std::io::Error::from_raw_os_error(status as i32))
}

/// Read-only wrapper over an [TRACE_EVENT_INFO]
///
/// [TRACE_EVENT_INFO]: https://docs.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-trace_event_info
pub struct TraceEventInfo {
    /// Pointer to a valid TRACE_EVENT_INFO buffer
    data: *const u8,
    /// Pointer to the same buffer, but mutable (used only when deallocating the data)
    mut_data_for_dealloc: *mut u8,
    /// Layout used to allocate the TRACE_EVENT_INFO buffer
    layout: Layout,
}

// Safety: TraceEventInfo contains a pointer to data that is never mutated (except on deallocation),
// and that itself does not contain pointers
unsafe impl Send for TraceEventInfo {}
// Safety: see above
unsafe impl Sync for TraceEventInfo {}

macro_rules! extract_utf16_string {
    ($self:ident, $member_name:ident) => {
        let provider_name_offset = $self.as_raw().$member_name;
        let provider_name_ptr = unsafe {
            // Safety: we trust Microsoft for providing correctly aligned data
            $self.data.add(provider_name_offset as usize)
        };
        if provider_name_offset == 0 || provider_name_ptr.is_null() {
            return String::new();
        }
        // UTF-16 strings sit at 2-byte-aligned offsets inside the TRACE_EVENT_INFO buffer
        #[allow(clippy::cast_ptr_alignment)]
        let provider_name = unsafe {
            // Safety:
            //  * we trust Microsoft for providing correctly aligned data
            //  * we will copy into a String before the buffer gets invalid
            U16CStr::from_ptr_str(provider_name_ptr.cast::<u16>())
        };
        return provider_name.to_string_lossy();
    };
}

impl TraceEventInfo {
    /// Build an instance that takes ownership of a manually-crafted
    /// `TRACE_EVENT_INFO` buffer (used by unit tests, so that no real ETW
    /// event is needed to exercise the parsing code)
    #[cfg(test)]
    pub(crate) fn from_raw_parts(data: *mut u8, layout: Layout) -> Self {
        Self {
            data,
            mut_data_for_dealloc: data,
            layout,
        }
    }

    /// Create a instance of `Self` suitable for the given event
    pub fn build_from_event(event: &EventRecord) -> TdhNativeResult<Self> {
        let mut buffer_size = 0;
        let status = unsafe {
            // Safety:
            //  * the `EVENT_RECORD` was passed by Microsoft and has not been modified: it is thus
            //    valid and correctly aligned
            Etw::TdhGetEventInformation(event.as_raw_ptr(), None, None, &raw mut buffer_size)
        };
        if status != ERROR_INSUFFICIENT_BUFFER.0 {
            return Err(io_error_from_win32(status));
        }

        if buffer_size == 0 {
            return Err(TdhNativeError::AllocationError);
        }

        let layout = Layout::from_size_align(buffer_size as usize, align_of::<TRACE_EVENT_INFO>())
            .map_err(|_| TdhNativeError::AllocationError)?;
        let data = unsafe {
            // Safety: size is not zero
            std::alloc::alloc(layout)
        };
        if data.is_null() {
            return Err(TdhNativeError::AllocationError);
        }

        let status = unsafe {
            // Safety:
            //  * the `EVENT_RECORD` was passed by Microsoft and has not been modified: it is thus
            //    valid and correctly aligned
            //  * `data` has been successfully allocated, with the required size and the correct
            //    alignment
            #[allow(clippy::cast_ptr_alignment)] // allocated with the alignment of TRACE_EVENT_INFO
            Etw::TdhGetEventInformation(
                event.as_raw_ptr(),
                None,
                Some(data.cast::<TRACE_EVENT_INFO>()),
                &raw mut buffer_size,
            )
        };

        if status != 0 {
            return Err(io_error_from_win32(status));
        }

        Ok(Self {
            data,
            mut_data_for_dealloc: data,
            layout,
        })
    }

    // The buffer is allocated with the alignment of TRACE_EVENT_INFO, so this
    // pointer cast is valid
    #[allow(clippy::cast_ptr_alignment)]
    fn as_raw(&self) -> &TRACE_EVENT_INFO {
        let p = self.data.cast::<TRACE_EVENT_INFO>();
        unsafe {
            // Safety: the API enforces self.data to point to a valid, allocated TRACE_EVENT_INFO
            p.as_ref().unwrap()
        }
    }

    pub fn provider_guid(&self) -> GUID {
        self.as_raw().ProviderGuid
    }

    pub fn event_id(&self) -> u16 {
        self.as_raw().EventDescriptor.Id
    }

    pub fn event_version(&self) -> u8 {
        self.as_raw().EventDescriptor.Version
    }

    pub fn decoding_source(&self) -> DecodingSource {
        let ds = self.as_raw().DecodingSource;
        DecodingSource::from(ds)
    }

    pub fn provider_name(&self) -> String {
        extract_utf16_string!(self, ProviderNameOffset);
    }

    pub fn task_name(&self) -> String {
        extract_utf16_string!(self, TaskNameOffset);
    }

    pub fn opcode_name(&self) -> String {
        extract_utf16_string!(self, OpcodeNameOffset);
    }

    pub fn properties(&self) -> PropertyIterator<'_> {
        PropertyIterator::new(self)
    }
}

impl Drop for TraceEventInfo {
    fn drop(&mut self) {
        unsafe {
            // Safety:
            // * ptr is a block of memory currently allocated via alloc::alloc
            // * layout is th one that was used to allocate that block of memory
            std::alloc::dealloc(self.mut_data_for_dealloc, self.layout);
        }
    }
}

pub struct PropertyIterator<'info> {
    next_index: u32,
    /// Number of top-level properties to yield: "top-level properties come
    /// before all member properties in the array" (TRACE_EVENT_INFO docs),
    /// members of structures are only reachable through PropertyInfo
    top_level_count: u32,
    /// Total number of entries in EventPropertyInfoArray
    property_count: u32,
    te_info: &'info TraceEventInfo,
}

impl<'info> PropertyIterator<'info> {
    fn new(te_info: &'info TraceEventInfo) -> Self {
        let raw = te_info.as_raw();
        let property_count = raw.PropertyCount;
        let top_level_count = if raw.TopLevelPropertyCount == 0 {
            // Defensive: keep the legacy behavior of treating every property
            // as top-level if TDH did not fill the top-level count
            property_count
        } else {
            raw.TopLevelPropertyCount.min(property_count)
        };
        Self {
            next_index: 0,
            top_level_count,
            property_count,
            te_info,
        }
    }

    /// The EVENT_PROPERTY_INFO at the given index, if within bounds
    fn property_at(&self, index: u32) -> Option<&Etw::EVENT_PROPERTY_INFO> {
        let properties_array = self.te_info.as_raw().EventPropertyInfoArray.as_ptr();
        let property_ptr = unsafe {
            // Safety:
            //  * index being in the right bounds, this guarantees the resulting pointer lies in the
            //    same allocated object
            // (we assume there will not be more than 4 billion properties for an event)
            properties_array.add(index as usize)
        };
        // Safety: this pointer has been allocated by a Microsoft API
        unsafe { property_ptr.as_ref() }
    }

    /// Name of a property entry, extracted from the TRACE_EVENT_INFO buffer
    fn property_name(&self, property: &Etw::EVENT_PROPERTY_INFO) -> Option<String> {
        let te_info_data = std::ptr::from_ref(self.te_info.as_raw()).cast::<u8>();
        let property_name_ptr = unsafe {
            // Safety: offset comes from a Microsoft API
            te_info_data.add(property.NameOffset as usize)
        };
        if property_name_ptr.is_null() {
            // This is really a safety net, there is no reason the offset nullifies the base pointer
            return None;
        }

        // UTF-16 strings sit at 2-byte-aligned offsets inside the TRACE_EVENT_INFO buffer
        #[allow(clippy::cast_ptr_alignment)]
        let property_name = unsafe {
            // Safety:
            //  * we trust Microsoft for providing correctly aligned data
            //  * we will copy into a String before the buffer gets invalid
            U16CStr::from_ptr_str(property_name_ptr.cast::<u16>())
        };
        Some(property_name.to_string_lossy())
    }

    /// Parses the property at `index`; a structure also pulls in its members,
    /// recursively, from their own entries in EventPropertyInfoArray.
    ///
    /// Returns `None` when the iteration must stop (unreadable entry): this
    /// truncates the property list rather than failing it, as there is no way
    /// to know where the remaining properties would sit in the buffer anyway
    fn parse_property(&self, index: u32) -> Option<Property> {
        let curr_prop = self.property_at(index)?;
        // This should not happen, as there is no reason the Microsoft API has put a
        // null pointer at an index below the property count.
        let property_name = self.property_name(curr_prop)?;

        let flags = PropertyFlags::from(curr_prop.Flags);

        if flags.contains(PropertyFlags::PROPERTY_STRUCT) {
            // Safety: PropertyStruct is set, the union holds a structType
            let struct_type = unsafe { curr_prop.Anonymous1.structType };
            let members =
                self.parse_members(struct_type.StructStartIndex, struct_type.NumOfStructMembers)?;
            // The structure is an array of structures when its element count
            // comes from another property, or is a literal greater than 1
            let count = if flags.contains(PropertyFlags::PROPERTY_PARAM_COUNT) {
                // Safety: PropertyParamCount is set, the union holds countPropertyIndex
                Some(PropertyCount::Index(unsafe {
                    curr_prop.Anonymous2.countPropertyIndex
                }))
            } else {
                // Safety: PropertyParamCount is not set, the union holds the literal count
                let count = unsafe { curr_prop.Anonymous2.count };
                (count > 1).then_some(PropertyCount::Count(count))
            };

            Some(Property {
                name: property_name,
                info: match count {
                    Some(count) => PropertyInfo::StructArray { members, count },
                    None => PropertyInfo::Struct { members },
                },
            })
        } else {
            Some(Property::new(property_name, curr_prop))
        }
    }

    /// Parses the `num` member entries starting at `start` (the member region
    /// of a structure). Trust but verify: the region is clamped to the
    /// property array so bogus struct info cannot read out of bounds.
    fn parse_members(&self, start: u16, num: u16) -> Option<Vec<Property>> {
        let start = u32::from(start).min(self.property_count);
        let end = start
            .saturating_add(u32::from(num))
            .min(self.property_count);
        let mut members = Vec::with_capacity((end - start) as usize);
        for index in start..end {
            members.push(self.parse_property(index)?);
        }
        Some(members)
    }
}

impl Iterator for PropertyIterator<'_> {
    type Item = Property;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_index >= self.top_level_count {
            return None;
        }

        let result = self.parse_property(self.next_index);
        self.next_index += 1;
        result
    }
}

pub fn property_size(event: &EventRecord, name: &str) -> TdhNativeResult<u32> {
    let mut property_size = 0;

    let name = name.into_utf16();
    let desc = Etw::PROPERTY_DATA_DESCRIPTOR {
        ArrayIndex: u32::MAX,
        PropertyName: name.as_ptr() as u64,
        ..Default::default()
    };

    unsafe {
        let status =
            Etw::TdhGetPropertySize(event.as_raw_ptr(), None, &[desc], &raw mut property_size);
        if status != 0 {
            return Err(io_error_from_win32(status));
        }
    }

    Ok(property_size)
}
