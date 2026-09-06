//! A module to handle Extended Data from ETW traces

use std::{convert::TryInto, ffi::CStr, mem};
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_EXTENDED_ITEM_RELATED_ACTIVITYID, EVENT_EXTENDED_ITEM_TS_ID,
};
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_HEADER_EXT_TYPE_EVENT_KEY, EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL,
    EVENT_HEADER_EXT_TYPE_INSTANCE_INFO, EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY,
    EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID, EVENT_HEADER_EXT_TYPE_SID,
    EVENT_HEADER_EXT_TYPE_STACK_TRACE32, EVENT_HEADER_EXT_TYPE_STACK_TRACE64,
    EVENT_HEADER_EXT_TYPE_TS_ID, EVENT_HEADER_EXTENDED_DATA_ITEM,
};
use windows::core::GUID;

// These types are returned by our public API. Let's use their re-exported versions
use crate::native::{
    EVENT_EXTENDED_ITEM_INSTANCE, EVENT_EXTENDED_ITEM_STACK_TRACE32,
    EVENT_EXTENDED_ITEM_STACK_TRACE64,
};

const OFFSET_OF_ADDRESS_IN_ITEM: usize = offset_of!(EVENT_EXTENDED_ITEM_STACK_TRACE64, Address);
const _: () =
    assert!(OFFSET_OF_ADDRESS_IN_ITEM == offset_of!(EVENT_EXTENDED_ITEM_STACK_TRACE32, Address));

/// A fixed-size representation of EVENT_EXTENDED_ITEM_STACK_TRACE32 (if Address is u32)
///                            and EVENT_EXTENDED_ITEM_STACK_TRACE64 (if Address is u64)
///
/// See <https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_extended_item_stack_trace32>
/// See <https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_extended_item_stack_trace64>
#[derive(Debug)]
pub struct StackTraceItem<Address>
where
    Address: Copy,
{
    match_id: u64,
    addresses: Box<[Address]>,
}

impl<Address> StackTraceItem<Address>
where
    Address: Copy,
{
    /// Accessor for the MatchId field
    pub fn match_id(&self) -> u64 {
        self.match_id
    }

    /// Accessor for the ANYSIZE_ARRAY Address field
    pub fn addresses(&self) -> &[Address] {
        self.addresses.as_ref()
    }

    unsafe fn from_raw(
        match_id: u64,
        first_address: *const Address,
        item_size: usize,
    ) -> StackTraceItem<Address> {
        let array_size_in_bytes = item_size.saturating_sub(OFFSET_OF_ADDRESS_IN_ITEM);
        let array_size = array_size_in_bytes / core::mem::size_of::<Address>();
        let addresses = unsafe { std::slice::from_raw_parts(first_address, array_size) }.into();
        StackTraceItem {
            match_id,
            addresses,
        }
    }
}

/// A wrapper over [`windows::Win32::System::Diagnostics::Etw::EVENT_HEADER_EXTENDED_DATA_ITEM`]
#[repr(transparent)]
pub struct EventHeaderExtendedDataItem(EVENT_HEADER_EXTENDED_DATA_ITEM);

/// An owned security identifier (SID), deep-copied from an event's extended data.
///
/// The windows `SID` type is only the fixed-size prefix of a variable-length
/// structure (its `SubAuthority` array holds a single element): copying it by
/// value would lose every sub-authority but the first, and any later use
/// (e.g. by `ConvertSidToStringSid`) would read out of bounds. `Sid` owns the
/// full buffer instead.
#[derive(Debug)]
pub struct Sid {
    /// `Revision`, `SubAuthorityCount`, `IdentifierAuthority`, then one
    /// little-endian `u32` per sub-authority
    data: Vec<u8>,
}

impl Sid {
    /// Deep-copies the full variable-length SID starting at `data_ptr`.
    ///
    /// The copy is bounded by `data_size`, the extended data item's declared size.
    ///
    /// # Safety
    ///
    /// `min(8 + 4 * SubAuthorityCount, data_size)` bytes must be readable from `data_ptr`
    unsafe fn from_raw(data_ptr: *const u8, data_size: u16) -> Self {
        // Safety: the SID prefix (2 first bytes) is part of the readable data
        let sub_authority_count = unsafe { data_ptr.add(1).read_unaligned() };
        let full_len = 8 + 4 * sub_authority_count as usize;
        let len = full_len.min(data_size as usize);
        // Safety: forwarded to the caller (at most data_size bytes are read)
        let bytes = unsafe { std::slice::from_raw_parts(data_ptr, len) };
        Self {
            data: bytes.to_vec(),
        }
    }

    /// The raw SID bytes, as expected by SID-related Win32 APIs taking a `PSID`
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Number of sub-authorities (e.g. 5 for `S-1-5-21-...-...-...-RID`)
    pub fn sub_authority_count(&self) -> u8 {
        self.data[1]
    }

    /// The `index`-th sub-authority (0-based), little-endian
    pub fn sub_authority(&self, index: usize) -> Option<u32> {
        if index >= self.sub_authority_count() as usize {
            return None;
        }
        let start = 8 + 4 * index;
        Some(u32::from_le_bytes(
            self.data[start..start + 4].try_into().unwrap(),
        ))
    }

    /// Renders this SID into its string form (e.g. `S-1-5-18`)
    pub fn to_sddl_string(&self) -> Result<String, crate::native::SddlNativeError> {
        crate::native::sddl::convert_sid_to_string(self.data.as_ptr() as *const _)
    }
}

/// A safe representation of an ExtendedDataItem
///
/// See <https://docs.microsoft.com/en-us/windows/win32/api/relogger/ns-relogger-event_header_extended_data_item>
#[derive(Debug)]
pub enum ExtendedDataItem {
    /// Unexpected, invalid or not implemented yet
    Unsupported,
    /// Related activity identifier
    RelatedActivityId(GUID),
    /// Security identifier (SID) of the user that logged the event
    Sid(Sid),
    /// Terminal session identifier
    TsId(u32),
    InstanceInfo(EVENT_EXTENDED_ITEM_INSTANCE),
    /// Call stack (if the event is captured on a 32-bit computer)
    StackTrace32(StackTraceItem<u32>),
    /// Call stack (if the event is captured on a 64-bit computer)
    StackTrace64(StackTraceItem<u64>),
    /// TraceLogging event metadata information
    TraceLogging(String),
    // /// Provider traits data
    // /// (for example traits set through EventSetInformation(EventProviderSetTraits) or specified through EVENT_DATA_DESCRIPTOR_TYPE_PROVIDER_METADATA)
    // ProvTraits,
    /// Unique event identifier
    EventKey(u64),
    /// Unique process identifier (unique across the boot session)
    ProcessStartKey(u64),
}

impl EventHeaderExtendedDataItem {
    /// Returns the `ExtType` of this extended data.
    ///
    /// See <https://docs.microsoft.com/en-us/windows/win32/api/relogger/ns-relogger-event_header_extended_data_item> for possible values
    pub fn data_type(&self) -> u16 {
        self.0.ExtType
    }

    pub fn is_tlg(&self) -> bool {
        self.0.ExtType as u32 == EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL
    }

    /// Returns this extended data as a variant of a Rust enum.
    // TODO: revisit this function
    pub fn to_extended_data_item(&self) -> ExtendedDataItem {
        let data_ptr = self.0.DataPtr as *const std::ffi::c_void;
        if data_ptr.is_null() {
            return ExtendedDataItem::Unsupported;
        }

        match self.0.ExtType as u32 {
            EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID => {
                let data_ptr = data_ptr as *const EVENT_EXTENDED_ITEM_RELATED_ACTIVITYID;
                ExtendedDataItem::RelatedActivityId(unsafe { *data_ptr }.RelatedActivityId)
            }

            EVENT_HEADER_EXT_TYPE_SID => ExtendedDataItem::Sid(unsafe {
                Sid::from_raw(data_ptr as *const u8, self.0.DataSize)
            }),

            EVENT_HEADER_EXT_TYPE_TS_ID => {
                let data_ptr = data_ptr as *const EVENT_EXTENDED_ITEM_TS_ID;
                ExtendedDataItem::TsId(unsafe { *data_ptr }.SessionId)
            }

            EVENT_HEADER_EXT_TYPE_INSTANCE_INFO => {
                let data_ptr = data_ptr as *const EVENT_EXTENDED_ITEM_INSTANCE;
                ExtendedDataItem::InstanceInfo(unsafe { *data_ptr })
            }

            EVENT_HEADER_EXT_TYPE_STACK_TRACE32 => {
                let data_ptr = data_ptr as *const EVENT_EXTENDED_ITEM_STACK_TRACE32;
                ExtendedDataItem::StackTrace32(unsafe {
                    let match_id = (*data_ptr).MatchId;
                    let first_address = &(*data_ptr).Address[0] as *const _;
                    let item_size = self.0.DataSize as usize;
                    StackTraceItem::from_raw(match_id, first_address, item_size)
                })
            }

            EVENT_HEADER_EXT_TYPE_STACK_TRACE64 => {
                let data_ptr = data_ptr as *const EVENT_EXTENDED_ITEM_STACK_TRACE64;
                ExtendedDataItem::StackTrace64(unsafe {
                    let match_id = (*data_ptr).MatchId;
                    let first_address = &(*data_ptr).Address[0] as *const _;
                    let item_size = self.0.DataSize as usize;
                    StackTraceItem::from_raw(match_id, first_address, item_size)
                })
            }

            EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY => {
                let data_ptr = data_ptr as *const u64;
                ExtendedDataItem::ProcessStartKey(unsafe { *data_ptr })
            }

            EVENT_HEADER_EXT_TYPE_EVENT_KEY => {
                let data_ptr = data_ptr as *const u64;
                ExtendedDataItem::EventKey(unsafe { *data_ptr })
            }

            EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL => {
                ExtendedDataItem::TraceLogging(unsafe { self.get_event_name().unwrap_or_default() })
            }

            _ => ExtendedDataItem::Unsupported,
        }
    }

    ///
    /// This function will parse the event metadata of a TraceLogging event to
    /// retrieve the EventName.
    ///
    /// The metadata blob (as generated by `TraceLoggingProvider.h` and the
    /// `tracelogging` crate) is laid out as follows:
    ///
    /// ```cpp
    /// UINT16 TotalSize;  // = sizeof(TotalSize + Tags + EventName + Fields)
    /// UINT8 Tags[];      // 0 or more bytes. Read until you hit a byte with high bit unset.
    /// char EventName[];  // UTF-8 nul-terminated event name
    /// // then, for each field: name, InType/OutType, tags, etc. (not parsed here)
    /// ```
    ///
    /// For more info see `_tlgEventMetadata_t` in `TraceLoggingProvider.h` (Windows SDK).
    ///
    /// We are only interested in `EventName`, so we skip `TotalSize` and `Tags`.
    ///
    /// # Safety
    ///
    /// As per the MS header 'This structure may change in future revisions of this header.'
    /// **Keep an eye on it!**
    ///
    // TODO: Make this function more robust
    unsafe fn get_event_name(&self) -> Option<String> {
        const TAGS_SIZE: usize = 1;
        debug_assert!(self.is_tlg());

        let mut data_ptr = self.0.DataPtr as *const u8;
        if data_ptr.is_null() {
            return None;
        }

        // The size is a u16: read both of its bytes (it used to be read as a
        // single byte, so any metadata >= 256 bytes got a bogus size)
        // Safety: reading the 2 first bytes of the extended data item
        let size = unsafe { (data_ptr as *const u16).read_unaligned() }.min(self.0.DataSize);
        data_ptr = unsafe { data_ptr.add(mem::size_of::<u16>()) };

        let mut n = 0;
        while n < size {
            // Read until you hit a byte with high bit unset.
            let tag = unsafe { data_ptr.read_unaligned() };
            data_ptr = unsafe { data_ptr.add(TAGS_SIZE) };

            if tag & 0b1000_0000 == 0 {
                break;
            }

            n += 1;
        }

        // If debug let's assert here since this is a case we want to investigate
        debug_assert!(n != size);
        if n == size {
            return None;
        }

        Some(String::from(
            unsafe {
                // Safety: same extended data item, the name follows the tags
                CStr::from_ptr(data_ptr as *const _)
            }
            .to_string_lossy(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Diagnostics::Etw::{
        EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL, EVENT_HEADER_EXT_TYPE_SID,
    };

    fn item_with_data(ext_type: u32, blob: &[u8]) -> EventHeaderExtendedDataItem {
        EventHeaderExtendedDataItem(EVENT_HEADER_EXTENDED_DATA_ITEM {
            ExtType: ext_type as u16,
            DataSize: blob.len() as u16,
            DataPtr: blob.as_ptr() as u64,
            ..Default::default()
        })
    }

    #[test]
    fn tlg_event_name_is_parsed() {
        // [u16 total size][tag byte][nul-terminated name][field metadata]
        // (the tags section always holds at least one byte: tag 0 encodes as 0x00)
        let name = b"Event1\0";
        let total = 2 + 1 + name.len() + 3;
        let mut blob = Vec::with_capacity(total);
        blob.extend_from_slice(&(total as u16).to_le_bytes());
        blob.push(0x00); // tag = 0
        blob.extend_from_slice(name);
        blob.extend_from_slice(&[0x20, 0x00, 0x00]); // dummy field metadata

        let ExtendedDataItem::TraceLogging(event_name) =
            item_with_data(EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL, &blob).to_extended_data_item()
        else {
            panic!("expected the TraceLogging variant");
        };
        assert_eq!(event_name, "Event1");
    }

    #[test]
    fn tlg_event_name_with_tags_and_metadata_over_255_bytes() {
        // Total size of 256: its low byte is 0, which the (buggy) single-byte
        // size read mistook for an empty metadata, failing to parse the name
        let name = b"MyEvent\0";
        let total = 256usize;
        let mut blob = Vec::with_capacity(total);
        blob.extend_from_slice(&(total as u16).to_le_bytes());
        blob.extend_from_slice(&[0x81, 0x02]); // two tag bytes, the second one ends the chain
        blob.extend_from_slice(name);
        blob.resize(total, 0xab); // dummy field metadata

        let ExtendedDataItem::TraceLogging(event_name) =
            item_with_data(EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL, &blob).to_extended_data_item()
        else {
            panic!("expected the TraceLogging variant");
        };
        assert_eq!(event_name, "MyEvent");
    }

    /// Builds S-1-5-21-100-200-300-999: 5 sub-authorities (i.e. longer than the
    /// single one windows' `SID` prefix type can hold)
    fn sample_sid_bytes() -> Vec<u8> {
        let mut bytes = vec![1u8, 5, 0, 0, 0, 0, 0, 5]; // revision, count, identifier authority
        for sub_authority in [21u32, 100, 200, 300, 999] {
            bytes.extend_from_slice(&sub_authority.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn sid_extended_data_is_deep_copied() {
        let sid_bytes = sample_sid_bytes();

        let item = EVENT_HEADER_EXTENDED_DATA_ITEM {
            ExtType: EVENT_HEADER_EXT_TYPE_SID as u16,
            DataSize: sid_bytes.len() as u16,
            DataPtr: sid_bytes.as_ptr() as u64,
            ..Default::default()
        };

        let ExtendedDataItem::Sid(sid) = EventHeaderExtendedDataItem(item).to_extended_data_item()
        else {
            panic!("expected the Sid variant");
        };

        assert_eq!(sid.as_bytes(), &sid_bytes[..]);
        assert_eq!(sid.sub_authority_count(), 5);
        assert_eq!(sid.sub_authority(0), Some(21));
        assert_eq!(sid.sub_authority(4), Some(999));
        assert_eq!(sid.sub_authority(5), None);
        assert_eq!(sid.to_sddl_string().unwrap(), "S-1-5-21-100-200-300-999");
    }

    #[test]
    fn sid_copy_survives_the_original_buffer() {
        let mut sid_bytes = sample_sid_bytes();

        let item = EVENT_HEADER_EXTENDED_DATA_ITEM {
            ExtType: EVENT_HEADER_EXT_TYPE_SID as u16,
            DataSize: sid_bytes.len() as u16,
            DataPtr: sid_bytes.as_ptr() as u64,
            ..Default::default()
        };
        let ExtendedDataItem::Sid(sid) = EventHeaderExtendedDataItem(item).to_extended_data_item()
        else {
            panic!("expected the Sid variant");
        };

        // The (old) shallow copy only captured the fixed-size prefix: trashing
        // the original buffer must not affect our deep copy
        sid_bytes.iter_mut().for_each(|byte| *byte = 0xaa);
        assert_eq!(sid.sub_authority(4), Some(999));
    }
}
