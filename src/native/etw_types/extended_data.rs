//! A module to handle Extended Data from ETW traces

use std::{borrow::Cow, convert::TryInto};

use windows::{
    Win32::System::Diagnostics::Etw::{
        EVENT_EXTENDED_ITEM_RELATED_ACTIVITYID, EVENT_EXTENDED_ITEM_TS_ID,
        EVENT_HEADER_EXT_TYPE_CONTAINER_ID, EVENT_HEADER_EXT_TYPE_EVENT_KEY,
        EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL, EVENT_HEADER_EXT_TYPE_INSTANCE_INFO,
        EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY, EVENT_HEADER_EXT_TYPE_PROV_TRAITS,
        EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID, EVENT_HEADER_EXT_TYPE_SID,
        EVENT_HEADER_EXT_TYPE_STACK_TRACE32, EVENT_HEADER_EXT_TYPE_STACK_TRACE64,
        EVENT_HEADER_EXT_TYPE_TS_ID, EVENT_HEADER_EXTENDED_DATA_ITEM,
    },
    core::GUID,
};

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

    /// Builds a `StackTraceItem` from a raw extended data item
    ///
    /// Returns `None` when `item_size` cannot hold the fixed part.
    ///
    /// # Safety
    ///
    /// `item_size` bytes must be readable from `data_ptr`
    unsafe fn from_raw(match_id: u64, data_ptr: *const u8, item_size: usize) -> Option<Self> {
        let addresses_size = item_size.checked_sub(OFFSET_OF_ADDRESS_IN_ITEM)?;
        let array_size = addresses_size / size_of::<Address>();
        let first_address = unsafe {
            // Safety: `item_size` bytes are readable, and the bound check above
            // guarantees `OFFSET_OF_ADDRESS_IN_ITEM <= item_size`
            data_ptr.add(OFFSET_OF_ADDRESS_IN_ITEM).cast::<Address>()
        };
        // The item sits in the packed event buffer, so the addresses are not
        // necessarily aligned: copy them element-wise
        let mut addresses = Vec::with_capacity(array_size);
        for index in 0..array_size {
            // Safety: `array_size * size_of::<Address>()` bytes fit in the
            // readable blob, so `index` addresses to read
            addresses.push(unsafe { first_address.add(index).read_unaligned() });
        }
        Some(Self {
            match_id,
            addresses: addresses.into_boxed_slice(),
        })
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
///
/// Extended data coming from an ETL file is untrusted input: a `Sid` is only
/// built when the item holds the complete SID (`8 + 4 * SubAuthorityCount`
/// bytes), which guarantees the buffer is self-consistent and valid to hand
/// over to SID-related Win32 APIs. Truncated items are dropped (the extended
/// data becomes [`ExtendedDataItem::Unsupported`]).
#[derive(Debug)]
pub struct Sid {
    /// `Revision`, `SubAuthorityCount`, `IdentifierAuthority`, then one
    /// little-endian `u32` per sub-authority. Always exactly
    /// `8 + 4 * SubAuthorityCount` bytes long.
    data: Vec<u8>,
}

impl Sid {
    /// Deep-copies the full variable-length SID starting at `data_ptr`.
    ///
    /// Returns `None` if the item is too short to hold the declared SID
    /// (e.g. `SubAuthorityCount` announces more sub-authorities than
    /// `data_size` can contain): rendering such a truncated SID would either
    /// panic on access or make Win32 read past the copied buffer.
    ///
    /// The copy is bounded by `data_size`, the extended data item's declared size.
    ///
    /// # Safety
    ///
    /// `min(8 + 4 * SubAuthorityCount, data_size)` bytes must be readable from `data_ptr`
    unsafe fn from_raw(data_ptr: *const u8, data_size: u16) -> Option<Self> {
        // The count byte lives at offset 1: anything shorter cannot even hold
        // the fixed-size prefix
        if data_size < 2 {
            return None;
        }
        // Safety: the SID prefix (2 first bytes) is part of the readable data
        let sub_authority_count = unsafe { data_ptr.add(1).read_unaligned() };
        let full_len = 8 + 4 * sub_authority_count as usize;
        if full_len > data_size as usize {
            return None;
        }
        // Safety: forwarded to the caller (data_size bytes are readable)
        let bytes = unsafe { std::slice::from_raw_parts(data_ptr, full_len) };
        Some(Self {
            data: bytes.to_vec(),
        })
    }

    /// The raw SID bytes, as expected by SID-related Win32 APIs taking a `PSID`
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Number of sub-authorities (e.g. 5 for `S-1-5-21-...-...-...-RID`)
    // In-bounds: `from_raw` guarantees the complete SID prefix (8 bytes)
    #[must_use]
    pub fn sub_authority_count(&self) -> u8 {
        self.data[1]
    }

    /// The `index`-th sub-authority (0-based), little-endian
    #[must_use]
    pub fn sub_authority(&self, index: usize) -> Option<u32> {
        if index >= self.sub_authority_count() as usize {
            return None;
        }
        // In-bounds: `from_raw` guarantees `4 * sub_authority_count()` trailing bytes
        let start = 8 + 4 * index;
        Some(u32::from_le_bytes(
            self.data[start..start + 4].try_into().unwrap(),
        ))
    }

    /// Renders this SID into its string form (e.g. `S-1-5-18`)
    pub fn to_sddl_string(&self) -> Result<String, crate::native::SddlNativeError> {
        crate::native::sddl::convert_sid_to_string(self.data.as_ptr().cast())
    }
}

/// A safe representation of an ExtendedDataItem
///
/// See <https://docs.microsoft.com/en-us/windows/win32/api/relogger/ns-relogger-event_header_extended_data_item>
#[derive(Debug)]
pub enum ExtendedDataItem {
    /// Unexpected, invalid (e.g. a declared size smaller than the item's
    /// fixed part: untrusted input is dropped rather than read out of bounds)
    /// or not implemented yet
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
    /// Opaque provider traits data (set through `EventSetInformation(EventProviderSetTraits)`
    /// or `EVENT_DATA_DESCRIPTOR_TYPE_PROVIDER_METADATA`)
    ProvTraits(Vec<u8>),
    /// Identifier of the container (server silo) the event was logged from
    ContainerId(GUID),
    /// Unique event identifier
    EventKey(u64),
    /// Unique process identifier (unique across the boot session)
    ProcessStartKey(u64),
}

impl EventHeaderExtendedDataItem {
    /// Returns the `ExtType` of this extended data.
    ///
    /// See <https://docs.microsoft.com/en-us/windows/win32/api/relogger/ns-relogger-event_header_extended_data_item> for possible values
    #[must_use]
    pub fn data_type(&self) -> u16 {
        self.0.ExtType
    }

    #[must_use]
    pub fn is_tlg(&self) -> bool {
        u32::from(self.0.ExtType) == EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL
    }

    /// Reads a fixed-size value from the start of the item's blob, or `None`
    /// when the declared `DataSize` cannot hold it.
    ///
    /// Extended data coming from an ETL file is untrusted input: an item too
    /// short to hold its value is dropped rather than read out of bounds. The
    /// value is read unaligned, as items are packed at the end of the event
    /// buffer without padding.
    ///
    /// # Safety
    ///
    /// `DataSize` bytes must be readable from `DataPtr`
    unsafe fn read_fixed<T>(&self) -> Option<T> {
        if (self.0.DataSize as usize) < size_of::<T>() {
            return None;
        }
        // Safety: DataPtr is non-null (checked by the caller) and holds at
        // least `size_of::<T>()` bytes per the bound check above
        Some(unsafe { (self.0.DataPtr as *const T).read_unaligned() })
    }

    /// Returns this extended data as a variant of a Rust enum.
    // TODO: revisit this function
    #[must_use]
    pub fn to_extended_data_item(&self) -> ExtendedDataItem {
        let data_ptr = self.0.DataPtr as *const std::ffi::c_void;
        if data_ptr.is_null() {
            return ExtendedDataItem::Unsupported;
        }

        match u32::from(self.0.ExtType) {
            EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID => {
                unsafe { self.read_fixed::<EVENT_EXTENDED_ITEM_RELATED_ACTIVITYID>() }
                    .map_or(ExtendedDataItem::Unsupported, |item| {
                        ExtendedDataItem::RelatedActivityId(item.RelatedActivityId)
                    })
            },

            // A truncated SID (declared count larger than the data) is untrusted
            // input: drop it rather than build a `Sid` that would panic on access
            // or make Win32 read past its buffer
            EVENT_HEADER_EXT_TYPE_SID => {
                let sid = unsafe { Sid::from_raw(data_ptr.cast::<u8>(), self.0.DataSize) };
                sid.map_or(ExtendedDataItem::Unsupported, ExtendedDataItem::Sid)
            },

            EVENT_HEADER_EXT_TYPE_TS_ID => {
                unsafe { self.read_fixed::<EVENT_EXTENDED_ITEM_TS_ID>() }
                    .map_or(ExtendedDataItem::Unsupported, |item| {
                        ExtendedDataItem::TsId(item.SessionId)
                    })
            },

            EVENT_HEADER_EXT_TYPE_INSTANCE_INFO => {
                unsafe { self.read_fixed::<EVENT_EXTENDED_ITEM_INSTANCE>() }.map_or(
                    ExtendedDataItem::Unsupported,
                    ExtendedDataItem::InstanceInfo,
                )
            },

            EVENT_HEADER_EXT_TYPE_STACK_TRACE32 => {
                let Some(match_id) = (unsafe { self.read_fixed::<u64>() }) else {
                    return ExtendedDataItem::Unsupported;
                };
                // Safety: DataSize bytes are readable (read_fixed's contract)
                unsafe {
                    StackTraceItem::from_raw(
                        match_id,
                        data_ptr.cast::<u8>(),
                        self.0.DataSize as usize,
                    )
                }
                .map_or(
                    ExtendedDataItem::Unsupported,
                    ExtendedDataItem::StackTrace32,
                )
            },

            EVENT_HEADER_EXT_TYPE_STACK_TRACE64 => {
                let Some(match_id) = (unsafe { self.read_fixed::<u64>() }) else {
                    return ExtendedDataItem::Unsupported;
                };
                // Safety: DataSize bytes are readable (read_fixed's contract)
                unsafe {
                    StackTraceItem::from_raw(
                        match_id,
                        data_ptr.cast::<u8>(),
                        self.0.DataSize as usize,
                    )
                }
                .map_or(
                    ExtendedDataItem::Unsupported,
                    ExtendedDataItem::StackTrace64,
                )
            },

            EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY => unsafe { self.read_fixed::<u64>() }.map_or(
                ExtendedDataItem::Unsupported,
                ExtendedDataItem::ProcessStartKey,
            ),

            EVENT_HEADER_EXT_TYPE_EVENT_KEY => unsafe { self.read_fixed::<u64>() }
                .map_or(ExtendedDataItem::Unsupported, ExtendedDataItem::EventKey),

            EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL => ExtendedDataItem::TraceLogging(
                unsafe { self.get_event_name() }
                    .unwrap_or_default()
                    .into_owned(),
            ),

            // The traits blob is provider-defined, keep it opaque
            EVENT_HEADER_EXT_TYPE_PROV_TRAITS => {
                let bytes = unsafe {
                    std::slice::from_raw_parts(data_ptr.cast::<u8>(), self.0.DataSize as usize)
                };
                ExtendedDataItem::ProvTraits(bytes.to_vec())
            },

            EVENT_HEADER_EXT_TYPE_CONTAINER_ID => unsafe { self.read_fixed::<GUID>() }
                .map_or(ExtendedDataItem::Unsupported, ExtendedDataItem::ContainerId),

            _ => ExtendedDataItem::Unsupported,
        }
    }

    /// Builds an item from an ext type constant and its raw data blob
    ///
    /// The blob must outlive the returned item (unit tests only)
    #[cfg(test)]
    pub(crate) fn from_raw_parts(ext_type: u32, blob: &[u8]) -> Self {
        // Test inputs use known-small ext types and blobs
        #[allow(clippy::cast_possible_truncation)]
        Self(EVENT_HEADER_EXTENDED_DATA_ITEM {
            ExtType: ext_type as u16,
            DataSize: blob.len() as u16,
            DataPtr: blob.as_ptr() as u64,
            ..Default::default()
        })
    }

    /// Builds an item whose blob starts `offset` bytes into `blob` (unit tests
    /// only: models the unaligned `DataPtr` of packed extended data)
    ///
    /// The blob must outlive the returned item
    #[cfg(test)]
    pub(crate) fn from_raw_parts_at(ext_type: u32, blob: &[u8], offset: usize) -> Self {
        // Test inputs use known-small ext types and blobs
        #[allow(clippy::cast_possible_truncation)]
        Self(EVENT_HEADER_EXTENDED_DATA_ITEM {
            ExtType: ext_type as u16,
            DataSize: (blob.len() - offset) as u16,
            DataPtr: blob[offset..].as_ptr() as u64,
            ..Default::default()
        })
    }

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
    /// The name borrows from the metadata blob whenever it is valid UTF-8
    /// (the common case), so probing a cache with it does not allocate.
    ///
    /// Every read is bounded by the declared sizes: a malformed (e.g. ETL-fed)
    /// blob without a NUL terminator yields `None` instead of an unbounded scan
    /// past the extended data buffer.
    ///
    /// # Safety
    ///
    /// `DataSize` bytes must be readable from `DataPtr`, and the returned string
    /// borrows the metadata blob: it must stay valid and unmodified as long as
    /// the borrow is alive.
    ///
    /// As per the MS header 'This structure may change in future revisions of this header.'
    /// **Keep an eye on it!**
    pub(crate) unsafe fn get_event_name(&self) -> Option<Cow<'_, str>> {
        debug_assert!(self.is_tlg());

        let data_size = self.0.DataSize as usize;
        if self.0.DataPtr == 0 || data_size < size_of::<u16>() {
            return None;
        }
        // Safety: DataPtr is non-null and DataSize bytes are readable
        let blob = unsafe { std::slice::from_raw_parts(self.0.DataPtr as *const u8, data_size) };

        // The size is a u16: read both of its bytes (it used to be read as a
        // single byte, so any metadata >= 256 bytes got a bogus size).
        // The declared size is untrusted input: clamp it to the blob
        let size = u16::from_le_bytes([blob[0], blob[1]]) as usize;
        let size = size.min(data_size);

        // Skip the tags: read until you hit a byte with high bit unset
        let mut tags_end = size_of::<u16>();
        while tags_end < size && blob[tags_end] & 0b1000_0000 != 0 {
            tags_end += 1;
        }
        // The tag chain ran through the whole declared metadata (or there is no
        // room left after it): there cannot be a name in there
        if tags_end >= size {
            return None;
        }

        // The name is NUL-terminated within the declared metadata size: a
        // missing NUL means malformed metadata
        let name = &blob[tags_end + 1..size];
        let name_len = memchr::memchr(0, name)?;
        Some(String::from_utf8_lossy(&name[..name_len]))
    }
}

/// In-memory GUID bytes: little-endian data1/2/3, then data4 as-is
/// (unit tests only)
#[cfg(test)]
pub(crate) fn guid_bytes(guid: GUID) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&guid.data1.to_le_bytes());
    bytes[4..6].copy_from_slice(&guid.data2.to_le_bytes());
    bytes[6..8].copy_from_slice(&guid.data3.to_le_bytes());
    bytes[8..].copy_from_slice(&guid.data4);
    bytes
}

#[cfg(test)]
mod tests {
    use windows::Win32::System::Diagnostics::Etw::{
        EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL, EVENT_HEADER_EXT_TYPE_SID,
    };

    use super::*;

    #[test]
    fn tlg_event_name_is_parsed() {
        // [u16 total size][tag byte][nul-terminated name][field metadata]
        // (the tags section always holds at least one byte: tag 0 encodes as 0x00)
        let name = b"Event1\0";
        let total = u16::try_from(2 + 1 + name.len() + 3).unwrap();
        let mut blob = Vec::with_capacity(usize::from(total));
        blob.extend_from_slice(&total.to_le_bytes());
        blob.push(0x00); // tag = 0
        blob.extend_from_slice(name);
        blob.extend_from_slice(&[0x20, 0x00, 0x00]); // dummy field metadata

        let ExtendedDataItem::TraceLogging(event_name) =
            EventHeaderExtendedDataItem::from_raw_parts(
                EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL,
                &blob,
            )
            .to_extended_data_item()
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
        let total = 256u16;
        let mut blob = Vec::with_capacity(usize::from(total));
        blob.extend_from_slice(&total.to_le_bytes());
        blob.extend_from_slice(&[0x81, 0x02]); // two tag bytes, the second one ends the chain
        blob.extend_from_slice(name);
        blob.resize(usize::from(total), 0xab); // dummy field metadata

        let ExtendedDataItem::TraceLogging(event_name) =
            EventHeaderExtendedDataItem::from_raw_parts(
                EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL,
                &blob,
            )
            .to_extended_data_item()
        else {
            panic!("expected the TraceLogging variant");
        };
        assert_eq!(event_name, "MyEvent");
    }

    /// Parses the event name out of a raw TLG metadata blob (owned result, so
    /// the item does not need to outlive the assertion)
    fn tlg_event_name(blob: &[u8]) -> Option<String> {
        let item = EventHeaderExtendedDataItem::from_raw_parts(
            EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL,
            blob,
        );
        // Safety: the item points at `blob`, which is alive for the whole call
        unsafe { item.get_event_name() }.map(Cow::into_owned)
    }

    #[test]
    fn tlg_event_name_without_nul_is_rejected() {
        // No NUL within the declared metadata size: the old code ran an
        // unbounded `CStr` scan past the blob
        let name = b"Event1"; // missing terminator
        let total = u16::try_from(2 + 1 + name.len()).unwrap();
        let mut blob = Vec::with_capacity(usize::from(total));
        blob.extend_from_slice(&total.to_le_bytes());
        blob.push(0x00); // tag = 0
        blob.extend_from_slice(name);

        assert!(tlg_event_name(&blob).is_none());
    }

    #[test]
    fn tlg_metadata_shorter_than_the_size_field_is_rejected() {
        // Blobs of 0/1 bytes cannot even hold the declared size
        for size in [0usize, 1] {
            let blob = vec![0u8; size];
            assert!(tlg_event_name(&blob).is_none());
        }
    }

    #[test]
    fn tlg_tag_chain_filling_the_declared_size_is_rejected() {
        // No terminating tag byte within the declared size: the old tag loop
        // kept reading up to 2 bytes past the blob before giving up
        let blob = [6u8, 0, 0x81, 0x82, 0x83, 0x84];

        assert!(tlg_event_name(&blob).is_none());
    }

    #[test]
    fn tlg_declared_size_larger_than_the_blob_is_clamped() {
        // Declares 100 bytes of metadata but only 6 are present: parsing must
        // stay within the blob (the name is complete inside it)
        let blob = [100u8, 0, 0x00, b'H', b'i', 0];

        assert_eq!(tlg_event_name(&blob).as_deref(), Some("Hi"));
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
    fn truncated_sid_extended_data_is_dropped() {
        // Declares 3 sub-authorities (20 bytes) but only holds 10: the old code
        // kept the declared count, so `sub_authority(2)` panicked and
        // `to_sddl_string` made Win32 read past the 10-byte buffer
        let bytes = vec![1u8, 3, 0, 0, 0, 0, 0, 5, 21, 0];

        assert!(matches!(
            EventHeaderExtendedDataItem::from_raw_parts(EVENT_HEADER_EXT_TYPE_SID, &bytes)
                .to_extended_data_item(),
            ExtendedDataItem::Unsupported
        ));
    }

    #[test]
    fn sid_shorter_than_the_fixed_prefix_is_dropped() {
        // The old code read the count byte out of bounds when DataSize < 2 and
        // indexed `data[1]` on an empty buffer
        for size in [0usize, 1] {
            let bytes = vec![1u8; size];
            assert!(matches!(
                EventHeaderExtendedDataItem::from_raw_parts(EVENT_HEADER_EXT_TYPE_SID, &bytes)
                    .to_extended_data_item(),
                ExtendedDataItem::Unsupported
            ));
        }
    }

    #[test]
    fn sid_prefix_without_room_for_sub_authorities_is_dropped() {
        // Complete 8-byte prefix declaring a sub-authority it does not hold
        let bytes = vec![1u8, 1, 0, 0, 0, 0, 0, 5];

        assert!(matches!(
            EventHeaderExtendedDataItem::from_raw_parts(EVENT_HEADER_EXT_TYPE_SID, &bytes)
                .to_extended_data_item(),
            ExtendedDataItem::Unsupported
        ));
    }

    #[test]
    fn exactly_sized_sid_is_accepted() {
        // Minimal well-formed SID: the completeness check must not reject it
        let mut bytes = vec![1u8, 1, 0, 0, 0, 0, 0, 5];
        bytes.extend_from_slice(&32u32.to_le_bytes());

        let ExtendedDataItem::Sid(sid) =
            EventHeaderExtendedDataItem::from_raw_parts(EVENT_HEADER_EXT_TYPE_SID, &bytes)
                .to_extended_data_item()
        else {
            panic!("expected the Sid variant");
        };

        assert_eq!(sid.sub_authority_count(), 1);
        assert_eq!(sid.sub_authority(0), Some(32));
        assert_eq!(sid.to_sddl_string().unwrap(), "S-1-5-32");
    }

    #[test]
    fn sid_extended_data_is_deep_copied() {
        let sid_bytes = sample_sid_bytes();

        let ExtendedDataItem::Sid(sid) =
            EventHeaderExtendedDataItem::from_raw_parts(EVENT_HEADER_EXT_TYPE_SID, &sid_bytes)
                .to_extended_data_item()
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

        let ExtendedDataItem::Sid(sid) =
            EventHeaderExtendedDataItem::from_raw_parts(EVENT_HEADER_EXT_TYPE_SID, &sid_bytes)
                .to_extended_data_item()
        else {
            panic!("expected the Sid variant");
        };

        // The (old) shallow copy only captured the fixed-size prefix: trashing
        // the original buffer must not affect our deep copy
        sid_bytes.fill(0xaa);
        assert_eq!(sid.sub_authority(4), Some(999));
    }

    #[test]
    fn prov_traits_blob_is_copied_verbatim() {
        let blob = [1u8, 2, 3, 4];

        let ExtendedDataItem::ProvTraits(bytes) =
            EventHeaderExtendedDataItem::from_raw_parts(EVENT_HEADER_EXT_TYPE_PROV_TRAITS, &blob)
                .to_extended_data_item()
        else {
            panic!("expected the ProvTraits variant");
        };

        assert_eq!(bytes, vec![1, 2, 3, 4]);
    }

    #[test]
    fn container_id_is_parsed() {
        let guid = GUID::from_u128(0x56781234_abcd_4609_0102_030405060708);

        let ExtendedDataItem::ContainerId(container_id) =
            EventHeaderExtendedDataItem::from_raw_parts(
                EVENT_HEADER_EXT_TYPE_CONTAINER_ID,
                &guid_bytes(guid),
            )
            .to_extended_data_item()
        else {
            panic!("expected the ContainerId variant");
        };

        assert_eq!(container_id, guid);
    }

    #[test]
    fn related_activity_id_is_parsed() {
        let guid = GUID::from_u128(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10);

        let ExtendedDataItem::RelatedActivityId(related) =
            EventHeaderExtendedDataItem::from_raw_parts(
                EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID,
                &guid_bytes(guid),
            )
            .to_extended_data_item()
        else {
            panic!("expected the RelatedActivityId variant");
        };

        assert_eq!(related, guid);
    }

    #[test]
    fn ts_id_is_parsed() {
        let blob = 7u32.to_le_bytes().to_vec();

        let ExtendedDataItem::TsId(session_id) =
            EventHeaderExtendedDataItem::from_raw_parts(EVENT_HEADER_EXT_TYPE_TS_ID, &blob)
                .to_extended_data_item()
        else {
            panic!("expected the TsId variant");
        };

        assert_eq!(session_id, 7);
    }

    #[test]
    fn instance_info_is_parsed() {
        let parent = GUID::from_u128(0x00ff_11ee_22dd_33cc_44bb_55aa_6699_7788);
        let mut blob = 42u32.to_le_bytes().to_vec();
        blob.extend_from_slice(&4242u32.to_le_bytes());
        blob.extend_from_slice(&guid_bytes(parent));

        let ExtendedDataItem::InstanceInfo(info) =
            EventHeaderExtendedDataItem::from_raw_parts(EVENT_HEADER_EXT_TYPE_INSTANCE_INFO, &blob)
                .to_extended_data_item()
        else {
            panic!("expected the InstanceInfo variant");
        };

        assert_eq!(info.InstanceId, 42);
        assert_eq!(info.ParentInstanceId, 4242);
        assert_eq!(info.ParentGuid, parent);
    }

    #[test]
    fn event_and_process_start_keys_are_parsed() {
        let blob = 42u64.to_le_bytes().to_vec();
        let item = EventHeaderExtendedDataItem::from_raw_parts;

        let ExtendedDataItem::EventKey(event_key) =
            item(EVENT_HEADER_EXT_TYPE_EVENT_KEY, &blob).to_extended_data_item()
        else {
            panic!("expected the EventKey variant");
        };
        assert_eq!(event_key, 42);

        let ExtendedDataItem::ProcessStartKey(process_start_key) =
            item(EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY, &blob).to_extended_data_item()
        else {
            panic!("expected the ProcessStartKey variant");
        };
        assert_eq!(process_start_key, 42);
    }

    #[test]
    fn stack_trace64_is_parsed() {
        let mut blob = 0x1234_5678_9abc_def0u64.to_le_bytes().to_vec(); // MatchId
        blob.extend_from_slice(&0x1000u64.to_le_bytes());
        blob.extend_from_slice(&0x2000u64.to_le_bytes());

        let ExtendedDataItem::StackTrace64(stack) =
            EventHeaderExtendedDataItem::from_raw_parts(EVENT_HEADER_EXT_TYPE_STACK_TRACE64, &blob)
                .to_extended_data_item()
        else {
            panic!("expected the StackTrace64 variant");
        };

        assert_eq!(stack.match_id(), 0x1234_5678_9abc_def0);
        assert_eq!(stack.addresses(), &[0x1000, 0x2000]);
    }

    #[test]
    fn stack_trace32_is_parsed() {
        let mut blob = 0xa5a5_a5a5_a5a5_a5a5u64.to_le_bytes().to_vec(); // MatchId
        blob.extend_from_slice(&0x10u32.to_le_bytes());
        blob.extend_from_slice(&0x20u32.to_le_bytes());

        let ExtendedDataItem::StackTrace32(stack) =
            EventHeaderExtendedDataItem::from_raw_parts(EVENT_HEADER_EXT_TYPE_STACK_TRACE32, &blob)
                .to_extended_data_item()
        else {
            panic!("expected the StackTrace32 variant");
        };

        assert_eq!(stack.match_id(), 0xa5a5_a5a5_a5a5_a5a5);
        assert_eq!(stack.addresses(), &[0x10, 0x20]);
    }

    #[test]
    fn stack_trace_without_room_for_addresses_is_kept() {
        // A stack trace holding only its MatchId is valid: no addresses yet
        let blob = 7u64.to_le_bytes().to_vec();

        let ExtendedDataItem::StackTrace64(stack) =
            EventHeaderExtendedDataItem::from_raw_parts(EVENT_HEADER_EXT_TYPE_STACK_TRACE64, &blob)
                .to_extended_data_item()
        else {
            panic!("expected the StackTrace64 variant");
        };

        assert_eq!(stack.match_id(), 7);
        assert_eq!(stack.addresses(), &[] as &[u64]);
    }

    #[test]
    fn short_fixed_size_items_are_dropped() {
        // Each item is dropped when its declared size cannot hold the fixed
        // part: the old code dereferenced the data pointer unchecked, reading
        // past the buffer (untrusted input coming from ETL files)
        let cases = [
            (EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID, size_of::<GUID>()),
            (EVENT_HEADER_EXT_TYPE_TS_ID, size_of::<u32>()),
            (
                EVENT_HEADER_EXT_TYPE_INSTANCE_INFO,
                size_of::<EVENT_EXTENDED_ITEM_INSTANCE>(),
            ),
            // Stack traces only need room for their MatchId
            (EVENT_HEADER_EXT_TYPE_STACK_TRACE32, size_of::<u64>()),
            (EVENT_HEADER_EXT_TYPE_STACK_TRACE64, size_of::<u64>()),
            (EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY, size_of::<u64>()),
            (EVENT_HEADER_EXT_TYPE_EVENT_KEY, size_of::<u64>()),
            (EVENT_HEADER_EXT_TYPE_CONTAINER_ID, size_of::<GUID>()),
        ];

        for (ext_type, fixed_size) in cases {
            // The empty buffer, then one byte short of the fixed part
            for size in [0, fixed_size - 1] {
                let blob = vec![0u8; size];
                assert!(
                    matches!(
                        EventHeaderExtendedDataItem::from_raw_parts(ext_type, &blob)
                            .to_extended_data_item(),
                        ExtendedDataItem::Unsupported
                    ),
                    "a {size}-byte item must be dropped"
                );
            }

            // Exactly the fixed part parses (addresses may be empty)
            let blob = vec![0u8; fixed_size];
            assert!(
                !matches!(
                    EventHeaderExtendedDataItem::from_raw_parts(ext_type, &blob)
                        .to_extended_data_item(),
                    ExtendedDataItem::Unsupported
                ),
                "a {fixed_size}-byte item must parse"
            );
        }
    }

    #[test]
    fn unaligned_items_are_read_safely() {
        // Extended data items are packed at the end of the event buffer, so
        // DataPtr can sit at an odd offset (e.g. a GUID following a 4-byte SID)
        let guid = GUID::from_u128(0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00);
        let mut blob = vec![0xaau8]; // forces the odd offset
        blob.extend_from_slice(&guid_bytes(guid));

        let ExtendedDataItem::RelatedActivityId(related) =
            EventHeaderExtendedDataItem::from_raw_parts_at(
                EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID,
                &blob,
                1,
            )
            .to_extended_data_item()
        else {
            panic!("expected the RelatedActivityId variant");
        };
        assert_eq!(related, guid);

        let mut blob = vec![0xaau8];
        blob.extend_from_slice(&42u64.to_le_bytes());

        let ExtendedDataItem::ProcessStartKey(key) =
            EventHeaderExtendedDataItem::from_raw_parts_at(
                EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY,
                &blob,
                1,
            )
            .to_extended_data_item()
        else {
            panic!("expected the ProcessStartKey variant");
        };
        assert_eq!(key, 42);
    }

    #[test]
    fn unaligned_stack_trace_addresses_are_read_safely() {
        let mut blob = vec![0xaau8]; // forces the odd offset
        blob.extend_from_slice(&0x42u64.to_le_bytes()); // MatchId
        blob.extend_from_slice(&0x30u64.to_le_bytes());
        blob.extend_from_slice(&0x40u64.to_le_bytes());

        let ExtendedDataItem::StackTrace64(stack) = EventHeaderExtendedDataItem::from_raw_parts_at(
            EVENT_HEADER_EXT_TYPE_STACK_TRACE64,
            &blob,
            1,
        )
        .to_extended_data_item() else {
            panic!("expected the StackTrace64 variant");
        };

        assert_eq!(stack.match_id(), 0x42);
        assert_eq!(stack.addresses(), &[0x30, 0x40]);
    }
}
