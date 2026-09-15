//! Parsing of `win:SocketAddress` properties (TDH_OUTTYPE_SOCKETADDRESS)
//!
//! ETW stores such a property as a raw [`sockaddr`](https://learn.microsoft.com/en-us/windows/win32/winsock/sockaddr-2)
//! whose actual size depends on the address family. Some providers (e.g.
//! WinINet) append a redundant `sockaddr_storage` copy after it; only the
//! leading `sockaddr` is decoded, the trailing bytes are ignored.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use super::ParserError;

/// `sockaddr` only carries the family at a fixed offset: everything else is
/// family-specific
const FAMILY_LEN: usize = size_of::<u16>();

/// sizeof(sockaddr_in): family, port, IPv4 address, 8 bytes of padding
const SOCKADDR_IN_LEN: usize = 16;

/// sizeof(sockaddr_in6): family, port, flow info, IPv6 address, scope id
const SOCKADDR_IN6_LEN: usize = 28;

/// Winsock address family, from the `sa_family` field of a `sockaddr`
/// (ws2def.h `AF_*` values)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressFamily {
    /// `AF_UNSPEC`
    Unspecified,
    /// `AF_INET` (IPv4)
    Inet,
    /// `AF_INET6` (IPv6)
    Inet6,
    /// Any other family, by its raw `AF_*` value
    Other(u16),
}

impl AddressFamily {
    /// The raw `AF_*` value as stored in the `sockaddr`
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Unspecified => 0,
            Self::Inet => 2,
            Self::Inet6 => 23,
            Self::Other(raw) => raw,
        }
    }

    /// Interprets the `sa_family` field of a `sockaddr` (host byte order)
    const fn from_u16(raw: u16) -> Self {
        match raw {
            0 => Self::Unspecified,
            2 => Self::Inet,
            23 => Self::Inet6,
            other => Self::Other(other),
        }
    }
}

impl std::fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unspecified => write!(f, "AF_UNSPEC"),
            Self::Inet => write!(f, "AF_INET"),
            Self::Inet6 => write!(f, "AF_INET6"),
            // No symbol name is available for exotic families
            Self::Other(raw) => write!(f, "AF_{raw}"),
        }
    }
}

/// An owned, decoded `win:SocketAddress` property
///
/// Only IPv4 and IPv6 socket addresses are decoded (`sa_family`, address and
/// port); anything else keeps the raw bytes as reported by TDH.
///
/// Byte order: `sa_family` is a host-order struct field, while the port,
/// flow info and scope id are stored in network order, as on the wire.
///
/// # Example
/// ```
/// # use ferrisetw::EventRecord;
/// # use ferrisetw::parser::{Parser, TdhSocketAddress};
/// # use ferrisetw::schema_locator::SchemaLocator;
/// let my_callback = |record: &EventRecord, schema_locator: &SchemaLocator| {
///     let schema = schema_locator.event_schema(record).unwrap();
///     let parser = Parser::create(record, &schema);
///     if let Ok(addr) = parser.try_parse::<TdhSocketAddress>("RemoteAddress") {
///         println!("remote endpoint: {addr}");
///     }
/// };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TdhSocketAddress {
    /// IPv4 socket address (address + port)
    Ipv4(SocketAddrV4),
    /// IPv6 socket address (address, port, flow info and scope id)
    Ipv6(SocketAddrV6),
    /// Unrecognized address family (or truncated sockaddr): raw property bytes
    Other { family: AddressFamily, raw: Vec<u8> },
}

impl TdhSocketAddress {
    /// Decodes the leading `sockaddr` of a `win:SocketAddress` property buffer
    pub(super) fn from_property_buffer(buffer: &[u8]) -> Result<Self, ParserError> {
        let Some(family_bytes) = buffer.get(..FAMILY_LEN) else {
            return Err(ParserError::LengthMismatch);
        };
        // Guaranteed by the slice length above
        let family = AddressFamily::from_u16(u16::from_ne_bytes(family_bytes.try_into().unwrap()));

        match family {
            AddressFamily::Inet if buffer.len() >= SOCKADDR_IN_LEN => {
                let port = u16::from_be_bytes(buffer[2..4].try_into().unwrap());
                let ip = Ipv4Addr::new(buffer[4], buffer[5], buffer[6], buffer[7]);
                Ok(Self::Ipv4(SocketAddrV4::new(ip, port)))
            },
            AddressFamily::Inet6 if buffer.len() >= SOCKADDR_IN6_LEN => {
                let port = u16::from_be_bytes(buffer[2..4].try_into().unwrap());
                let flow_info = u32::from_be_bytes(buffer[4..8].try_into().unwrap());
                let ip_bytes: [u8; 16] = buffer[8..24].try_into().unwrap();
                let scope_id = u32::from_be_bytes(buffer[24..28].try_into().unwrap());
                Ok(Self::Ipv6(SocketAddrV6::new(
                    Ipv6Addr::from(ip_bytes),
                    port,
                    flow_info,
                    scope_id,
                )))
            },
            // Be liberal: unsupported families and truncated sockaddrs keep
            // their raw bytes instead of failing the whole event parsing
            _ => Ok(Self::Other {
                family,
                raw: buffer.to_vec(),
            }),
        }
    }

    /// The address family of the underlying `sockaddr`
    #[must_use]
    pub const fn family(&self) -> AddressFamily {
        match self {
            Self::Ipv4(_) => AddressFamily::Inet,
            Self::Ipv6(_) => AddressFamily::Inet6,
            Self::Other { family, .. } => *family,
        }
    }

    /// The socket address, when the family is IPv4 or IPv6
    #[must_use]
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Ipv4(addr) => Some(SocketAddr::V4(*addr)),
            Self::Ipv6(addr) => Some(SocketAddr::V6(*addr)),
            Self::Other { .. } => None,
        }
    }

    /// The IP address, when the family is IPv4 or IPv6
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        self.socket_addr().map(|addr| addr.ip())
    }

    /// The port, when the family is IPv4 or IPv6
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.socket_addr().map(|addr| addr.port())
    }
}

impl std::fmt::Display for TdhSocketAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4(addr) => write!(f, "{addr}"),
            Self::Ipv6(addr) => write!(f, "{addr}"),
            Self::Other { family, raw } => write!(f, "{} ({} bytes)", family, raw.len()),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::ser::Serialize for TdhSocketAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        // A socket address has no compact serde representation: always use the
        // canonical "ip:port" (or family) text form
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// sockaddr_in: AF_INET, port 0x0050 (80), address 127.0.0.1
    fn sockaddr_in() -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&2u16.to_ne_bytes()); // family
        buffer.extend_from_slice(&80u16.to_be_bytes()); // port, network order
        buffer.extend_from_slice(&[127, 0, 0, 1]); // address
        buffer.resize(SOCKADDR_IN_LEN, 0); // sin_zero padding
        buffer
    }

    /// sockaddr_in6: AF_INET6, port 443, flow info 1, address ::1, scope id 7
    fn sockaddr_in6() -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&23u16.to_ne_bytes()); // family
        buffer.extend_from_slice(&443u16.to_be_bytes()); // port, network order
        buffer.extend_from_slice(&1u32.to_be_bytes()); // flow info
        buffer.extend([0u8; 15]); // ::1
        buffer.push(1);
        buffer.extend_from_slice(&7u32.to_be_bytes()); // scope id
        buffer
    }

    #[test]
    fn ipv4_sockaddr_decodes() {
        let addr = TdhSocketAddress::from_property_buffer(&sockaddr_in()).unwrap();
        assert_eq!(
            addr,
            TdhSocketAddress::Ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80))
        );
        assert_eq!(addr.family(), AddressFamily::Inet);
        assert_eq!(addr.socket_addr(), Some("127.0.0.1:80".parse().unwrap()));
        assert_eq!(addr.to_string(), "127.0.0.1:80");
    }

    #[test]
    fn ipv6_sockaddr_decodes() {
        let addr = TdhSocketAddress::from_property_buffer(&sockaddr_in6()).unwrap();
        let SocketAddr::V6(v6) = addr.socket_addr().unwrap() else {
            panic!("expected an IPv6 address");
        };
        assert_eq!(v6.ip(), &Ipv6Addr::LOCALHOST);
        assert_eq!(v6.port(), 443);
        assert_eq!(v6.flowinfo(), 1);
        assert_eq!(v6.scope_id(), 7);
        assert_eq!(addr.to_string(), "[::1%7]:443");
    }

    #[test]
    fn trailing_sockaddr_storage_is_ignored() {
        // Some providers (e.g. WinINet) append a sockaddr_storage copy after
        // the sockaddr: only the leading sockaddr is decoded
        let mut buffer = sockaddr_in6();
        buffer.resize(SOCKADDR_IN6_LEN + 128, 0xaa);
        let addr = TdhSocketAddress::from_property_buffer(&buffer).unwrap();
        assert!(matches!(addr, TdhSocketAddress::Ipv6(_)));
    }

    #[test]
    fn unsupported_family_and_short_buffers_keep_raw_bytes() {
        let raw = sockaddr_in();
        let mut other_family = raw.clone();
        other_family[0..2].copy_from_slice(&34u16.to_ne_bytes()); // AF_HYPERV
        let addr = TdhSocketAddress::from_property_buffer(&other_family).unwrap();
        assert_eq!(addr, TdhSocketAddress::Other {
            family: AddressFamily::Other(34),
            raw: other_family.clone(),
        });
        assert_eq!(addr.family(), AddressFamily::Other(34));
        assert_eq!(addr.socket_addr(), None);

        // A recognized family with a truncated sockaddr is kept raw as well
        let truncated = &raw[..8];
        let addr = TdhSocketAddress::from_property_buffer(truncated).unwrap();
        assert_eq!(addr, TdhSocketAddress::Other {
            family: AddressFamily::Inet,
            raw: truncated.to_vec(),
        });
    }

    #[test]
    fn buffer_without_family_is_rejected() {
        assert!(TdhSocketAddress::from_property_buffer(&[0]).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serializes_as_display_string() {
        let addr = TdhSocketAddress::from_property_buffer(&sockaddr_in()).unwrap();
        assert_eq!(
            serde_json::to_value(addr).unwrap(),
            serde_json::Value::String("127.0.0.1:80".into())
        );
    }
}
