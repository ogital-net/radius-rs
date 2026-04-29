use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, Bytes, BytesMut};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::core::crypto;
use crate::core::tag::{Tag, UNUSED_TAG_VALUE};

#[derive(Error, PartialEq, Debug)]
pub enum AVPError {
    /// This error is raised on the length of given plain text for user-password exceeds the maximum limit.
    #[error("the maximum length of the plain text for user-password is 128, but the given value has {0} bytes")]
    UserPasswordPlainTextMaximumLengthExceededError(usize),

    /// This error is raised when the given secret value for a password is empty.
    #[error("secret for password mustn't be empty, but the given value is empty")]
    PasswordSecretMissingError(),

    /// This error is raised when the given request-authenticator for the password doesn't have 16 bytes length exactly.
    #[error("request authenticator for password has to have 16-bytes payload, but the given value doesn't")]
    InvalidRequestAuthenticatorLengthError(),

    /// This error is raised when attribute length is conflicted with the expected.
    #[error("invalid attribute length: expected={0}, actual={1} bytes")]
    InvalidAttributeLengthError(String, usize),

    /// This error is raised when the tagged-value doesn't have a tag byte.
    #[error("tag value is missing")]
    TagMissingError(),

    /// This error represents AVP decoding error.
    #[error("decoding error: {0}")]
    DecodingError(String),

    /// This error is raised when the MSB of salt is invalid.
    #[error("invalid salt. the MSB has to be 1, but given value isn't: {0}")]
    InvalidSaltMSBError(u8),

    /// This error is raised when a tag is invalid for the tagged-staring value.
    #[error("invalid tag for string value. this must not be zero")]
    InvalidTagForStringValueError(),

    /// This error is raised when a tag is invalid for the tagged-integer value.
    #[error("invalid tag for integer value. this must be less than or equal 0x1f")]
    InvalidTagForIntegerValueError(),
}

pub type AVPType = u8;

pub const TYPE_INVALID: AVPType = 255;
/// The RADIUS Vendor-Specific attribute type (RFC 2865 §5.26).
pub const VENDOR_SPECIFIC_TYPE: AVPType = 26;

/// An attribute-value pair (AVP) from a RADIUS packet.
///
/// Each AVP consists of a 1-byte type identifier and a variable-length value.
/// The helper constructors (`from_string`, `from_u32`, etc.) and decoders
/// (`encode_string`, `encode_u32`, etc.) handle all type conversions.
///
/// # Example
///
/// ```
/// use radius::core::avp::AVP;
///
/// // Build an AVP for User-Name (type 1) and round-trip it.
/// let avp = AVP::from_string(1, "alice");
/// assert_eq!(avp.encode_string().unwrap(), "alice");
///
/// // IPv4 address AVP.
/// use std::net::Ipv4Addr;
/// let avp = AVP::from_ipv4(4, &Ipv4Addr::new(192, 168, 1, 1));
/// assert_eq!(avp.encode_ipv4().unwrap(), Ipv4Addr::new(192, 168, 1, 1));
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AVP {
    /// Full RADIUS wire encoding: `[type(1), length(1), value...]`
    pub(crate) raw: Bytes,
}

/// Wire encoding kind for a known RFC 2865 attribute, used only for Debug formatting.
#[derive(Clone, Copy)]
enum Rfc2865Kind {
    String,
    Encrypted,
    Octets,
    IpAddr,
    Integer,
    NamedInteger(&'static [(u32, &'static str)]),
}

const SERVICE_TYPE_NAMES: &[(u32, &str)] = &[
    (1, "Login-User"),
    (2, "Framed-User"),
    (3, "Callback-Login-User"),
    (4, "Callback-Framed-User"),
    (5, "Outbound-User"),
    (6, "Administrative-User"),
    (7, "NAS-Prompt-User"),
    (8, "Authenticate-Only"),
    (9, "Callback-NAS-Prompt"),
    (10, "Call-Check"),
    (11, "Callback-Administrative"),
];

const FRAMED_PROTOCOL_NAMES: &[(u32, &str)] = &[
    (1, "PPP"),
    (2, "SLIP"),
    (3, "ARAP"),
    (4, "Gandalf-SLML"),
    (5, "Xylogics-IPX-SLIP"),
    (6, "X.75-Synchronous"),
];

const FRAMED_ROUTING_NAMES: &[(u32, &str)] = &[
    (0, "None"),
    (1, "Broadcast"),
    (2, "Listen"),
    (3, "Broadcast-Listen"),
];

const FRAMED_COMPRESSION_NAMES: &[(u32, &str)] = &[
    (0, "None"),
    (1, "Van-Jacobson-TCP-IP"),
    (2, "IPX-Header-Compression"),
    (3, "Stac-LZS"),
];

const LOGIN_SERVICE_NAMES: &[(u32, &str)] = &[
    (0, "Telnet"),
    (1, "Rlogin"),
    (2, "TCP-Clear"),
    (3, "PortMaster"),
    (4, "LAT"),
    (5, "X25-PAD"),
    (6, "X25-T3POS"),
    (8, "TCP-Clear-Quiet"),
];

const LOGIN_TCP_PORT_NAMES: &[(u32, &str)] = &[(23, "Telnet"), (513, "Rlogin"), (514, "Rsh")];

const TERMINATION_ACTION_NAMES: &[(u32, &str)] = &[(0, "Default"), (1, "RADIUS-Request")];

const NAS_PORT_TYPE_NAMES: &[(u32, &str)] = &[
    (0, "Async"),
    (1, "Sync"),
    (2, "ISDN"),
    (3, "ISDN-V120"),
    (4, "ISDN-V110"),
    (5, "Virtual"),
    (6, "PIAFS"),
    (7, "HDLC-Clear-Channel"),
    (8, "X.25"),
    (9, "X.75"),
    (10, "G.3-Fax"),
    (11, "SDSL"),
    (12, "ADSL-CAP"),
    (13, "ADSL-DMT"),
    (14, "IDSL"),
    (15, "Ethernet"),
    (16, "xDSL"),
    (17, "Cable"),
    (18, "Wireless-Other"),
    (19, "Wireless-802.11"),
];

fn rfc2865_attr_info(typ: AVPType) -> Option<(&'static str, Rfc2865Kind)> {
    match typ {
        1 => Some(("User-Name", Rfc2865Kind::String)),
        2 => Some(("User-Password", Rfc2865Kind::Encrypted)),
        3 => Some(("CHAP-Password", Rfc2865Kind::Octets)),
        4 => Some(("NAS-IP-Address", Rfc2865Kind::IpAddr)),
        5 => Some(("NAS-Port", Rfc2865Kind::Integer)),
        6 => Some((
            "Service-Type",
            Rfc2865Kind::NamedInteger(SERVICE_TYPE_NAMES),
        )),
        7 => Some((
            "Framed-Protocol",
            Rfc2865Kind::NamedInteger(FRAMED_PROTOCOL_NAMES),
        )),
        8 => Some(("Framed-IP-Address", Rfc2865Kind::IpAddr)),
        9 => Some(("Framed-IP-Netmask", Rfc2865Kind::IpAddr)),
        10 => Some((
            "Framed-Routing",
            Rfc2865Kind::NamedInteger(FRAMED_ROUTING_NAMES),
        )),
        11 => Some(("Filter-Id", Rfc2865Kind::String)),
        12 => Some(("Framed-MTU", Rfc2865Kind::Integer)),
        13 => Some((
            "Framed-Compression",
            Rfc2865Kind::NamedInteger(FRAMED_COMPRESSION_NAMES),
        )),
        14 => Some(("Login-IP-Host", Rfc2865Kind::IpAddr)),
        15 => Some((
            "Login-Service",
            Rfc2865Kind::NamedInteger(LOGIN_SERVICE_NAMES),
        )),
        16 => Some((
            "Login-TCP-Port",
            Rfc2865Kind::NamedInteger(LOGIN_TCP_PORT_NAMES),
        )),
        18 => Some(("Reply-Message", Rfc2865Kind::String)),
        19 => Some(("Callback-Number", Rfc2865Kind::String)),
        20 => Some(("Callback-Id", Rfc2865Kind::String)),
        22 => Some(("Framed-Route", Rfc2865Kind::String)),
        23 => Some(("Framed-IPX-Network", Rfc2865Kind::IpAddr)),
        24 => Some(("State", Rfc2865Kind::Octets)),
        25 => Some(("Class", Rfc2865Kind::Octets)),
        26 => Some(("Vendor-Specific", Rfc2865Kind::Octets)),
        27 => Some(("Session-Timeout", Rfc2865Kind::Integer)),
        28 => Some(("Idle-Timeout", Rfc2865Kind::Integer)),
        29 => Some((
            "Termination-Action",
            Rfc2865Kind::NamedInteger(TERMINATION_ACTION_NAMES),
        )),
        30 => Some(("Called-Station-Id", Rfc2865Kind::String)),
        31 => Some(("Calling-Station-Id", Rfc2865Kind::String)),
        32 => Some(("NAS-Identifier", Rfc2865Kind::String)),
        33 => Some(("Proxy-State", Rfc2865Kind::Octets)),
        34 => Some(("Login-LAT-Service", Rfc2865Kind::String)),
        35 => Some(("Login-LAT-Node", Rfc2865Kind::String)),
        36 => Some(("Login-LAT-Group", Rfc2865Kind::Octets)),
        37 => Some(("Framed-AppleTalk-Link", Rfc2865Kind::Integer)),
        38 => Some(("Framed-AppleTalk-Network", Rfc2865Kind::Integer)),
        39 => Some(("Framed-AppleTalk-Zone", Rfc2865Kind::String)),
        60 => Some(("CHAP-Challenge", Rfc2865Kind::Octets)),
        61 => Some((
            "NAS-Port-Type",
            Rfc2865Kind::NamedInteger(NAS_PORT_TYPE_NAMES),
        )),
        62 => Some(("Port-Limit", Rfc2865Kind::Integer)),
        63 => Some(("Login-LAT-Port", Rfc2865Kind::String)),
        _ => None,
    }
}

impl std::fmt::Debug for AVP {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn hex(data: &[u8]) -> String {
            use std::fmt::Write as _;
            data.iter()
                .fold(String::with_capacity(data.len() * 2), |mut s, b| {
                    write!(s, "{b:02x}").unwrap();
                    s
                })
        }

        let (type_label, value_label) = match rfc2865_attr_info(self.typ()) {
            Some((name, kind)) => {
                let type_str = format!("{name} ({})", self.typ());
                let value = self.value();
                let value_str = match kind {
                    Rfc2865Kind::String => match std::str::from_utf8(value) {
                        Ok(s) => format!("{s:?}"),
                        Err(_) => hex(value),
                    },
                    Rfc2865Kind::Encrypted => {
                        format!("<encrypted, {} bytes>", value.len())
                    }
                    Rfc2865Kind::Octets => hex(value),
                    Rfc2865Kind::IpAddr => {
                        if let Ok(arr) = <[u8; 4]>::try_from(value) {
                            Ipv4Addr::from(arr).to_string()
                        } else {
                            hex(value)
                        }
                    }
                    Rfc2865Kind::Integer => {
                        if let Ok(arr) = <[u8; 4]>::try_from(value) {
                            u32::from_be_bytes(arr).to_string()
                        } else {
                            hex(value)
                        }
                    }
                    Rfc2865Kind::NamedInteger(names) => {
                        if let Ok(arr) = <[u8; 4]>::try_from(value) {
                            let n = u32::from_be_bytes(arr);
                            match names.iter().find(|(v, _)| *v == n) {
                                Some((_, label)) => format!("{label} ({n})"),
                                None => n.to_string(),
                            }
                        } else {
                            hex(value)
                        }
                    }
                };
                (type_str, value_str)
            }
            None => (format!("{}", self.typ()), hex(self.value())),
        };

        f.debug_struct("AVP")
            .field("typ", &format_args!("{type_label}"))
            .field("value", &format_args!("{value_label}"))
            .finish()
    }
}

impl AVP {
    /// Returns the RADIUS attribute type byte.
    #[inline]
    pub(crate) fn typ(&self) -> AVPType {
        self.raw[0]
    }

    /// Returns a view of the value bytes (skips the 2-byte type+length header).
    #[inline]
    pub(crate) fn value(&self) -> &[u8] {
        &self.raw[2..]
    }

    /// Zero-copy view of this AVP's value bytes as a [`Bytes`] handle that
    /// shares ownership with the underlying packet buffer.
    ///
    /// Use this in preference to [`AVP::encode_bytes`] when the caller does
    /// not need an independently-owned `Box<[u8]>`. Particularly useful for
    /// VSA payload readers, which would otherwise heap-copy each match.
    #[inline]
    #[must_use]
    pub fn value_bytes(&self) -> Bytes {
        self.raw.slice(2..)
    }

    /// Borrow this AVP's value bytes as `&str` without allocating a `String`.
    ///
    /// Static counterpart of [`AVP::encode_string_value`] that performs no copy.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::DecodingError`] if `value` is not valid UTF-8.
    #[inline]
    pub fn encode_str_value(value: &[u8]) -> Result<&str, AVPError> {
        std::str::from_utf8(value).map_err(|e| AVPError::DecodingError(e.to_string()))
    }

    /// Borrow this AVP's value as `&str` without allocating a `String`.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::DecodingError`] if the bytes are not valid UTF-8.
    #[inline]
    pub fn encode_str(&self) -> Result<&str, AVPError> {
        Self::encode_str_value(self.value())
    }

    /// (This method is for dictionary developers) make an AVP from a u32 value.
    #[must_use]
    pub fn from_u32(typ: AVPType, value: u32) -> Self {
        Self::from_u32_in(&mut BytesMut::with_capacity(6), typ, value)
    }

    /// (This method is for dictionary developers) make an AVP from a u16 value.
    #[must_use]
    pub fn from_u16(typ: AVPType, value: u16) -> Self {
        Self::from_u16_in(&mut BytesMut::with_capacity(4), typ, value)
    }

    /// (This method is for dictionary developers) make an AVP from a tagged u32 value.
    ///
    /// Per RFC 2868, tagged-integer attributes carry a **3-byte** value field (the
    /// high byte of the `u32` is silently discarded), giving a total wire length of 6.
    #[must_use]
    pub fn from_tagged_u32(typ: AVPType, tag: Option<&Tag>, value: u32) -> Self {
        Self::from_tagged_u32_in(&mut BytesMut::with_capacity(6), typ, tag, value)
    }

    /// (This method is for dictionary developers) make an AVP from a string value.
    #[must_use]
    pub fn from_string(typ: AVPType, value: &str) -> Self {
        Self::from_string_in(&mut BytesMut::with_capacity(2 + value.len()), typ, value)
    }

    /// (This method is for dictionary developers) make an AVP from a tagged string value.
    #[must_use]
    pub fn from_tagged_string(typ: AVPType, tag: Option<&Tag>, value: &str) -> Self {
        let cap = tag.map_or(2 + value.len(), |_| 3 + value.len());
        Self::from_tagged_string_in(&mut BytesMut::with_capacity(cap), typ, tag, value)
    }

    /// (This method is for dictionary developers) make an AVP from bytes.
    #[must_use]
    pub fn from_bytes(typ: AVPType, value: &[u8]) -> Self {
        Self::from_bytes_in(&mut BytesMut::with_capacity(2 + value.len()), typ, value)
    }

    /// Build a Vendor-Specific Attribute (type 26, RFC 2865 §5.26) wrapping a sub-attribute.
    ///
    /// The resulting AVP has `typ = 26` and a value of:
    /// `vendor_id (4 bytes) | vendor_type (1 byte) | vendor_length (1 byte) | payload`
    /// where `vendor_length = 2 + payload.len()`.
    ///
    /// # Panics
    ///
    /// Panics if `payload.len() > 253` (vendor-length would overflow a `u8`).
    #[must_use]
    pub fn from_vsa(vendor_id: u32, vendor_type: u8, payload: &[u8]) -> Self {
        Self::from_vsa_in(
            &mut BytesMut::with_capacity(8 + payload.len()),
            vendor_id,
            vendor_type,
            payload,
        )
    }

    /// If this AVP is a Vendor-Specific (type 26) attribute matching `(vendor_id, vendor_type)`,
    /// return the inner value bytes. Otherwise return `None`.
    #[must_use]
    pub fn decode_vsa(&self, vendor_id: u32, vendor_type: u8) -> Option<Bytes> {
        let value = self.value();
        if self.typ() != VENDOR_SPECIFIC_TYPE || value.len() < 6 {
            return None;
        }
        let vid = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
        if vid != vendor_id || value[4] != vendor_type {
            return None;
        }
        let vlen = value[5] as usize;
        if vlen < 2 || 6 + vlen - 2 > value.len() {
            return None;
        }
        // Slice from raw to avoid a redundant Bytes clone when slicing value.
        Some(self.raw.slice(2 + 6..2 + 6 + vlen - 2))
    }

    /// (This method is for dictionary developers) make an AVP from a IPv4 value.
    #[must_use]
    pub fn from_ipv4(typ: AVPType, value: &Ipv4Addr) -> Self {
        Self::from_ipv4_in(&mut BytesMut::with_capacity(6), typ, value)
    }

    /// (This method is for dictionary developers) make an AVP from a IPv4-prefix value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if `prefix` is not exactly 4 bytes.
    pub fn from_ipv4_prefix(typ: AVPType, prefix: &[u8]) -> Result<Self, AVPError> {
        Self::from_ipv4_prefix_in(&mut BytesMut::with_capacity(8), typ, prefix)
    }

    /// (This method is for dictionary developers) make an AVP from a IPv6 value.
    #[must_use]
    pub fn from_ipv6(typ: AVPType, value: &Ipv6Addr) -> Self {
        Self::from_ipv6_in(&mut BytesMut::with_capacity(18), typ, value)
    }

    /// (This method is for dictionary developers) make an AVP from a IPv6-prefix value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if `prefix` exceeds 16 bytes.
    pub fn from_ipv6_prefix(typ: AVPType, prefix: &[u8]) -> Result<Self, AVPError> {
        Self::from_ipv6_prefix_in(&mut BytesMut::with_capacity(4 + prefix.len()), typ, prefix)
    }

    /// (This method is for dictionary developers) make an AVP from a user-password value.
    ///
    /// see also: <https://tools.ietf.org/html/rfc2865#section-5.2>
    ///
    /// # Errors
    ///
    /// Returns [`AVPError`] if `plain_text` exceeds 128 bytes, `secret` is empty, or
    /// `request_authenticator` is not exactly 16 bytes.
    pub fn from_user_password(
        typ: AVPType,
        plain_text: &[u8],
        secret: &[u8],
        request_authenticator: &[u8],
    ) -> Result<Self, AVPError> {
        let cap = plain_text.len().div_ceil(16) * 16;
        Self::from_user_password_in(
            &mut BytesMut::with_capacity(2 + cap.max(16)),
            typ,
            plain_text,
            secret,
            request_authenticator,
        )
    }

    /// (This method is for dictionary developers) make an AVP from a date value.
    #[must_use]
    pub fn from_date(typ: AVPType, dt: &SystemTime) -> Self {
        Self::from_date_in(&mut BytesMut::with_capacity(6), typ, dt)
    }

    /// (This method is for dictionary developers) make an AVP from a tunnel-password value.
    ///
    /// see also: <https://tools.ietf.org/html/rfc2868#section-3.5>
    ///
    /// # Errors
    ///
    /// Returns [`AVPError`] if `request_authenticator` exceeds 240 bytes, is not exactly 16 bytes,
    /// or `secret` is empty.
    pub fn from_tunnel_password(
        typ: AVPType,
        tag: Option<&Tag>,
        plain_text: &[u8],
        secret: &[u8],
        request_authenticator: &[u8],
    ) -> Result<Self, AVPError> {
        let num_chunks = (1 + plain_text.len()).div_ceil(16);
        Self::from_tunnel_password_in(
            &mut BytesMut::with_capacity(2 + 3 + num_chunks * 16),
            typ,
            tag,
            plain_text,
            secret,
            request_authenticator,
        )
    }

    // -----------------------------------------------------------------------
    // Buffer-reuse variants (`_in`): same as the `from_*` methods above, but
    // the caller supplies a `&mut BytesMut` arena.  Each method appends the
    // complete wire encoding (type + length + value) to `buf`, then calls
    // `buf.split().freeze()` so the returned `Bytes` shares that allocation.
    // All validation happens before any bytes are written, so the buffer is
    // never modified when an error is returned.
    // -----------------------------------------------------------------------

    /// Like [`AVP::from_u32`], but writes into `buf`.
    #[must_use]
    #[inline]
    pub fn from_u32_in(buf: &mut BytesMut, typ: AVPType, value: u32) -> Self {
        buf.put_u8(typ);
        buf.put_u8(6); // 2 header + 4 value
        buf.put_slice(&u32::to_be_bytes(value));
        AVP {
            raw: buf.split().freeze(),
        }
    }

    /// Like [`AVP::from_u16`], but writes into `buf`.
    #[must_use]
    #[inline]
    pub fn from_u16_in(buf: &mut BytesMut, typ: AVPType, value: u16) -> Self {
        buf.put_u8(typ);
        buf.put_u8(4); // 2 header + 2 value
        buf.put_slice(&u16::to_be_bytes(value));
        AVP {
            raw: buf.split().freeze(),
        }
    }

    /// Like [`AVP::from_tagged_u32`], but writes into `buf`.
    #[must_use]
    #[inline]
    pub fn from_tagged_u32_in(
        buf: &mut BytesMut,
        typ: AVPType,
        tag: Option<&Tag>,
        value: u32,
    ) -> Self {
        let tag_val = tag.map_or(UNUSED_TAG_VALUE, |t| t.value);
        let be = u32::to_be_bytes(value);
        buf.put_u8(typ);
        buf.put_u8(6); // 2 header + 1 tag + 3 value (RFC 2868)
        buf.put_u8(tag_val);
        buf.put_slice(&be[1..]);
        AVP {
            raw: buf.split().freeze(),
        }
    }

    /// Like [`AVP::from_string`], but writes into `buf`.
    ///
    /// # Panics
    ///
    /// Panics if `value` is longer than 253 bytes.
    #[must_use]
    #[inline]
    #[allow(clippy::cast_possible_truncation)] // len ≤ 253 asserted above; 2+len ≤ 255
    pub fn from_string_in(buf: &mut BytesMut, typ: AVPType, value: &str) -> Self {
        let bytes = value.as_bytes();
        assert!(
            bytes.len() <= 253,
            "string AVP too large: {} bytes (max 253)",
            bytes.len()
        );
        buf.put_u8(typ);
        buf.put_u8((2 + bytes.len()) as u8);
        buf.put_slice(bytes);
        AVP {
            raw: buf.split().freeze(),
        }
    }

    /// Like [`AVP::from_tagged_string`], but writes into `buf`.
    ///
    /// # Panics
    ///
    /// Panics if `value` exceeds 253 bytes (untagged) or 252 bytes (tagged).
    #[must_use]
    #[inline]
    #[allow(clippy::cast_possible_truncation)] // len ≤ 253 asserted above; 2+len ≤ 255
    pub fn from_tagged_string_in(
        buf: &mut BytesMut,
        typ: AVPType,
        tag: Option<&Tag>,
        value: &str,
    ) -> Self {
        let bytes = value.as_bytes();
        buf.put_u8(typ);
        match tag {
            None => {
                assert!(
                    bytes.len() <= 253,
                    "tagged-string AVP too large: {} bytes (max 253)",
                    bytes.len()
                );
                buf.put_u8((2 + bytes.len()) as u8);
                buf.put_slice(bytes);
            }
            Some(t) => {
                assert!(
                    bytes.len() <= 252,
                    "tagged-string AVP too large: {} bytes (max 252 with tag)",
                    bytes.len()
                );
                buf.put_u8((3 + bytes.len()) as u8);
                buf.put_u8(t.value);
                buf.put_slice(bytes);
            }
        }
        AVP {
            raw: buf.split().freeze(),
        }
    }

    /// Like [`AVP::from_bytes`], but writes into `buf`.
    ///
    /// # Panics
    ///
    /// Panics if `value` is longer than 253 bytes.
    #[must_use]
    #[inline]
    #[allow(clippy::cast_possible_truncation)] // len ≤ 253 asserted above; 2+len ≤ 255
    pub fn from_bytes_in(buf: &mut BytesMut, typ: AVPType, value: &[u8]) -> Self {
        assert!(
            value.len() <= 253,
            "bytes AVP too large: {} bytes (max 253)",
            value.len()
        );
        buf.put_u8(typ);
        buf.put_u8((2 + value.len()) as u8);
        buf.put_slice(value);
        AVP {
            raw: buf.split().freeze(),
        }
    }

    /// Like [`AVP::from_vsa`], but writes into `buf`.
    ///
    /// # Panics
    ///
    /// Panics if `payload.len() > 247` (outer AVP value would exceed 253 bytes).
    #[must_use]
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub fn from_vsa_in(
        buf: &mut BytesMut,
        vendor_id: u32,
        vendor_type: u8,
        payload: &[u8],
    ) -> Self {
        // outer AVP value = vendor_id(4) + vendor_type(1) + vendor_len(1) + payload
        //                 = 6 + payload.len() bytes; must be ≤ 253
        assert!(
            payload.len() <= 247,
            "VSA payload too large: {} bytes (max 247)",
            payload.len()
        );
        buf.put_u8(VENDOR_SPECIFIC_TYPE);
        buf.put_u8((8 + payload.len()) as u8); // 2 header + 6 VSA header + payload
        buf.put_u32(vendor_id);
        buf.put_u8(vendor_type);
        buf.put_u8((2 + payload.len()) as u8); // sub-attribute length
        buf.put_slice(payload);
        AVP {
            raw: buf.split().freeze(),
        }
    }

    /// Like [`AVP::from_ipv4`], but writes into `buf`.
    #[must_use]
    #[inline]
    pub fn from_ipv4_in(buf: &mut BytesMut, typ: AVPType, value: &Ipv4Addr) -> Self {
        buf.put_u8(typ);
        buf.put_u8(6); // 2 header + 4 value
        buf.put_slice(&value.octets());
        AVP {
            raw: buf.split().freeze(),
        }
    }

    /// Like [`AVP::from_ipv4_prefix`], but writes into `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if `prefix` is not exactly 4 bytes.
    #[inline]
    #[allow(clippy::cast_possible_truncation)] // prefix_len == 4, so try_from can't fail; cast is safe
    #[allow(clippy::missing_panics_doc)] // the .unwrap() is unreachable: prefix_len validated == 4 above
    pub fn from_ipv4_prefix_in(
        buf: &mut BytesMut,
        typ: AVPType,
        prefix: &[u8],
    ) -> Result<Self, AVPError> {
        let prefix_len = prefix.len();
        if prefix_len != 4 {
            return Err(AVPError::InvalidAttributeLengthError(
                "4 bytes".to_owned(),
                prefix_len,
            ));
        }
        buf.put_u8(typ);
        buf.put_u8(8); // 2 header + 1 reserved + 1 prefix-length + 4 prefix
        buf.put_u8(0x00);
        buf.put_u8(u8::try_from(prefix_len).unwrap() & 0b0011_1111);
        buf.put_slice(prefix);
        Ok(AVP {
            raw: buf.split().freeze(),
        })
    }

    /// Like [`AVP::from_ipv6`], but writes into `buf`.
    #[must_use]
    #[inline]
    pub fn from_ipv6_in(buf: &mut BytesMut, typ: AVPType, value: &Ipv6Addr) -> Self {
        buf.put_u8(typ);
        buf.put_u8(18); // 2 header + 16 value
        buf.put_slice(&value.octets());
        AVP {
            raw: buf.split().freeze(),
        }
    }

    /// Like [`AVP::from_ipv6_prefix`], but writes into `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if `prefix` exceeds 16 bytes.
    #[inline]
    #[allow(clippy::missing_panics_doc)] // the .unwrap() is unreachable; prefix is validated ≤ 16 bytes above
    #[allow(clippy::cast_possible_truncation)] // 4 + prefix_len ≤ 20 ≤ 255; prefix_len * 8 ≤ 128 ≤ 255
    pub fn from_ipv6_prefix_in(
        buf: &mut BytesMut,
        typ: AVPType,
        prefix: &[u8],
    ) -> Result<Self, AVPError> {
        let prefix_len = prefix.len();
        if prefix_len > 16 {
            return Err(AVPError::InvalidAttributeLengthError(
                "16 bytes".to_owned(),
                prefix_len,
            ));
        }
        buf.put_u8(typ);
        buf.put_u8((4 + prefix_len) as u8); // 2 header + 1 reserved + 1 prefix-length-bits + prefix
        buf.put_u8(0x00);
        buf.put_u8(u8::try_from(prefix_len * 8).unwrap());
        buf.put_slice(prefix);
        Ok(AVP {
            raw: buf.split().freeze(),
        })
    }

    /// Like [`AVP::from_date`], but writes into `buf`.
    #[must_use]
    #[inline]
    pub fn from_date_in(buf: &mut BytesMut, typ: AVPType, dt: &SystemTime) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        let secs = dt.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as u32;
        buf.put_u8(typ);
        buf.put_u8(6); // 2 header + 4 value
        buf.put_slice(&u32::to_be_bytes(secs));
        AVP {
            raw: buf.split().freeze(),
        }
    }

    /// Like [`AVP::from_user_password`], but writes into `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError`] if `plain_text` exceeds 128 bytes, `secret` is empty, or
    /// `request_authenticator` is not exactly 16 bytes.
    ///
    /// # Panics
    ///
    /// Does not panic in practice: the `try_into` on `request_authenticator` is guarded
    /// by the preceding length check (`!= 16`).
    #[inline]
    pub fn from_user_password_in(
        buf: &mut BytesMut,
        typ: AVPType,
        plain_text: &[u8],
        secret: &[u8],
        request_authenticator: &[u8],
    ) -> Result<Self, AVPError> {
        if plain_text.len() > 128 {
            return Err(AVPError::UserPasswordPlainTextMaximumLengthExceededError(
                plain_text.len(),
            ));
        }
        if secret.is_empty() {
            return Err(AVPError::PasswordSecretMissingError());
        }
        if request_authenticator.len() != 16 {
            return Err(AVPError::InvalidRequestAuthenticatorLengthError());
        }

        // RFC 2865 §5.2 stream cipher:
        //   hash_0 = md5(secret || request_authenticator)
        //   c_i    = p_i XOR md5(secret || c_{i-1})   (c_0 = request_authenticator)
        // We feed two separate slices into md5_of to avoid allocating md5_input.
        let mut hash_tail: [u8; 16] = request_authenticator.try_into().unwrap();

        // value_len is always a multiple of 16; at least one block even for empty passwords.
        let value_len = plain_text.len().div_ceil(16).max(1) * 16;
        debug_assert!((16..=128).contains(&value_len));
        #[allow(clippy::cast_possible_truncation)] // 2 + value_len ≤ 130 ≤ 255
        buf.put_u8(typ);
        #[allow(clippy::cast_possible_truncation)]
        buf.put_u8((2 + value_len) as u8);

        if plain_text.is_empty() {
            buf.put_slice(&crypto::md5_of(&[secret, &hash_tail]));
        } else {
            for chunk in plain_text.chunks(16) {
                // Start with the keystream block; XOR only the plaintext bytes.
                // Bytes beyond the chunk (zero padding) stay as enc_block[n..],
                // which is equivalent to XOR with zero — no copy_from_slice needed.
                let mut block = crypto::md5_of(&[secret, &hash_tail]);
                let n = chunk.len();
                for i in 0..n {
                    block[i] ^= chunk[i];
                }
                buf.put_slice(&block);
                hash_tail = block;
            }
        }

        Ok(AVP {
            raw: buf.split().freeze(),
        })
    }

    /// Like [`AVP::from_tunnel_password`], but writes into `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError`] if `secret` is empty or `request_authenticator` is not exactly 16 bytes.
    #[inline]
    pub fn from_tunnel_password_in(
        buf: &mut BytesMut,
        typ: AVPType,
        tag: Option<&Tag>,
        plain_text: &[u8],
        secret: &[u8],
        request_authenticator: &[u8],
    ) -> Result<Self, AVPError> {
        if secret.is_empty() {
            return Err(AVPError::PasswordSecretMissingError());
        }
        if request_authenticator.len() != 16 {
            return Err(AVPError::InvalidRequestAuthenticatorLengthError());
        }

        let mut salt = [0u8; 2];
        crypto::fill_random(&mut salt);
        salt[0] |= 0x80;

        let data_len = 1 + plain_text.len();
        let num_chunks = data_len.div_ceil(16);
        // 2 (header) + 1 (tag) + 2 (salt) + num_chunks*16 (ciphertext)
        let avp_len = 2 + 3 + num_chunks * 16;
        debug_assert!(avp_len >= 21); // 2 header + 3 (tag+salt) + 16 (min 1 chunk)

        buf.put_u8(typ);
        #[allow(clippy::cast_possible_truncation)] // avp_len ≤ 2+3+240=245 ≤ 255
        buf.put_u8(avp_len as u8);

        buf.put_u8(tag.map_or(UNUSED_TAG_VALUE, |v| v.value));
        buf.put_slice(&salt);

        // RFC 2868 §3.5 tunnel-password stream cipher:
        //   B_0   = md5(secret || request_authenticator || salt)
        //   B_i   = md5(secret || cipher_block_{i-1})
        //   output_i = plaintext_chunk_i XOR B_i
        //
        // Build the padded plaintext (length-byte || plain_text || zeros) on the
        // stack. A u8 length field caps plain_text at 255 bytes, so padded_len ≤ 256.
        debug_assert!(
            plain_text.len() <= 255,
            "tunnel-password plaintext exceeds 255 bytes"
        );
        let padded_len = num_chunks * 16;
        let mut padded = [0u8; 256];
        #[allow(clippy::cast_possible_truncation)] // plain_text.len() ≤ 255 (u8 length field)
        {
            padded[0] = plain_text.len() as u8;
        }
        padded[1..=plain_text.len()].copy_from_slice(plain_text);

        // First block hashes secret || RA || salt (18 bytes after secret).
        let mut hash_tail_16 = {
            let enc = crypto::md5_of(&[secret, request_authenticator, &salt]);
            let mut b = [0u8; 16];
            for i in 0..16 {
                b[i] = enc[i] ^ padded[i];
            }
            buf.put_slice(&b);
            b
        };
        // Remaining blocks hash secret || prev_ciphertext_block (always 16 bytes).
        for chunk_start in (16..padded_len).step_by(16) {
            let enc = crypto::md5_of(&[secret, &hash_tail_16]);
            let mut b = [0u8; 16];
            for i in 0..16 {
                b[i] = enc[i] ^ padded[chunk_start + i];
            }
            buf.put_slice(&b);
            hash_tail_16 = b;
        }

        Ok(AVP {
            raw: buf.split().freeze(),
        })
    }

    /// Decode raw value bytes as a `u32`.
    ///
    /// This is the static counterpart to [`encode_u32`](Self::encode_u32); callers in the VSA
    /// lookup path can use this to avoid constructing a throwaway [`AVP`].
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if `value` is not exactly 4 bytes.
    #[inline]
    pub fn encode_u32_value(value: &[u8]) -> Result<u32, AVPError> {
        const U32_SIZE: usize = std::mem::size_of::<u32>();
        let array: [u8; U32_SIZE] = value.try_into().map_err(|_| {
            AVPError::InvalidAttributeLengthError(format!("{U32_SIZE} bytes"), value.len())
        })?;
        Ok(u32::from_be_bytes(array))
    }

    /// (This method is for dictionary developers) encode an AVP into a u32 value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is not exactly 4 bytes.
    pub fn encode_u32(&self) -> Result<u32, AVPError> {
        Self::encode_u32_value(self.value())
    }

    /// Decode raw value bytes as a `u16`.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if `value` is not exactly 2 bytes.
    #[inline]
    pub fn encode_u16_value(value: &[u8]) -> Result<u16, AVPError> {
        const U16_SIZE: usize = std::mem::size_of::<u16>();
        let array: [u8; U16_SIZE] = value.try_into().map_err(|_| {
            AVPError::InvalidAttributeLengthError(format!("{U16_SIZE} bytes"), value.len())
        })?;
        Ok(u16::from_be_bytes(array))
    }

    /// (This method is for dictionary developers) encode an AVP into a u16 value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is not exactly 2 bytes.
    pub fn encode_u16(&self) -> Result<u16, AVPError> {
        Self::encode_u16_value(self.value())
    }

    /// (This method is for dictionary developers) encode an AVP into a tag and u32 value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError`] if the tag byte is missing, the tag value is invalid, or the
    /// payload is not exactly 3 bytes following the tag.
    pub fn encode_tagged_u32(&self) -> Result<(u32, Tag), AVPError> {
        // RFC 2868: tagged-integer value field is 3 bytes (total AVP payload = 4 bytes)
        const VALUE_SIZE: usize = 3;
        let value = self.value();
        if value.is_empty() {
            return Err(AVPError::TagMissingError());
        }

        let tag = Tag { value: value[0] };

        // ref RFC2868:
        //   Valid values for this field are 0x01 through 0x1F,
        //   inclusive.  If the Tag field is unused, it MUST be zero (0x00)
        if !tag.is_valid_value() && !tag.is_zero() {
            return Err(AVPError::InvalidTagForIntegerValueError());
        }

        if value[1..].len() != VALUE_SIZE {
            return Err(AVPError::InvalidAttributeLengthError(
                format!("{} bytes", VALUE_SIZE + 1),
                value.len(),
            ));
        }
        let v = u32::from_be_bytes([0, value[1], value[2], value[3]]);
        Ok((v, tag))
    }

    /// Decode raw value bytes as a UTF-8 string.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::DecodingError`] if `value` is not valid UTF-8.
    #[inline]
    pub fn encode_string_value(value: &[u8]) -> Result<String, AVPError> {
        std::str::from_utf8(value)
            .map(str::to_owned)
            .map_err(|e| AVPError::DecodingError(e.to_string()))
    }

    /// (This method is for dictionary developers) encode an AVP into a string value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::DecodingError`] if the bytes are not valid UTF-8.
    pub fn encode_string(&self) -> Result<String, AVPError> {
        Self::encode_string_value(self.value())
    }

    /// (This method is for dictionary developers) encode an AVP into a tag and string value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError`] if the tag byte is missing, the tag is zero (invalid), or the
    /// bytes are not valid UTF-8.
    pub fn encode_tagged_string(&self) -> Result<(String, Option<Tag>), AVPError> {
        let value = self.value();
        if value.is_empty() {
            return Err(AVPError::TagMissingError());
        }

        let tag = Tag { value: value[0] };

        // ref RFC2868:
        //   If the value of the Tag field is greater than 0x00
        //   and less than or equal to 0x1F, it SHOULD be interpreted as
        //   indicating which tunnel (of several alternatives) this attribute
        //   pertains.
        if tag.is_valid_value() {
            return match std::str::from_utf8(&value[1..]) {
                Ok(s) => Ok((s.to_owned(), Some(tag))),
                Err(e) => Err(AVPError::DecodingError(e.to_string())),
            };
        }

        if tag.is_zero() {
            return Err(AVPError::InvalidTagForStringValueError());
        }

        // ref RFC2868:
        //   If the Tag field is greater than 0x1F, it SHOULD be
        //   interpreted as the first byte of the following String field.
        match std::str::from_utf8(value) {
            Ok(s) => Ok((s.to_owned(), None)),
            Err(e) => Err(AVPError::DecodingError(e.to_string())),
        }
    }

    /// (This method is for dictionary developers) encode an AVP into bytes.
    #[must_use]
    pub fn encode_bytes(&self) -> Box<[u8]> {
        Box::from(self.value())
    }

    /// Decode raw value bytes as an `Ipv4Addr`.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if `value` is not exactly 4 bytes.
    #[inline]
    pub fn encode_ipv4_value(value: &[u8]) -> Result<Ipv4Addr, AVPError> {
        const IPV4_SIZE: usize = std::mem::size_of::<Ipv4Addr>();
        let array: [u8; IPV4_SIZE] = value.try_into().map_err(|_| {
            AVPError::InvalidAttributeLengthError(format!("{IPV4_SIZE} bytes"), value.len())
        })?;
        Ok(Ipv4Addr::from(array))
    }

    /// (This method is for dictionary developers) encode an AVP into Ipv4 value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is not exactly 4 bytes.
    pub fn encode_ipv4(&self) -> Result<Ipv4Addr, AVPError> {
        Self::encode_ipv4_value(self.value())
    }

    /// Decode raw value bytes as an IPv4 prefix (returns the 4-byte prefix, stripping the 2-byte header).
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if `value` is not exactly 6 bytes.
    #[inline]
    pub fn encode_ipv4_prefix_value(value: &[u8]) -> Result<Box<[u8]>, AVPError> {
        if value.len() == 6 {
            Ok(Box::from(&value[2..]))
        } else {
            Err(AVPError::InvalidAttributeLengthError(
                "6 bytes".to_owned(),
                value.len(),
            ))
        }
    }

    /// (This method is for dictionary developers) encode an AVP into Ipv4-prefix value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is not exactly 6 bytes.
    pub fn encode_ipv4_prefix(&self) -> Result<Box<[u8]>, AVPError> {
        Self::encode_ipv4_prefix_value(self.value())
    }

    /// Decode raw value bytes as an `Ipv6Addr`.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if `value` is not exactly 16 bytes.
    #[inline]
    pub fn encode_ipv6_value(value: &[u8]) -> Result<Ipv6Addr, AVPError> {
        const IPV6_SIZE: usize = std::mem::size_of::<Ipv6Addr>();
        let array: [u8; IPV6_SIZE] = value.try_into().map_err(|_| {
            AVPError::InvalidAttributeLengthError(format!("{IPV6_SIZE} bytes"), value.len())
        })?;
        Ok(Ipv6Addr::from(array))
    }

    /// (This method is for dictionary developers) encode an AVP into Ipv6 value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is not exactly 16 bytes.
    pub fn encode_ipv6(&self) -> Result<Ipv6Addr, AVPError> {
        Self::encode_ipv6_value(self.value())
    }

    /// Decode raw value bytes as an IPv6 prefix (strips the 2-byte header, returns the prefix).
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if `value` is shorter than 2 bytes.
    #[inline]
    pub fn encode_ipv6_prefix_value(value: &[u8]) -> Result<Box<[u8]>, AVPError> {
        if value.len() >= 2 {
            Ok(Box::from(&value[2..]))
        } else {
            Err(AVPError::InvalidAttributeLengthError(
                "2+ bytes".to_owned(),
                value.len(),
            ))
        }
    }

    /// (This method is for dictionary developers) encode an AVP into Ipv6-prefix value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is shorter than 2 bytes.
    pub fn encode_ipv6_prefix(&self) -> Result<Box<[u8]>, AVPError> {
        Self::encode_ipv6_prefix_value(self.value())
    }

    /// Decode raw value bytes as a user-password (RFC 2865 §5.2 reverse cipher).
    ///
    /// # Errors
    ///
    /// Returns [`AVPError`] if `value` length is out of range, `secret` is empty, or
    /// `request_authenticator` is not exactly 16 bytes.
    #[inline]
    pub fn encode_user_password_value(
        value: &[u8],
        secret: &[u8],
        request_authenticator: &[u8],
    ) -> Result<Vec<u8>, AVPError> {
        if value.len() < 16 || value.len() > 128 {
            return Err(AVPError::InvalidAttributeLengthError(
                "16 >= bytes && 128 <= bytes".to_owned(),
                value.len(),
            ));
        }

        if secret.is_empty() {
            return Err(AVPError::PasswordSecretMissingError());
        }

        if request_authenticator.len() != 16 {
            return Err(AVPError::InvalidRequestAuthenticatorLengthError());
        }

        let mut dec: Vec<u8> = Vec::with_capacity(value.len());

        // RFC 2865 §5.2 reverse stream cipher:
        //   p_i = c_i XOR md5(secret || c_{i-1})   (c_0 = request_authenticator)
        // Use md5_of with two slices to avoid allocating an md5_input Vec.
        let mut hash_tail = [0u8; 16];
        hash_tail.copy_from_slice(request_authenticator);

        // NOTE:
        // It ensures attribute value has 16 bytes length at least because the value is encoded by md5.
        // And this must be aligned by each 16 bytes length.
        for chunk in value.chunks(16) {
            let dec_block = crypto::md5_of(&[secret, &hash_tail]);
            for (&d, &p) in dec_block.iter().zip(chunk) {
                dec.push(d ^ p);
            }
            // Next hash input = current ciphertext chunk (copy into fixed 16-byte tail).
            let n = chunk.len();
            hash_tail = [0u8; 16];
            hash_tail[..n].copy_from_slice(chunk);
        }

        // Strip RFC 2865 §5.2 trailing null padding by scanning from the end.
        let end = dec.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        dec.truncate(end);
        Ok(dec)
    }

    /// (This method is for dictionary developers) encode an AVP into user-password value as bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError`] if the encoded value length is out of range, `secret` is empty, or
    /// `request_authenticator` is not exactly 16 bytes.
    pub fn encode_user_password(
        &self,
        secret: &[u8],
        request_authenticator: &[u8],
    ) -> Result<Vec<u8>, AVPError> {
        Self::encode_user_password_value(self.value(), secret, request_authenticator)
    }

    /// Decode raw value bytes as a `SystemTime` (RADIUS date: u32 big-endian seconds since Unix epoch).
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if `value` is not exactly 4 bytes.
    #[inline]
    pub fn encode_date_value(value: &[u8]) -> Result<SystemTime, AVPError> {
        const U32_SIZE: usize = std::mem::size_of::<u32>();
        let array: [u8; U32_SIZE] = value.try_into().map_err(|_| {
            AVPError::InvalidAttributeLengthError(format!("{U32_SIZE}"), value.len())
        })?;
        let timestamp = u32::from_be_bytes(array);
        Ok(UNIX_EPOCH + Duration::from_secs(u64::from(timestamp)))
    }

    /// (This method is for dictionary developers) encode an AVP into date value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is not exactly 4 bytes.
    pub fn encode_date(&self) -> Result<SystemTime, AVPError> {
        Self::encode_date_value(self.value())
    }

    /// (This method is for dictionary developers) encode an AVP into a tunnel-password value as bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError`] if the value length is out of range, salt MSB is invalid, `secret` is
    /// empty, or `request_authenticator` is not exactly 16 bytes.
    pub fn encode_tunnel_password(
        &self,
        secret: &[u8],
        request_authenticator: &[u8],
    ) -> Result<(Vec<u8>, Tag), AVPError> {
        let value = self.value();
        if value.len() < 19 || value.len() > 243 || (value.len() - 3) % 16 != 0 {
            return Err(AVPError::InvalidAttributeLengthError(
                "19 <= bytes && bytes <= 243 && (bytes - 3) % 16 == 0".to_owned(),
                value.len(),
            ));
        }

        if value[1] & 0x80 != 0x80 {
            // salt
            return Err(AVPError::InvalidSaltMSBError(value[1]));
        }

        if secret.is_empty() {
            return Err(AVPError::PasswordSecretMissingError());
        }

        if request_authenticator.len() != 16 {
            return Err(AVPError::InvalidRequestAuthenticatorLengthError());
        }

        let tag = Tag { value: value[0] };
        let ciphertext = &value[3..];
        let secret_len = secret.len();
        let mut dec = Vec::with_capacity(ciphertext.len());
        // Round 1: MD5(secret || request_authenticator || salt)
        // Round N: MD5(secret || prev_ciphertext_chunk)
        let mut md5_input = Vec::with_capacity(secret_len + 18);
        md5_input.extend_from_slice(secret);
        md5_input.extend_from_slice(request_authenticator);
        md5_input.extend_from_slice(&value[1..3]); // salt

        for chunk in ciphertext.chunks(16) {
            let dec_block = crypto::md5(&md5_input);
            for (&d, &p) in dec_block.iter().zip(chunk) {
                dec.push(d ^ p);
            }
            // Next iteration hashes secret || this ciphertext chunk.
            md5_input.truncate(secret_len);
            md5_input.extend_from_slice(chunk);
        }

        // RFC 2868 §3.5: the first decrypted byte is the plaintext length.
        // Use it to extract exactly that many bytes, preserving any embedded zeros.
        let length = dec[0] as usize;
        if length + 1 > dec.len() {
            return Err(AVPError::InvalidAttributeLengthError(
                format!("tunnel-password length prefix ({length}) exceeds decrypted payload"),
                length,
            ));
        }
        Ok((dec[1..=length].to_vec(), tag))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::core::avp::{AVPError, AVP};
    use crate::core::tag::Tag;

    #[test]
    fn it_should_convert_attribute_to_integer32() -> Result<(), AVPError> {
        let given_u32 = 16_909_060;
        let avp = AVP::from_u32(1, given_u32);
        assert_eq!(avp.encode_u32()?, given_u32);
        Ok(())
    }

    #[test]
    fn it_should_convert_attribute_to_integer16() -> Result<(), AVPError> {
        let given_u16 = 65534;
        let avp = AVP::from_u16(1, given_u16);
        assert_eq!(avp.encode_u16()?, given_u16);
        Ok(())
    }

    #[test]
    fn it_should_convert_attribute_to_tagged_integer32() -> Result<(), AVPError> {
        // RFC 2868 tagged integers are 3-byte values; use a value that fits (≤ 0xFFFFFF).
        // 13 = VLAN (matches the FreeRADIUS Tunnel-Type example).
        let given_u32 = 13u32;
        let avp = AVP::from_tagged_u32(1, None, given_u32);
        assert_eq!(avp.value().len(), 4); // tag(1) + value(3)
        assert_eq!(avp.encode_tagged_u32()?, (given_u32, Tag::new_unused()));

        let tag = Tag::new(2);
        let avp = AVP::from_tagged_u32(1, Some(&tag), given_u32);
        assert_eq!(avp.encode_tagged_u32()?, (given_u32, tag));

        // Verify exact wire bytes match FreeRADIUS output for Tunnel-Type VLAN(13) Tag=0x00:
        // AVP value field (excluding RADIUS type/length bytes): 0x00, 0x00, 0x00, 0x0d
        let avp_vlan = AVP::from_tagged_u32(64, None, 13);
        assert_eq!(avp_vlan.value(), &[0x00, 0x00, 0x00, 0x0d]);
        Ok(())
    }

    #[test]
    fn it_should_convert_attribute_to_string() -> Result<(), AVPError> {
        let given_str = "Hello, World";
        let avp = AVP::from_string(1, given_str);
        assert_eq!(avp.encode_string()?, given_str);
        Ok(())
    }

    #[test]
    fn it_should_convert_tagged_attribute_to_string() -> Result<(), AVPError> {
        let given_str = "Hello, World";
        let avp = AVP::from_tagged_string(1, None, given_str);
        assert_eq!(avp.encode_tagged_string()?, (given_str.to_owned(), None));

        let tag = Tag::new(3);
        let avp = AVP::from_tagged_string(1, Some(&tag), given_str);
        assert_eq!(
            avp.encode_tagged_string()?,
            (given_str.to_owned(), Some(tag))
        );

        let avp = AVP::from_tagged_string(1, Some(&Tag::new_unused()), given_str);
        assert_eq!(
            avp.encode_tagged_string().unwrap_err(),
            AVPError::InvalidTagForStringValueError()
        );

        Ok(())
    }

    #[test]
    fn it_should_convert_attribute_to_byte() {
        let given_bytes = b"Hello, World";
        let avp = AVP::from_bytes(1, given_bytes);
        assert_eq!(avp.encode_bytes().as_ref(), given_bytes as &[u8]);
    }

    #[test]
    fn it_should_convert_ipv4() -> Result<(), AVPError> {
        let given_ipv4 = Ipv4Addr::new(192, 0, 2, 1);
        let avp = AVP::from_ipv4(1, &given_ipv4);
        assert_eq!(avp.encode_ipv4()?, given_ipv4);
        Ok(())
    }

    #[test]
    fn it_should_convert_ipv6() -> Result<(), AVPError> {
        let given_ipv6 = Ipv6Addr::new(
            0x2001, 0x0db8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001,
        );
        let avp = AVP::from_ipv6(1, &given_ipv6);
        assert_eq!(avp.encode_ipv6()?, given_ipv6);
        Ok(())
    }

    #[test]
    fn it_should_convert_user_password() {
        struct TestCase<'a> {
            plain_text: &'a str,
            expected_encoded_len: usize,
        }

        let secret = b"12345".to_vec();
        let request_authenticator = b"0123456789abcdef".to_vec();

        let test_cases = &[
            TestCase {
                plain_text: "",
                expected_encoded_len: 16,
            },
            TestCase {
                plain_text: "abc",
                expected_encoded_len: 16,
            },
            TestCase {
                plain_text: "0123456789abcde",
                expected_encoded_len: 16,
            },
            TestCase {
                plain_text: "0123456789abcdef",
                expected_encoded_len: 16,
            },
            TestCase {
                plain_text: "0123456789abcdef0",
                expected_encoded_len: 32,
            },
            TestCase {
                plain_text: "0123456789abcdef0123456789abcdef0123456789abcdef",
                expected_encoded_len: 48,
            },
        ];

        for test_case in test_cases {
            let user_password_avp_result = AVP::from_user_password(
                1,
                test_case.plain_text.as_bytes(),
                &secret,
                &request_authenticator,
            );
            let avp = user_password_avp_result.unwrap();
            assert_eq!(avp.value().len(), test_case.expected_encoded_len);

            let decoded_password = avp
                .encode_user_password(&secret, &request_authenticator)
                .unwrap();
            assert_eq!(
                String::from_utf8(decoded_password.clone()).unwrap(),
                test_case.plain_text
            );
        }
    }

    #[test]
    fn it_should_convert_date() -> Result<(), AVPError> {
        let now = SystemTime::now();
        let avp = AVP::from_date(1, &now);
        let now_secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
        let encoded_secs = avp
            .encode_date()?
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(encoded_secs, now_secs);
        Ok(())
    }

    #[test]
    fn it_should_convert_tunnel_password() {
        struct TestCase<'a> {
            plain_text: &'a str,
            expected_encoded_len: usize,
        }

        let tag = Tag { value: 0x1e };
        let secret = b"12345".to_vec();
        let request_authenticator = b"0123456789abcdef".to_vec();

        let test_cases = &[
            TestCase {
                plain_text: "",
                expected_encoded_len: 16 + 3, // ceil((0+1)/16)=1 chunk
            },
            TestCase {
                plain_text: "abc",
                expected_encoded_len: 16 + 3, // ceil((3+1)/16)=1 chunk
            },
            TestCase {
                plain_text: "0123456789abcde",
                expected_encoded_len: 16 + 3, // ceil((15+1)/16)=1 chunk; length byte fills the 16th slot
            },
            TestCase {
                plain_text: "0123456789abcdef",
                expected_encoded_len: 32 + 3, // ceil((16+1)/16)=2 chunks; length byte pushes to second block
            },
            TestCase {
                plain_text: "0123456789abcdef0",
                expected_encoded_len: 32 + 3, // ceil((17+1)/16)=2 chunks
            },
            TestCase {
                plain_text: "0123456789abcdef0123456789abcdef0123456789abcdef",
                expected_encoded_len: 64 + 3, // ceil((48+1)/16)=4 chunks
            },
        ];

        for test_case in test_cases {
            let user_password_avp_result = AVP::from_tunnel_password(
                1,
                Some(&tag),
                test_case.plain_text.as_bytes(),
                &secret,
                &request_authenticator,
            );
            let avp = user_password_avp_result.unwrap();
            assert_eq!(avp.value().len(), test_case.expected_encoded_len);

            let (decoded_password, got_tag) = avp
                .encode_tunnel_password(&secret, &request_authenticator)
                .unwrap();
            assert_eq!(got_tag, tag);
            assert_eq!(
                String::from_utf8(decoded_password.clone()).unwrap(),
                test_case.plain_text
            );
        }
    }

    #[test]
    fn should_convert_ipv4_prefix() -> Result<(), AVPError> {
        let prefix = vec![0x01, 0x02, 0x03, 0x04];
        let avp = AVP::from_ipv4_prefix(1, &prefix)?;
        assert_eq!(avp.encode_ipv4_prefix()?.as_ref(), prefix.as_slice());

        Ok(())
    }

    #[test]
    fn should_convert_ipv4_prefix_fail_because_of_invalid_prefix_length() {
        let avp = AVP::from_ipv4_prefix(1, &[0x01, 0x02, 0x03]);
        assert_eq!(
            avp.unwrap_err(),
            AVPError::InvalidAttributeLengthError("4 bytes".to_owned(), 3)
        );

        let avp = AVP::from_ipv4_prefix(1, &[0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(
            avp.unwrap_err(),
            AVPError::InvalidAttributeLengthError("4 bytes".to_owned(), 5)
        );

        assert_eq!(
            AVP::from_bytes(1, &[]).encode_ipv4_prefix().unwrap_err(),
            AVPError::InvalidAttributeLengthError("6 bytes".to_owned(), 0)
        );
    }

    #[test]
    fn should_convert_ipv6_prefix() -> Result<(), AVPError> {
        let prefix = vec![];
        let avp = AVP::from_ipv6_prefix(1, &prefix)?;
        assert_eq!(avp.encode_ipv6_prefix()?.as_ref(), prefix.as_slice());

        let prefix = vec![0x00, 0x01, 0x02, 0x03];
        let avp = AVP::from_ipv6_prefix(1, &prefix)?;
        assert_eq!(avp.encode_ipv6_prefix()?.as_ref(), prefix.as_slice());

        let prefix = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let avp = AVP::from_ipv6_prefix(1, &prefix)?;
        assert_eq!(avp.encode_ipv6_prefix()?.as_ref(), prefix.as_slice());

        Ok(())
    }

    #[test]
    fn should_convert_ipv6_prefix_fail_because_of_invalid_prefix_length() {
        let avp = AVP::from_ipv6_prefix(
            1,
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10,
            ],
        );
        assert_eq!(
            avp.unwrap_err(),
            AVPError::InvalidAttributeLengthError("16 bytes".to_owned(), 17)
        );
    }

    #[test]
    fn encode_u32_should_fail_on_wrong_length() {
        let avp = AVP::from_bytes(1, b"\x01\x02\x03");
        assert_eq!(
            avp.encode_u32().unwrap_err(),
            AVPError::InvalidAttributeLengthError("4 bytes".to_owned(), 3)
        );
    }

    #[test]
    fn encode_u16_should_fail_on_wrong_length() {
        let avp = AVP::from_bytes(1, b"\x01\x02\x03");
        assert_eq!(
            avp.encode_u16().unwrap_err(),
            AVPError::InvalidAttributeLengthError("2 bytes".to_owned(), 3)
        );
    }

    #[test]
    fn encode_tagged_u32_should_fail_on_empty_value() {
        let avp = AVP::from_bytes(1, &[]);
        assert_eq!(
            avp.encode_tagged_u32().unwrap_err(),
            AVPError::TagMissingError()
        );
    }

    #[test]
    fn encode_tagged_u32_should_fail_on_invalid_tag() {
        // Tag 0x20 is non-zero and > 0x1f, which is invalid
        let avp = AVP::from_bytes(1, b"\x20\x00\x00\x00\x01");
        assert_eq!(
            avp.encode_tagged_u32().unwrap_err(),
            AVPError::InvalidTagForIntegerValueError()
        );
    }

    #[test]
    fn encode_tagged_u32_should_fail_on_wrong_payload_size() {
        // Valid tag 0x01 but only 2 bytes of payload instead of 3 (RFC 2868 requires 3)
        let avp = AVP::from_bytes(1, b"\x01\x00\x01");
        assert_eq!(
            avp.encode_tagged_u32().unwrap_err(),
            AVPError::InvalidAttributeLengthError("4 bytes".to_owned(), 3)
        );
    }

    #[test]
    fn encode_tagged_string_should_fail_on_empty_value() {
        let avp = AVP::from_bytes(1, &[]);
        assert_eq!(
            avp.encode_tagged_string().unwrap_err(),
            AVPError::TagMissingError()
        );
    }

    #[test]
    fn encode_string_should_fail_on_invalid_utf8() {
        let avp = AVP::from_bytes(1, b"\xff\xfe");
        assert!(matches!(
            avp.encode_string().unwrap_err(),
            AVPError::DecodingError(_)
        ));
    }

    #[test]
    fn encode_ipv4_should_fail_on_wrong_length() {
        let avp = AVP::from_bytes(1, b"\x01\x02\x03");
        assert_eq!(
            avp.encode_ipv4().unwrap_err(),
            AVPError::InvalidAttributeLengthError("4 bytes".to_owned(), 3)
        );
    }

    #[test]
    fn encode_ipv6_should_fail_on_wrong_length() {
        let avp = AVP::from_bytes(1, &[0u8; 15]);
        assert_eq!(
            avp.encode_ipv6().unwrap_err(),
            AVPError::InvalidAttributeLengthError("16 bytes".to_owned(), 15)
        );
    }

    #[test]
    fn encode_ipv6_prefix_should_fail_on_too_short_value() {
        let avp = AVP::from_bytes(1, b"\x01");
        assert_eq!(
            avp.encode_ipv6_prefix().unwrap_err(),
            AVPError::InvalidAttributeLengthError("2+ bytes".to_owned(), 1)
        );
    }

    #[test]
    fn encode_date_should_fail_on_wrong_length() {
        let avp = AVP::from_bytes(1, b"\x01\x02\x03");
        assert_eq!(
            avp.encode_date().unwrap_err(),
            AVPError::InvalidAttributeLengthError("4".to_owned(), 3)
        );
    }

    #[test]
    fn from_user_password_should_fail_on_too_long_plain_text() {
        let plain_text = vec![0u8; 129];
        assert_eq!(
            AVP::from_user_password(1, &plain_text, b"secret", b"0123456789abcdef").unwrap_err(),
            AVPError::UserPasswordPlainTextMaximumLengthExceededError(129)
        );
    }

    #[test]
    fn from_user_password_should_fail_on_missing_secret() {
        assert_eq!(
            AVP::from_user_password(1, b"pass", b"", b"0123456789abcdef").unwrap_err(),
            AVPError::PasswordSecretMissingError()
        );
    }

    #[test]
    fn from_user_password_should_fail_on_wrong_authenticator_length() {
        assert_eq!(
            AVP::from_user_password(1, b"pass", b"secret", b"short").unwrap_err(),
            AVPError::InvalidRequestAuthenticatorLengthError()
        );
    }

    #[test]
    fn encode_user_password_should_fail_on_wrong_avp_length() {
        // value < 16 bytes
        let avp = AVP::from_bytes(1, &[0u8; 10]);
        assert_eq!(
            avp.encode_user_password(b"s", b"0123456789abcdef")
                .unwrap_err(),
            AVPError::InvalidAttributeLengthError("16 >= bytes && 128 <= bytes".to_owned(), 10)
        );
        // value > 128 bytes
        let avp = AVP::from_bytes(1, &[0u8; 144]);
        assert_eq!(
            avp.encode_user_password(b"s", b"0123456789abcdef")
                .unwrap_err(),
            AVPError::InvalidAttributeLengthError("16 >= bytes && 128 <= bytes".to_owned(), 144)
        );
    }

    #[test]
    fn encode_user_password_should_fail_on_missing_secret() {
        let avp = AVP::from_bytes(1, &[0u8; 16]);
        assert_eq!(
            avp.encode_user_password(b"", b"0123456789abcdef")
                .unwrap_err(),
            AVPError::PasswordSecretMissingError()
        );
    }

    #[test]
    fn encode_user_password_should_fail_on_wrong_authenticator_length() {
        let avp = AVP::from_bytes(1, &[0u8; 16]);
        assert_eq!(
            avp.encode_user_password(b"secret", b"short").unwrap_err(),
            AVPError::InvalidRequestAuthenticatorLengthError()
        );
    }

    #[test]
    fn from_tunnel_password_should_fail_on_missing_secret() {
        assert_eq!(
            AVP::from_tunnel_password(1, None, b"pass", b"", b"0123456789abcdef").unwrap_err(),
            AVPError::PasswordSecretMissingError()
        );
    }

    #[test]
    fn from_tunnel_password_should_fail_on_wrong_authenticator_length() {
        assert_eq!(
            AVP::from_tunnel_password(1, None, b"pass", b"secret", b"short").unwrap_err(),
            AVPError::InvalidRequestAuthenticatorLengthError()
        );
    }

    #[test]
    fn encode_tunnel_password_should_fail_on_wrong_length() {
        // too short (< 19)
        let avp = AVP::from_bytes(1, &[0u8; 10]);
        assert_eq!(
            avp.encode_tunnel_password(b"secret", b"0123456789abcdef")
                .unwrap_err(),
            AVPError::InvalidAttributeLengthError(
                "19 <= bytes && bytes <= 243 && (bytes - 3) % 16 == 0".to_owned(),
                10
            )
        );
    }

    #[test]
    fn encode_tunnel_password_should_fail_on_invalid_salt_msb() {
        // 19-byte value: tag(1) + salt(2) + ciphertext(16); MSB of salt byte not set
        let mut value = [0u8; 19];
        value[1] = 0x00; // MSB not set
        let avp = AVP::from_bytes(1, &value);
        assert_eq!(
            avp.encode_tunnel_password(b"secret", b"0123456789abcdef")
                .unwrap_err(),
            AVPError::InvalidSaltMSBError(0x00)
        );
    }

    #[test]
    fn encode_tunnel_password_should_fail_on_missing_secret() {
        let mut value = [0u8; 19];
        value[1] = 0x80; // MSB set (valid salt)
        let avp = AVP::from_bytes(1, &value);
        assert_eq!(
            avp.encode_tunnel_password(b"", b"0123456789abcdef")
                .unwrap_err(),
            AVPError::PasswordSecretMissingError()
        );
    }

    #[test]
    fn encode_tunnel_password_should_fail_on_wrong_authenticator_length() {
        let mut value = [0u8; 19];
        value[1] = 0x80; // MSB set (valid salt)
        let avp = AVP::from_bytes(1, &value);
        assert_eq!(
            avp.encode_tunnel_password(b"secret", b"short").unwrap_err(),
            AVPError::InvalidRequestAuthenticatorLengthError()
        );
    }

    // ── RFC 2868 §3.5 compliance tests ────────────────────────────────────────

    /// RFC 2868 §3.5: the ciphertext length must be `16 * ceil((1 + n) / 16)`
    /// where the +1 accounts for the mandatory length-prefix byte.  Verify the
    /// chunk-boundary cases that matter most for interop:
    ///
    ///  - 0-byte  plaintext: [0x00]              → 1 byte  → 1 chunk  → value 19 B
    ///  - 14-byte plaintext: [0x0e][14 bytes]     → 15 bytes → 1 chunk  → value 19 B
    ///  - 15-byte plaintext: [0x0f][15 bytes]     → 16 bytes → 1 chunk  → value 19 B
    ///  - 16-byte plaintext: [0x10][16 bytes]     → 17 bytes → 2 chunks → value 35 B
    ///  - 31-byte plaintext: [0x1f][31 bytes]     → 32 bytes → 2 chunks → value 35 B
    ///  - 32-byte plaintext: [0x20][32 bytes]     → 33 bytes → 3 chunks → value 51 B
    #[test]
    fn tunnel_password_chunk_boundary_cases() {
        let secret = b"12345";
        let req_auth = b"0123456789abcdef";

        let cases: &[(&[u8], usize)] = &[
            (b"" as &[u8], 19), // 0 bytes  → 1 chunk
            (&[b'A'; 14], 19),  // 14 bytes → 1 chunk
            (&[b'B'; 15], 19),  // 15 bytes → exactly fills 1 chunk
            (&[b'C'; 16], 35),  // 16 bytes → overflows to 2nd chunk
            (&[b'D'; 31], 35),  // 31 bytes → exactly fills 2 chunks
            (&[b'E'; 32], 51),  // 32 bytes → overflows to 3rd chunk
        ];

        for (plaintext, expected_value_len) in cases {
            let avp = AVP::from_tunnel_password(69, None, plaintext, secret, req_auth).unwrap();
            assert_eq!(
                avp.value().len(),
                *expected_value_len,
                "wrong value length for {}-byte plaintext",
                plaintext.len()
            );
            // Ciphertext portion (after tag + salt) must be a multiple of 16.
            let ciphertext_len = avp.value().len() - 3;
            assert_eq!(
                ciphertext_len % 16,
                0,
                "ciphertext not 16-byte aligned for {}-byte plaintext",
                plaintext.len()
            );

            // Round-trip must recover the original plaintext.
            let (decoded, _) = avp.encode_tunnel_password(secret, req_auth).unwrap();
            assert_eq!(
                decoded,
                *plaintext,
                "round-trip mismatch for {}-byte plaintext",
                plaintext.len()
            );
        }
    }

    /// RFC 2868 §3.5 wire-format: tag byte is first, salt MSB is always set,
    /// and the total value length is 3 + ciphertext.
    #[test]
    fn tunnel_password_wire_format_structure() {
        let tag = Tag::new(0x1f);
        let secret = b"s3cr3t";
        let req_auth = b"AAAAAAAAAAAAAAAA";

        let avp = AVP::from_tunnel_password(69, Some(&tag), b"pw", secret, req_auth).unwrap();

        // Byte 0: tag value.
        assert_eq!(avp.value()[0], 0x1f, "tag byte mismatch");
        // Byte 1: salt high byte — MSB must be set (RFC 2868 §3.5).
        assert_eq!(avp.value()[1] & 0x80, 0x80, "salt MSB not set");
        // Total value = tag(1) + salt(2) + ciphertext(16n).
        assert_eq!(
            (avp.value().len() - 3) % 16,
            0,
            "ciphertext not 16-byte aligned"
        );

        // No-tag encode (tag byte must be 0x00).
        let avp_notag = AVP::from_tunnel_password(69, None, b"pw", secret, req_auth).unwrap();
        assert_eq!(
            avp_notag.value()[0],
            0x00,
            "tag byte should be 0x00 when no tag supplied"
        );
    }

    /// RFC 2868 §3.5 requires the length-prefix byte so that the decoder can
    /// recover the exact plaintext even when it contains embedded `\x00` bytes.
    /// A trailing-zero-strip decoder (e.g. `rposition`) would truncate such data.
    #[test]
    fn tunnel_password_preserves_binary_data_with_embedded_zeros() {
        let secret = b"secret";
        let req_auth = b"0123456789abcdef";
        let plaintext: &[u8] = &[0x01, 0x00, 0x02, 0x00, 0x03]; // embedded zeros

        let avp = AVP::from_tunnel_password(69, None, plaintext, secret, req_auth).unwrap();
        let (decoded, _) = avp.encode_tunnel_password(secret, req_auth).unwrap();
        assert_eq!(decoded, plaintext, "embedded zeros must be preserved");
    }

    /// Decode a pre-computed RFC-compliant wire value and assert the expected
    /// plaintext and tag.  The wire bytes were produced by the reference
    /// Python computation in the test suite comments:
    ///
    ///   secret          = b"secret"
    ///   `request_auth`    = b"0123456789abcdef"
    ///   tag             = 0x01
    ///   salt            = [0x80, 0x01]
    ///   plaintext       = b"hello"  (5 bytes)
    ///
    /// Padded plaintext  = [0x05, 'h', 'e', 'l', 'l', 'o', 0x00×10]  (16 bytes)
    /// b1                = MD5("secret" || "0123456789abcdef" || 0x80 0x01)
    /// ciphertext        = padded XOR b1
    /// wire value        = [0x01][0x80][0x01][ciphertext]
    ///
    /// The ciphertext is computed inside the test using `crypto::md5` so that
    /// the expected bytes are derived from the same crypto primitive and the
    /// test acts as a cross-check of the implementation.
    #[test]
    fn tunnel_password_known_vector_decode() {
        use crate::core::crypto;

        let secret: &[u8] = b"secret";
        let req_auth: &[u8] = b"0123456789abcdef";
        let salt = [0x80u8, 0x01u8];
        let plaintext = b"hello";

        // Build the RFC 2868 padded plaintext: [length(1)][data][zeros].
        let mut padded = [0u8; 16];
        padded[0] = u8::try_from(plaintext.len()).unwrap(); // 0x05
        padded[1..=plaintext.len()].copy_from_slice(plaintext);

        // Compute b1 = MD5(secret || req_auth || salt).
        let mut md5_in = Vec::new();
        md5_in.extend_from_slice(secret);
        md5_in.extend_from_slice(req_auth);
        md5_in.extend_from_slice(&salt);
        let b1 = crypto::md5(&md5_in);

        // c1 = padded XOR b1.
        let ciphertext: Vec<u8> = b1.iter().zip(padded.iter()).map(|(&k, &p)| k ^ p).collect();

        // Assemble wire value: [tag][salt0][salt1][ciphertext].
        let mut wire = vec![0x01u8]; // tag = 1
        wire.extend_from_slice(&salt);
        wire.extend_from_slice(&ciphertext);

        let avp = AVP::from_bytes(69, &wire);
        let (decoded, tag) = avp.encode_tunnel_password(secret, req_auth).unwrap();
        assert_eq!(decoded, b"hello", "decoded plaintext mismatch");
        assert_eq!(tag.value(), 0x01, "tag mismatch");
    }

    /// Encode followed by decode must return the original plaintext and tag for
    /// every tag value in the valid range (0x00–0x1f).
    #[test]
    fn tunnel_password_tag_roundtrip() {
        let secret = b"secret";
        let req_auth = b"0123456789abcdef";
        let plaintext = b"password";

        for tag_val in 0x00u8..=0x1f {
            let tag = Tag::new(tag_val);
            let avp =
                AVP::from_tunnel_password(69, Some(&tag), plaintext, secret, req_auth).unwrap();
            let (decoded, got_tag) = avp.encode_tunnel_password(secret, req_auth).unwrap();
            assert_eq!(
                decoded, plaintext,
                "tag 0x{tag_val:02x}: plaintext mismatch"
            );
            assert_eq!(
                got_tag.value(),
                tag_val,
                "tag 0x{tag_val:02x}: tag value mismatch"
            );
        }
    }
}
