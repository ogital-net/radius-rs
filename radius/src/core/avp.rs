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
    pub(crate) typ: AVPType,
    pub(crate) value: Bytes,
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

        let (type_label, value_label) = match rfc2865_attr_info(self.typ) {
            Some((name, kind)) => {
                let type_str = format!("{name} ({})", self.typ);
                let value_str = match kind {
                    Rfc2865Kind::String => match std::str::from_utf8(&self.value) {
                        Ok(s) => format!("{s:?}"),
                        Err(_) => hex(&self.value),
                    },
                    Rfc2865Kind::Encrypted => {
                        format!("<encrypted, {} bytes>", self.value.len())
                    }
                    Rfc2865Kind::Octets => hex(&self.value),
                    Rfc2865Kind::IpAddr => {
                        if let Ok(arr) = <[u8; 4]>::try_from(self.value.as_ref()) {
                            Ipv4Addr::from(arr).to_string()
                        } else {
                            hex(&self.value)
                        }
                    }
                    Rfc2865Kind::Integer => {
                        if let Ok(arr) = <[u8; 4]>::try_from(self.value.as_ref()) {
                            u32::from_be_bytes(arr).to_string()
                        } else {
                            hex(&self.value)
                        }
                    }
                    Rfc2865Kind::NamedInteger(names) => {
                        if let Ok(arr) = <[u8; 4]>::try_from(self.value.as_ref()) {
                            let n = u32::from_be_bytes(arr);
                            match names.iter().find(|(v, _)| *v == n) {
                                Some((_, label)) => format!("{label} ({n})"),
                                None => n.to_string(),
                            }
                        } else {
                            hex(&self.value)
                        }
                    }
                };
                (type_str, value_str)
            }
            None => (format!("{}", self.typ), hex(&self.value)),
        };

        f.debug_struct("AVP")
            .field("typ", &format_args!("{type_label}"))
            .field("value", &format_args!("{value_label}"))
            .finish()
    }
}

impl AVP {
    /// (This method is for dictionary developers) make an AVP from a u32 value.
    #[must_use]
    pub fn from_u32(typ: AVPType, value: u32) -> Self {
        AVP {
            typ,
            value: Bytes::copy_from_slice(&u32::to_be_bytes(value)),
        }
    }

    /// (This method is for dictionary developers) make an AVP from a u16 value.
    #[must_use]
    pub fn from_u16(typ: AVPType, value: u16) -> Self {
        AVP {
            typ,
            value: Bytes::copy_from_slice(&u16::to_be_bytes(value)),
        }
    }

    /// (This method is for dictionary developers) make an AVP from a tagged u32 value.
    ///
    /// Per RFC 2868, tagged-integer attributes carry a **3-byte** value field (the
    /// high byte of the `u32` is silently discarded), giving a total wire length of 6.
    #[must_use]
    pub fn from_tagged_u32(typ: AVPType, tag: Option<&Tag>, value: u32) -> Self {
        let tag_val = tag.map_or(UNUSED_TAG_VALUE, |t| t.value);
        let be = u32::to_be_bytes(value);
        let mut buf = BytesMut::with_capacity(4);
        buf.put_u8(tag_val);
        buf.put_slice(&be[1..]); // RFC 2868: value is 3 bytes, not 4
        AVP {
            typ,
            value: buf.freeze(),
        }
    }

    /// (This method is for dictionary developers) make an AVP from a string value.
    #[must_use]
    pub fn from_string(typ: AVPType, value: &str) -> Self {
        AVP {
            typ,
            value: Bytes::copy_from_slice(value.as_bytes()),
        }
    }

    /// (This method is for dictionary developers) make an AVP from a tagged string value.
    #[must_use]
    pub fn from_tagged_string(typ: AVPType, tag: Option<&Tag>, value: &str) -> Self {
        match tag {
            None => AVP {
                typ,
                value: Bytes::copy_from_slice(value.as_bytes()),
            },
            Some(tag) => {
                let mut buf = BytesMut::with_capacity(1 + value.len());
                buf.put_u8(tag.value);
                buf.put_slice(value.as_bytes());
                AVP {
                    typ,
                    value: buf.freeze(),
                }
            }
        }
    }

    /// (This method is for dictionary developers) make an AVP from bytes.
    #[must_use]
    pub fn from_bytes(typ: AVPType, value: &[u8]) -> Self {
        AVP {
            typ,
            value: Bytes::copy_from_slice(value),
        }
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
    #[allow(clippy::cast_possible_truncation)]
    pub fn from_vsa(vendor_id: u32, vendor_type: u8, payload: &[u8]) -> Self {
        assert!(
            payload.len() <= 253,
            "VSA payload too large: {} bytes (max 253)",
            payload.len()
        );
        let mut buf = BytesMut::with_capacity(6 + payload.len());
        buf.put_u32(vendor_id);
        buf.put_u8(vendor_type);
        buf.put_u8((2 + payload.len()) as u8);
        buf.put_slice(payload);
        AVP {
            typ: VENDOR_SPECIFIC_TYPE,
            value: buf.freeze(),
        }
    }

    /// If this AVP is a Vendor-Specific (type 26) attribute matching `(vendor_id, vendor_type)`,
    /// return the inner value bytes. Otherwise return `None`.
    #[must_use]
    pub fn decode_vsa(&self, vendor_id: u32, vendor_type: u8) -> Option<Bytes> {
        if self.typ != VENDOR_SPECIFIC_TYPE || self.value.len() < 6 {
            return None;
        }
        let vid = u32::from_be_bytes([self.value[0], self.value[1], self.value[2], self.value[3]]);
        if vid != vendor_id || self.value[4] != vendor_type {
            return None;
        }
        let vlen = self.value[5] as usize;
        if vlen < 2 || 6 + vlen - 2 > self.value.len() {
            return None;
        }
        Some(self.value.slice(6..6 + vlen - 2))
    }

    /// (This method is for dictionary developers) make an AVP from a IPv4 value.
    #[must_use]
    pub fn from_ipv4(typ: AVPType, value: &Ipv4Addr) -> Self {
        AVP {
            typ,
            value: Bytes::copy_from_slice(&value.octets()),
        }
    }

    /// (This method is for dictionary developers) make an AVP from a IPv4-prefix value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if `prefix` is not exactly 4 bytes.
    ///
    /// # Panics
    ///
    /// Panics if the length check logic is somehow bypassed (cannot happen in normal use).
    pub fn from_ipv4_prefix(typ: AVPType, prefix: &[u8]) -> Result<Self, AVPError> {
        let prefix_len = prefix.len();
        if prefix_len != 4 {
            return Err(AVPError::InvalidAttributeLengthError(
                "4 bytes".to_owned(),
                prefix_len,
            ));
        }

        let mut buf = BytesMut::with_capacity(2 + prefix_len);
        buf.put_u8(0x00);
        buf.put_u8(u8::try_from(prefix_len).unwrap() & 0b0011_1111);
        buf.put_slice(prefix);
        Ok(AVP {
            typ,
            value: buf.freeze(),
        })
    }

    /// (This method is for dictionary developers) make an AVP from a IPv6 value.
    #[must_use]
    pub fn from_ipv6(typ: AVPType, value: &Ipv6Addr) -> Self {
        AVP {
            typ,
            value: Bytes::copy_from_slice(&value.octets()),
        }
    }

    /// (This method is for dictionary developers) make an AVP from a IPv6-prefix value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if `prefix` exceeds 16 bytes.
    ///
    /// # Panics
    ///
    /// Panics if the length check logic is somehow bypassed (cannot happen in normal use).
    pub fn from_ipv6_prefix(typ: AVPType, prefix: &[u8]) -> Result<Self, AVPError> {
        let prefix_len = prefix.len();
        if prefix_len > 16 {
            return Err(AVPError::InvalidAttributeLengthError(
                "16 bytes".to_owned(),
                prefix_len,
            ));
        }

        let mut buf = BytesMut::with_capacity(2 + prefix_len);
        buf.put_u8(0x00);
        buf.put_u8(u8::try_from(prefix_len * 8).unwrap());
        buf.put_slice(prefix);
        Ok(AVP {
            typ,
            value: buf.freeze(),
        })
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
        // Call the shared secret S and the pseudo-random 128-bit Request
        // Authenticator RA.  Break the password into 16-octet chunks p1, p2,
        // etc.  with the last one padded at the end with nulls to a 16-octet
        // boundary.  Call the ciphertext blocks c(1), c(2), etc.  We'll need
        // intermediate values b1, b2, etc.
        //
        //    b1 = MD5(S + RA)       c(1) = p1 xor b1
        //    b2 = MD5(S + c(1))     c(2) = p2 xor b2
        //           .                       .
        //           .                       .
        //           .                       .
        //    bi = MD5(S + c(i-1))   c(i) = pi xor bi
        //
        // ref: https://tools.ietf.org/html/rfc2865#section-5.2

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

        // Pre-allocate a single buffer for MD5 inputs: secret || prev_block (16 bytes).
        // Reusing it avoids a heap allocation on every iteration.
        let secret_len = secret.len();
        let mut md5_input = Vec::with_capacity(secret_len + 16);
        md5_input.extend_from_slice(secret);
        md5_input.extend_from_slice(request_authenticator);

        if plain_text.is_empty() {
            let enc_block = crypto::md5(&md5_input);
            return Ok(AVP {
                typ,
                value: Bytes::copy_from_slice(&enc_block),
            });
        }

        let num_chunks = plain_text.len().div_ceil(16);
        let mut enc = BytesMut::with_capacity(num_chunks * 16);
        for chunk in plain_text.chunks(16) {
            // Zero-pad the chunk to 16 bytes on the stack — no heap allocation.
            let mut padded = [0u8; 16];
            padded[..chunk.len()].copy_from_slice(chunk);

            let enc_block = crypto::md5(&md5_input);
            let mut block = [0u8; 16];
            for (i, (&d, p)) in enc_block.iter().zip(padded).enumerate() {
                block[i] = d ^ p;
            }
            enc.put_slice(&block);

            // Next iteration hashes secret || this ciphertext block.
            md5_input.truncate(secret_len);
            md5_input.extend_from_slice(&block);
        }

        Ok(AVP {
            typ,
            value: enc.freeze(),
        })
    }

    /// (This method is for dictionary developers) make an AVP from a date value.
    #[must_use]
    pub fn from_date(typ: AVPType, dt: &SystemTime) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        // RADIUS timestamp field is 32-bit by protocol design
        let secs = dt.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as u32;
        AVP {
            typ,
            value: Bytes::copy_from_slice(&u32::to_be_bytes(secs)),
        }
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
        /*
         *   0                   1                   2                   3
         *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |     Type      |    Length     |     Tag       |   Salt
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *     Salt (cont)  |   String ...
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *
         *    b(1) = MD5(S + R + A)    c(1) = p(1) xor b(1)   C = c(1)
         *    b(2) = MD5(S + c(1))     c(2) = p(2) xor b(2)   C = C + c(2)
         *                .                      .
         *                .                      .
         *                .                      .
         *    b(i) = MD5(S + c(i-1))   c(i) = p(i) xor b(i)   C = C + c(i)
         *
         *  The resulting encrypted String field will contain
         *  c(1)+c(2)+...+c(i).
         *
         *  https://tools.ietf.org/html/rfc2868#section-3.5
         */

        if secret.is_empty() {
            return Err(AVPError::PasswordSecretMissingError());
        }

        if request_authenticator.len() != 16 {
            return Err(AVPError::InvalidRequestAuthenticatorLengthError());
        }

        let mut salt = [0u8; 2];
        crypto::fill_random(&mut salt);
        salt[0] |= 0x80;

        // RFC 2868 §3.5: the plaintext to encrypt is [length(1)][data][zero-padding].
        // The length byte records how many bytes of actual data follow.
        // num_chunks = ceil((1 + plain_text.len()) / 16)
        let data_len = 1 + plain_text.len(); // 1 for the RFC 2868 length prefix
        let num_chunks = data_len.div_ceil(16);
        let mut enc = BytesMut::with_capacity(3 + num_chunks * 16);
        enc.put_u8(tag.map_or(UNUSED_TAG_VALUE, |v| v.value));
        enc.put_slice(&salt);

        // Pre-allocate a reusable MD5 input buffer.
        // Round 1:  MD5(secret || request_authenticator || salt)  (18-byte suffix)
        // Round N:  MD5(secret || prev_ciphertext_block)          (16-byte suffix)
        let secret_len = secret.len();
        let mut md5_input = Vec::with_capacity(secret_len + 18);
        md5_input.extend_from_slice(secret);
        md5_input.extend_from_slice(request_authenticator);
        md5_input.extend_from_slice(&salt);

        // Build the RFC 2868 plaintext buffer: [length(1)][data][zeros...].
        let padded_len = num_chunks * 16;
        let mut padded = vec![0u8; padded_len];
        padded[0] = plain_text.len() as u8; // RFC 2868 §3.5 length prefix
        padded[1..1 + plain_text.len()].copy_from_slice(plain_text);

        for chunk in padded.chunks(16) {
            let enc_block = crypto::md5(&md5_input);
            let mut block = [0u8; 16];
            for (i, (&k, &p)) in enc_block.iter().zip(chunk.iter()).enumerate() {
                block[i] = k ^ p;
            }
            enc.put_slice(&block);

            // Next iteration hashes secret || this ciphertext block.
            md5_input.truncate(secret_len);
            md5_input.extend_from_slice(&block);
        }

        Ok(AVP {
            typ,
            value: enc.freeze(),
        })
    }

    /// (This method is for dictionary developers) encode an AVP into a u32 value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is not exactly 4 bytes.
    pub fn encode_u32(&self) -> Result<u32, AVPError> {
        const U32_SIZE: usize = std::mem::size_of::<u32>();
        let array: [u8; U32_SIZE] = self.value[..].try_into().map_err(|_| {
            AVPError::InvalidAttributeLengthError(format!("{U32_SIZE} bytes"), self.value.len())
        })?;
        Ok(u32::from_be_bytes(array))
    }

    /// (This method is for dictionary developers) encode an AVP into a u16 value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is not exactly 2 bytes.
    pub fn encode_u16(&self) -> Result<u16, AVPError> {
        const U16_SIZE: usize = std::mem::size_of::<u16>();
        let array: [u8; U16_SIZE] = self.value[..].try_into().map_err(|_| {
            AVPError::InvalidAttributeLengthError(format!("{U16_SIZE} bytes"), self.value.len())
        })?;
        Ok(u16::from_be_bytes(array))
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
        if self.value.is_empty() {
            return Err(AVPError::TagMissingError());
        }

        let tag = Tag {
            value: self.value[0],
        };

        // ref RFC2868:
        //   Valid values for this field are 0x01 through 0x1F,
        //   inclusive.  If the Tag field is unused, it MUST be zero (0x00)
        if !tag.is_valid_value() && !tag.is_zero() {
            return Err(AVPError::InvalidTagForIntegerValueError());
        }

        if self.value[1..].len() != VALUE_SIZE {
            return Err(AVPError::InvalidAttributeLengthError(
                format!("{} bytes", VALUE_SIZE + 1),
                self.value.len(),
            ));
        }
        let v = u32::from_be_bytes([0, self.value[1], self.value[2], self.value[3]]);
        Ok((v, tag))
    }

    /// (This method is for dictionary developers) encode an AVP into a string value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::DecodingError`] if the bytes are not valid UTF-8.
    pub fn encode_string(&self) -> Result<String, AVPError> {
        match std::str::from_utf8(&self.value) {
            Ok(s) => Ok(s.to_owned()),
            Err(e) => Err(AVPError::DecodingError(e.to_string())),
        }
    }

    /// (This method is for dictionary developers) encode an AVP into a tag and string value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError`] if the tag byte is missing, the tag is zero (invalid), or the
    /// bytes are not valid UTF-8.
    pub fn encode_tagged_string(&self) -> Result<(String, Option<Tag>), AVPError> {
        if self.value.is_empty() {
            return Err(AVPError::TagMissingError());
        }

        let tag = Tag {
            value: self.value[0],
        };

        // ref RFC2868:
        //   If the value of the Tag field is greater than 0x00
        //   and less than or equal to 0x1F, it SHOULD be interpreted as
        //   indicating which tunnel (of several alternatives) this attribute
        //   pertains.
        if tag.is_valid_value() {
            return match std::str::from_utf8(&self.value[1..]) {
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
        match std::str::from_utf8(&self.value) {
            Ok(s) => Ok((s.to_owned(), None)),
            Err(e) => Err(AVPError::DecodingError(e.to_string())),
        }
    }

    /// (This method is for dictionary developers) encode an AVP into bytes.
    #[must_use]
    pub fn encode_bytes(&self) -> Box<[u8]> {
        Box::from(self.value.as_ref())
    }

    /// (This method is for dictionary developers) encode an AVP into Ipv4 value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is not exactly 4 bytes.
    pub fn encode_ipv4(&self) -> Result<Ipv4Addr, AVPError> {
        const IPV4_SIZE: usize = std::mem::size_of::<Ipv4Addr>();
        let array: [u8; IPV4_SIZE] = self.value[..].try_into().map_err(|_| {
            AVPError::InvalidAttributeLengthError(format!("{IPV4_SIZE} bytes"), self.value.len())
        })?;
        Ok(Ipv4Addr::from(array))
    }

    /// (This method is for dictionary developers) encode an AVP into Ipv4-prefix value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is not exactly 6 bytes.
    pub fn encode_ipv4_prefix(&self) -> Result<Box<[u8]>, AVPError> {
        if self.value.len() == 6 {
            Ok(Box::from(&self.value[2..]))
        } else {
            Err(AVPError::InvalidAttributeLengthError(
                "6 bytes".to_owned(),
                self.value.len(),
            ))
        }
    }

    /// (This method is for dictionary developers) encode an AVP into Ipv6 value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is not exactly 16 bytes.
    pub fn encode_ipv6(&self) -> Result<Ipv6Addr, AVPError> {
        const IPV6_SIZE: usize = std::mem::size_of::<Ipv6Addr>();
        let array: [u8; IPV6_SIZE] = self.value[..].try_into().map_err(|_| {
            AVPError::InvalidAttributeLengthError(format!("{IPV6_SIZE} bytes"), self.value.len())
        })?;
        Ok(Ipv6Addr::from(array))
    }

    /// (This method is for dictionary developers) encode an AVP into Ipv6-prefix value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is shorter than 2 bytes.
    pub fn encode_ipv6_prefix(&self) -> Result<Box<[u8]>, AVPError> {
        if self.value.len() >= 2 {
            Ok(Box::from(&self.value[2..]))
        } else {
            Err(AVPError::InvalidAttributeLengthError(
                "2+ bytes".to_owned(),
                self.value.len(),
            ))
        }
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
        if self.value.len() < 16 || self.value.len() > 128 {
            return Err(AVPError::InvalidAttributeLengthError(
                "16 >= bytes && 128 <= bytes".to_owned(),
                self.value.len(),
            ));
        }

        if secret.is_empty() {
            return Err(AVPError::PasswordSecretMissingError());
        }

        if request_authenticator.len() != 16 {
            return Err(AVPError::InvalidRequestAuthenticatorLengthError());
        }

        let secret_len = secret.len();
        let mut dec: Vec<u8> = Vec::with_capacity(self.value.len());
        let mut md5_input = Vec::with_capacity(secret_len + 16);
        md5_input.extend_from_slice(secret);
        md5_input.extend_from_slice(request_authenticator);

        // NOTE:
        // It ensures attribute value has 16 bytes length at least because the value is encoded by md5.
        // And this must be aligned by each 16 bytes length.
        for chunk in self.value.chunks(16) {
            let dec_block = crypto::md5(&md5_input);
            for (&d, &p) in dec_block.iter().zip(chunk) {
                dec.push(d ^ p);
            }
            // Next iteration hashes secret || this ciphertext chunk.
            md5_input.truncate(secret_len);
            md5_input.extend_from_slice(chunk);
        }

        // Strip RFC 2865 §5.2 trailing null padding by scanning from the end.
        let end = dec.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        dec.truncate(end);
        Ok(dec)
    }

    /// (This method is for dictionary developers) encode an AVP into date value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is not exactly 4 bytes.
    pub fn encode_date(&self) -> Result<SystemTime, AVPError> {
        const U32_SIZE: usize = std::mem::size_of::<u32>();
        let array: [u8; U32_SIZE] = self.value[..].try_into().map_err(|_| {
            AVPError::InvalidAttributeLengthError(format!("{U32_SIZE}"), self.value.len())
        })?;
        let timestamp = u32::from_be_bytes(array);
        Ok(UNIX_EPOCH + Duration::from_secs(u64::from(timestamp)))
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
        if self.value.len() < 19 || self.value.len() > 243 || (self.value.len() - 3) % 16 != 0 {
            return Err(AVPError::InvalidAttributeLengthError(
                "19 <= bytes && bytes <= 243 && (bytes - 3) % 16 == 0".to_owned(),
                self.value.len(),
            ));
        }

        if self.value[1] & 0x80 != 0x80 {
            // salt
            return Err(AVPError::InvalidSaltMSBError(self.value[1]));
        }

        if secret.is_empty() {
            return Err(AVPError::PasswordSecretMissingError());
        }

        if request_authenticator.len() != 16 {
            return Err(AVPError::InvalidRequestAuthenticatorLengthError());
        }

        let tag = Tag {
            value: self.value[0],
        };
        let ciphertext = &self.value[3..];
        let secret_len = secret.len();
        let mut dec = Vec::with_capacity(ciphertext.len());
        // Round 1: MD5(secret || request_authenticator || salt)
        // Round N: MD5(secret || prev_ciphertext_chunk)
        let mut md5_input = Vec::with_capacity(secret_len + 18);
        md5_input.extend_from_slice(secret);
        md5_input.extend_from_slice(request_authenticator);
        md5_input.extend_from_slice(&self.value[1..3]); // salt

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
        Ok((dec[1..1 + length].to_vec(), tag))
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
        assert_eq!(avp.value.len(), 4); // tag(1) + value(3)
        assert_eq!(avp.encode_tagged_u32()?, (given_u32, Tag::new_unused()));

        let tag = Tag::new(2);
        let avp = AVP::from_tagged_u32(1, Some(&tag), given_u32);
        assert_eq!(avp.encode_tagged_u32()?, (given_u32, tag));

        // Verify exact wire bytes match FreeRADIUS output for Tunnel-Type VLAN(13) Tag=0x00:
        // AVP value field (excluding RADIUS type/length bytes): 0x00, 0x00, 0x00, 0x0d
        let avp_vlan = AVP::from_tagged_u32(64, None, 13);
        assert_eq!(&avp_vlan.value[..], &[0x00, 0x00, 0x00, 0x0d]);
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
            assert_eq!(avp.value.len(), test_case.expected_encoded_len);

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
            assert_eq!(avp.value.len(), test_case.expected_encoded_len);

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
            AVP {
                typ: 1,
                value: bytes::Bytes::new()
            }
            .encode_ipv4_prefix()
            .unwrap_err(),
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
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::from_static(b"\x01\x02\x03"),
        };
        assert_eq!(
            avp.encode_u32().unwrap_err(),
            AVPError::InvalidAttributeLengthError("4 bytes".to_owned(), 3)
        );
    }

    #[test]
    fn encode_u16_should_fail_on_wrong_length() {
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::from_static(b"\x01\x02\x03"),
        };
        assert_eq!(
            avp.encode_u16().unwrap_err(),
            AVPError::InvalidAttributeLengthError("2 bytes".to_owned(), 3)
        );
    }

    #[test]
    fn encode_tagged_u32_should_fail_on_empty_value() {
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::new(),
        };
        assert_eq!(
            avp.encode_tagged_u32().unwrap_err(),
            AVPError::TagMissingError()
        );
    }

    #[test]
    fn encode_tagged_u32_should_fail_on_invalid_tag() {
        // Tag 0x20 is non-zero and > 0x1f, which is invalid
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::from_static(b"\x20\x00\x00\x00\x01"),
        };
        assert_eq!(
            avp.encode_tagged_u32().unwrap_err(),
            AVPError::InvalidTagForIntegerValueError()
        );
    }

    #[test]
    fn encode_tagged_u32_should_fail_on_wrong_payload_size() {
        // Valid tag 0x01 but only 2 bytes of payload instead of 3 (RFC 2868 requires 3)
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::from_static(b"\x01\x00\x01"),
        };
        assert_eq!(
            avp.encode_tagged_u32().unwrap_err(),
            AVPError::InvalidAttributeLengthError("4 bytes".to_owned(), 3)
        );
    }

    #[test]
    fn encode_tagged_string_should_fail_on_empty_value() {
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::new(),
        };
        assert_eq!(
            avp.encode_tagged_string().unwrap_err(),
            AVPError::TagMissingError()
        );
    }

    #[test]
    fn encode_string_should_fail_on_invalid_utf8() {
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::from_static(b"\xff\xfe"),
        };
        assert!(matches!(
            avp.encode_string().unwrap_err(),
            AVPError::DecodingError(_)
        ));
    }

    #[test]
    fn encode_ipv4_should_fail_on_wrong_length() {
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::from_static(b"\x01\x02\x03"),
        };
        assert_eq!(
            avp.encode_ipv4().unwrap_err(),
            AVPError::InvalidAttributeLengthError("4 bytes".to_owned(), 3)
        );
    }

    #[test]
    fn encode_ipv6_should_fail_on_wrong_length() {
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::from(vec![0u8; 15]),
        };
        assert_eq!(
            avp.encode_ipv6().unwrap_err(),
            AVPError::InvalidAttributeLengthError("16 bytes".to_owned(), 15)
        );
    }

    #[test]
    fn encode_ipv6_prefix_should_fail_on_too_short_value() {
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::from_static(b"\x01"),
        };
        assert_eq!(
            avp.encode_ipv6_prefix().unwrap_err(),
            AVPError::InvalidAttributeLengthError("2+ bytes".to_owned(), 1)
        );
    }

    #[test]
    fn encode_date_should_fail_on_wrong_length() {
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::from_static(b"\x01\x02\x03"),
        };
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
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::from(vec![0u8; 10]),
        };
        assert_eq!(
            avp.encode_user_password(b"s", b"0123456789abcdef")
                .unwrap_err(),
            AVPError::InvalidAttributeLengthError("16 >= bytes && 128 <= bytes".to_owned(), 10)
        );
        // value > 128 bytes
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::from(vec![0u8; 144]),
        };
        assert_eq!(
            avp.encode_user_password(b"s", b"0123456789abcdef")
                .unwrap_err(),
            AVPError::InvalidAttributeLengthError("16 >= bytes && 128 <= bytes".to_owned(), 144)
        );
    }

    #[test]
    fn encode_user_password_should_fail_on_missing_secret() {
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::from(vec![0u8; 16]),
        };
        assert_eq!(
            avp.encode_user_password(b"", b"0123456789abcdef")
                .unwrap_err(),
            AVPError::PasswordSecretMissingError()
        );
    }

    #[test]
    fn encode_user_password_should_fail_on_wrong_authenticator_length() {
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::from(vec![0u8; 16]),
        };
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
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::from(vec![0u8; 10]),
        };
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
        let mut value = vec![0u8; 19];
        value[1] = 0x00; // MSB not set
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::from(value),
        };
        assert_eq!(
            avp.encode_tunnel_password(b"secret", b"0123456789abcdef")
                .unwrap_err(),
            AVPError::InvalidSaltMSBError(0x00)
        );
    }

    #[test]
    fn encode_tunnel_password_should_fail_on_missing_secret() {
        let mut value = vec![0u8; 19];
        value[1] = 0x80; // MSB set (valid salt)
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::from(value),
        };
        assert_eq!(
            avp.encode_tunnel_password(b"", b"0123456789abcdef")
                .unwrap_err(),
            AVPError::PasswordSecretMissingError()
        );
    }

    #[test]
    fn encode_tunnel_password_should_fail_on_wrong_authenticator_length() {
        let mut value = vec![0u8; 19];
        value[1] = 0x80; // MSB set (valid salt)
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::from(value),
        };
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
                avp.value.len(),
                *expected_value_len,
                "wrong value length for {}-byte plaintext",
                plaintext.len()
            );
            // Ciphertext portion (after tag + salt) must be a multiple of 16.
            let ciphertext_len = avp.value.len() - 3;
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
        assert_eq!(avp.value[0], 0x1f, "tag byte mismatch");
        // Byte 1: salt high byte — MSB must be set (RFC 2868 §3.5).
        assert_eq!(avp.value[1] & 0x80, 0x80, "salt MSB not set");
        // Total value = tag(1) + salt(2) + ciphertext(16n).
        assert_eq!(
            (avp.value.len() - 3) % 16,
            0,
            "ciphertext not 16-byte aligned"
        );

        // No-tag encode (tag byte must be 0x00).
        let avp_notag = AVP::from_tunnel_password(69, None, b"pw", secret, req_auth).unwrap();
        assert_eq!(
            avp_notag.value[0], 0x00,
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
    ///   request_auth    = b"0123456789abcdef"
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
        padded[0] = plaintext.len() as u8; // 0x05
        padded[1..1 + plaintext.len()].copy_from_slice(plaintext);

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

        let avp = AVP {
            typ: 69,
            value: bytes::Bytes::from(wire),
        };
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
