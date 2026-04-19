//! EAP (Extensible Authentication Protocol) support for 802.1X / RFC 3748 & RFC 3579.
//!
//! It provides:
//! - [`EapCode`] — the four EAP packet codes.
//! - [`EapType`] — common EAP method types carried in Request/Response packets.
//! - [`EapPacket`] — a parsed EAP packet with encode/decode support.
//! - [`EapError`] — parse errors.
//!
//! EAP packets are carried inside RADIUS `EAP-Message` attributes (type 79).
//! The `Message-Authenticator` attribute (type 80) is computed with HMAC-MD5
//! over the RADIUS packet; see [`crate::core::packet::Packet::add_message_authenticator`]
//! and [`crate::core::packet::Packet::verify_message_authenticator`].

use bytes::Bytes;
use thiserror::Error;

// ── RADIUS attribute types (RFC 3579) ─────────────────────────────────────────

/// RADIUS `EAP-Message` attribute type (RFC 3579 §3.1).
///
/// A single EAP packet may be fragmented across multiple consecutive
/// `EAP-Message` attributes, each carrying at most 253 octets.
pub const EAP_MESSAGE_TYPE: u8 = 79;

/// RADIUS `Message-Authenticator` attribute type (RFC 3579 §3.2).
///
/// Value is a 16-byte HMAC-MD5 keyed with the shared secret, computed over
/// the entire RADIUS packet with the `Message-Authenticator` value set to
/// all-zeros.  **Must** be present whenever `EAP-Message` is present.
pub const MESSAGE_AUTHENTICATOR_TYPE: u8 = 80;

// ── EAP Code ──────────────────────────────────────────────────────────────────

/// EAP packet code (RFC 3748 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EapCode {
    /// The authenticator is challenging the peer.
    Request = 1,
    /// The peer is answering a challenge.
    Response = 2,
    /// Authentication succeeded.
    Success = 3,
    /// Authentication failed.
    Failure = 4,
}

impl EapCode {
    /// Convert a raw byte to an `EapCode`, returning `None` for unknown values.
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Request),
            2 => Some(Self::Response),
            3 => Some(Self::Success),
            4 => Some(Self::Failure),
            _ => None,
        }
    }
}

// ── EAP Type ──────────────────────────────────────────────────────────────────

/// EAP method type byte, present in Request and Response packets (RFC 3748 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EapType {
    /// Peer identity request (RFC 3748 §5.1).
    Identity,
    /// Human-readable notification (RFC 3748 §5.2).
    Notification,
    /// Peer's preferred method list (Response only, RFC 3748 §5.3).
    Nak,
    /// CHAP-style challenge using MD5 (RFC 3748 §5.4).
    Md5Challenge,
    /// One-Time Password (RFC 3748 §5.5).
    Otp,
    /// Generic Token Card (RFC 3748 §5.6).
    Gtc,
    /// EAP-TLS (RFC 5216).
    Tls,
    /// EAP-TTLS (RFC 5281).
    Ttls,
    /// PEAP (draft-josefsson-pppext-eap-tls-eap).
    Peap,
    /// EAP-MS-CHAPv2 (Microsoft).
    MsChapV2,
    /// EAP-FAST (RFC 4851).
    Fast,
    /// EAP-PWD (RFC 5931).
    Pwd,
    /// An unrecognised type value.
    Other(u8),
}

impl EapType {
    /// Convert a raw byte to an `EapType`.
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Identity,
            2 => Self::Notification,
            3 => Self::Nak,
            4 => Self::Md5Challenge,
            5 => Self::Otp,
            6 => Self::Gtc,
            13 => Self::Tls,
            21 => Self::Ttls,
            25 => Self::Peap,
            26 => Self::MsChapV2,
            43 => Self::Fast,
            52 => Self::Pwd,
            other => Self::Other(other),
        }
    }

    /// Return the raw byte value of this type.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Identity => 1,
            Self::Notification => 2,
            Self::Nak => 3,
            Self::Md5Challenge => 4,
            Self::Otp => 5,
            Self::Gtc => 6,
            Self::Tls => 13,
            Self::Ttls => 21,
            Self::Peap => 25,
            Self::MsChapV2 => 26,
            Self::Fast => 43,
            Self::Pwd => 52,
            Self::Other(v) => v,
        }
    }
}

// ── EapError ──────────────────────────────────────────────────────────────────

/// Errors that can occur while parsing an EAP packet.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum EapError {
    /// The byte slice is shorter than the minimum 4-byte EAP header.
    #[error("EAP packet too short: need at least 4 bytes, got {0}")]
    TooShort(usize),

    /// The `Length` field in the header is inconsistent with the slice length.
    #[error("EAP length field {declared} does not match available data {available}")]
    LengthMismatch { declared: u16, available: usize },

    /// The Code byte is not one of the four defined codes (1–4).
    #[error("unknown EAP code: {0}")]
    UnknownCode(u8),

    /// A Request or Response packet has no Type byte (Length == 4).
    #[error("EAP Request/Response packet is missing the Type byte")]
    MissingType,
}

// ── EapPacket ─────────────────────────────────────────────────────────────────

/// A parsed EAP packet (RFC 3748 §4).
///
/// The `data` field carries everything that follows the 4-byte header:
/// - For `Request` and `Response`: `data[0]` is the Type byte and `data[1..]`
///   is the method-specific Type-Data.
/// - For `Success` and `Failure`: `data` is empty.
///
/// # Wire format
///
/// ```text
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Code      |  Identifier   |            Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Type       |  Type-Data …  (Request/Response only)
/// +-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapPacket {
    /// EAP code: Request, Response, Success, or Failure.
    pub code: EapCode,
    /// Per-conversation sequence number chosen by the authenticator.
    pub identifier: u8,
    /// Payload after the 4-byte header (includes the Type byte for
    /// Request/Response; empty for Success/Failure).
    pub data: Bytes,
}

impl EapPacket {
    /// Construct a new Request or Response packet.
    ///
    /// `eap_type` becomes `data[0]`; `type_data` is appended as `data[1..]`.
    #[must_use]
    pub fn new_request_response(
        code: EapCode,
        identifier: u8,
        eap_type: EapType,
        type_data: &[u8],
    ) -> Self {
        debug_assert!(
            matches!(code, EapCode::Request | EapCode::Response),
            "use new_success_failure for Success/Failure packets"
        );
        let mut data = Vec::with_capacity(1 + type_data.len());
        data.push(eap_type.as_u8());
        data.extend_from_slice(type_data);
        Self {
            code,
            identifier,
            data: Bytes::from(data),
        }
    }

    /// Construct a Success or Failure packet.
    #[must_use]
    pub fn new_success_failure(code: EapCode, identifier: u8) -> Self {
        debug_assert!(
            matches!(code, EapCode::Success | EapCode::Failure),
            "use new_request_response for Request/Response packets"
        );
        Self {
            code,
            identifier,
            data: Bytes::new(),
        }
    }

    /// Parse an EAP packet from raw bytes (e.g. concatenated `EAP-Message` AVP values).
    ///
    /// # Errors
    ///
    /// Returns [`EapError`] if the slice is malformed.
    pub fn decode(bs: &[u8]) -> Result<Self, EapError> {
        if bs.len() < 4 {
            return Err(EapError::TooShort(bs.len()));
        }
        let code_byte = bs[0];
        let identifier = bs[1];
        let declared_len_raw = u16::from_be_bytes([bs[2], bs[3]]);
        let declared_len = declared_len_raw as usize;

        if declared_len < 4 {
            return Err(EapError::TooShort(declared_len));
        }
        if declared_len > bs.len() {
            return Err(EapError::LengthMismatch {
                declared: declared_len_raw,
                available: bs.len(),
            });
        }

        let code = EapCode::from_u8(code_byte).ok_or(EapError::UnknownCode(code_byte))?;

        let data_bytes = &bs[4..declared_len];

        match code {
            EapCode::Request | EapCode::Response => {
                if data_bytes.is_empty() {
                    return Err(EapError::MissingType);
                }
            }
            EapCode::Success | EapCode::Failure => {}
        }

        Ok(Self {
            code,
            identifier,
            data: Bytes::copy_from_slice(data_bytes),
        })
    }

    /// Encode the EAP packet to its wire representation.
    ///
    /// # Panics
    ///
    /// Panics if the encoded length exceeds `u16::MAX` (65 535 bytes), which
    /// cannot happen for any valid EAP packet.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let len = 4 + self.data.len();
        let mut out = Vec::with_capacity(len);
        out.push(self.code as u8);
        out.push(self.identifier);
        out.extend_from_slice(
            &u16::try_from(len)
                .expect("EAP packet length exceeds u16::MAX")
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.data);
        out
    }

    /// Return the EAP method type for Request/Response packets.
    ///
    /// Returns `None` for Success and Failure packets (which carry no Type byte).
    #[must_use]
    pub fn eap_type(&self) -> Option<EapType> {
        self.data.first().map(|&b| EapType::from_u8(b))
    }

    /// Return the method-specific Type-Data for Request/Response packets.
    ///
    /// Returns an empty slice for Success/Failure or a Request/Response with
    /// no Type-Data beyond the Type byte.
    #[must_use]
    pub fn type_data(&self) -> &[u8] {
        if self.data.len() > 1 {
            &self.data[1..]
        } else {
            &[]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_identity_request() {
        let pkt = EapPacket::new_request_response(EapCode::Request, 42, EapType::Identity, b"");
        let encoded = pkt.encode();
        let decoded = EapPacket::decode(&encoded).unwrap();
        assert_eq!(decoded, pkt);
        assert_eq!(decoded.eap_type(), Some(EapType::Identity));
        assert_eq!(decoded.type_data(), b"");
    }

    #[test]
    fn roundtrip_md5_challenge() {
        let type_data = b"\x10challenge_data_16bvalue";
        let pkt =
            EapPacket::new_request_response(EapCode::Request, 1, EapType::Md5Challenge, type_data);
        let encoded = pkt.encode();
        let decoded = EapPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.eap_type(), Some(EapType::Md5Challenge));
        assert_eq!(decoded.type_data(), type_data);
    }

    #[test]
    fn roundtrip_success() {
        let pkt = EapPacket::new_success_failure(EapCode::Success, 7);
        let encoded = pkt.encode();
        let decoded = EapPacket::decode(&encoded).unwrap();
        assert_eq!(decoded, pkt);
        assert_eq!(decoded.eap_type(), None);
    }

    #[test]
    fn decode_too_short() {
        assert_eq!(EapPacket::decode(b"\x01\x02"), Err(EapError::TooShort(2)));
    }

    #[test]
    fn decode_unknown_code() {
        let bytes = [0x09, 0x01, 0x00, 0x05, 0x01];
        assert_eq!(EapPacket::decode(&bytes), Err(EapError::UnknownCode(9)));
    }
}
