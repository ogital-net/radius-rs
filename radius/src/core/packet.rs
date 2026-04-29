use std::convert::TryInto;
use std::fmt::Debug;

use bytes::{Bytes, BytesMut};
use thiserror::Error;

use crate::core::attributes::Attributes;
use crate::core::avp::{AVPType, AVP, VENDOR_SPECIFIC_TYPE};
use crate::core::code::Code;
use crate::core::crypto;

const MAX_PACKET_LENGTH: usize = 4096;
const RADIUS_PACKET_HEADER_LENGTH: usize = 20; // i.e. minimum packet length

#[derive(Error, Debug, PartialEq)]
pub enum PacketError {
    /// An error indicates the entire length of the given packet has insufficient length.
    #[error("RADIUS packet doesn't have enough length of bytes; it has to be at least {0} bytes, but actual length was {1}")]
    InsufficientPacketPayloadLengthError(usize, usize),

    /// An error indicates the length that is instructed by a header is insufficient.
    #[error("RADIUS packet header indicates the length as {0} bytes, but this is insufficient; this must have {1} bytes at least")]
    InsufficientHeaderDefinedPacketLengthError(usize, usize),

    /// An error indicates the length that is instructed by a header exceeds the maximum length of the RADIUS packet.
    #[error("RADIUS packet header indicates the length as {0} bytes, but this exceeds the maximum length {1} bytes")]
    HeaderDefinedPacketLengthExceedsMaximumLimitError(usize, usize),

    /// An error that is raised when an error has been occurred on decoding bytes for a packet.
    #[error("failed to decode the packet: {0}")]
    DecodingError(String),

    /// An error that is raised when an error has been occurred on encoding a packet into bytes.
    #[error("failed to encode the packet: {0}")]
    EncodingError(String),

    /// An error that is raised when it received unknown packet type code of RADIUS.
    #[error("unknown RADIUS packet type code: {0}")]
    UnknownCodeError(String),

    /// This error is raised when computation of hash fails using openssl hash
    #[error("computation of hash failed: {0}")]
    HashComputationFailedError(String),
}

/// This struct represents a packet of RADIUS for request and response.
///
/// # Example
///
/// ```
/// use radius::core::code::Code;
/// use radius::core::packet::Packet;
/// use radius::dict::rfc2865;
///
/// let mut packet = Packet::new(Code::AccessRequest, b"secret");
/// rfc2865::add_user_name(&mut packet, "alice");
/// let bytes = packet.encode().unwrap();
///
/// let decoded = Packet::decode(&bytes, b"secret").unwrap();
/// assert_eq!(decoded.code(), Code::AccessRequest);
/// assert_eq!(rfc2865::lookup_user_name(&decoded).unwrap().unwrap(), "alice");
/// ```
#[derive(Clone)]
pub struct Packet {
    code: Code,
    identifier: u8,
    authenticator: Bytes,
    secret: Bytes,
    attributes: Attributes,
    /// Scratch buffer for the `AVP::from_*_in` family of constructors.
    /// Successive `add_*` calls append into this arena, keeping AVP values
    /// in a single contiguous allocation.  Not part of logical packet equality.
    pub(crate) avp_buf: BytesMut,
}

impl PartialEq for Packet {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
            && self.identifier == other.identifier
            && self.authenticator == other.authenticator
            && self.secret == other.secret
            && self.attributes == other.attributes
    }
}

impl Eq for Packet {}

impl Packet {
    /// Constructor for a Packet.
    ///
    /// By default, this constructor makes an instance with a random identifier value.
    /// If you'd like to set an arbitrary identifier, please use `new_with_identifier()` constructor instead or `set_identifier()` method for created instance.
    #[must_use]
    pub fn new(code: Code, secret: &[u8]) -> Self {
        Self::_new(code, secret, None)
    }

    /// Constructor for a Packet with arbitrary identifier value.
    ///
    /// If you want to make an instance with a random identifier value, please consider using `new()`.
    #[must_use]
    pub fn new_with_identifier(code: Code, secret: &[u8], identifier: u8) -> Self {
        Self::_new(code, secret, Some(identifier))
    }

    fn _new(code: Code, secret: &[u8], maybe_identifier: Option<u8>) -> Self {
        if let Some(ident) = maybe_identifier {
            let authenticator = Bytes::from(crypto::random_bytes(16));
            Packet {
                code,
                identifier: ident,
                authenticator,
                secret: Bytes::copy_from_slice(secret),
                attributes: Attributes(vec![]),
                avp_buf: BytesMut::new(),
            }
        } else {
            // Single RNG call: 16 bytes authenticator + 1 byte identifier
            let mut buf = [0u8; 17];
            crypto::fill_random(&mut buf);
            Packet {
                code,
                identifier: buf[16],
                authenticator: Bytes::copy_from_slice(&buf[..16]),
                secret: Bytes::copy_from_slice(secret),
                attributes: Attributes(vec![]),
                avp_buf: BytesMut::new(),
            }
        }
    }

    #[must_use]
    pub fn code(&self) -> Code {
        self.code
    }

    #[must_use]
    pub fn identifier(&self) -> u8 {
        self.identifier
    }

    #[must_use]
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    #[must_use]
    pub fn authenticator(&self) -> &[u8] {
        &self.authenticator
    }

    /// This sets an identifier value to an instance.
    pub fn set_identifier(&mut self, identifier: u8) {
        self.identifier = identifier;
    }

    /// This decodes bytes into a Packet.
    ///
    /// # Errors
    ///
    /// Returns [`PacketError`] if the byte slice is too short, length fields are invalid, or
    /// the attributes cannot be decoded.
    pub fn decode(bs: &[u8], secret: &[u8]) -> Result<Self, PacketError> {
        if bs.len() < RADIUS_PACKET_HEADER_LENGTH {
            return Err(PacketError::InsufficientPacketPayloadLengthError(
                RADIUS_PACKET_HEADER_LENGTH,
                bs.len(),
            ));
        }

        let len = match bs[2..4].try_into() {
            Ok(v) => u16::from_be_bytes(v),
            Err(e) => return Err(PacketError::DecodingError(e.to_string())),
        } as usize;
        if len < RADIUS_PACKET_HEADER_LENGTH {
            return Err(PacketError::InsufficientHeaderDefinedPacketLengthError(
                len,
                RADIUS_PACKET_HEADER_LENGTH,
            ));
        }
        if len > MAX_PACKET_LENGTH {
            return Err(
                PacketError::HeaderDefinedPacketLengthExceedsMaximumLimitError(
                    len,
                    MAX_PACKET_LENGTH,
                ),
            );
        }
        if bs.len() < len {
            return Err(PacketError::InsufficientPacketPayloadLengthError(
                len,
                bs.len(),
            ));
        }

        let bs_bytes = Bytes::copy_from_slice(&bs[..len]);

        let attributes = match Attributes::decode(&bs_bytes.slice(RADIUS_PACKET_HEADER_LENGTH..len))
        {
            Ok(attributes) => attributes,
            Err(e) => return Err(PacketError::DecodingError(e)),
        };

        Ok(Packet {
            code: Code::from(bs[0]),
            identifier: bs[1],
            authenticator: bs_bytes.slice(4..RADIUS_PACKET_HEADER_LENGTH),
            secret: Bytes::copy_from_slice(secret),
            attributes,
            avp_buf: BytesMut::new(),
        })
    }

    /// This method makes a response packet according to self (i.e. request packet).
    #[must_use]
    pub fn make_response_packet(&self, code: Code) -> Self {
        Packet {
            code,
            identifier: self.identifier,
            authenticator: self.authenticator.clone(),
            secret: self.secret.clone(),
            attributes: Attributes(vec![]),
            avp_buf: BytesMut::new(),
        }
    }

    /// This method encodes the Packet into bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PacketError`] if the packet is too large, encoding fails, or the code is unknown.
    pub fn encode(&self) -> Result<Vec<u8>, PacketError> {
        let mut bs = match self.marshal_binary() {
            Ok(bs) => bs,
            Err(e) => return Err(PacketError::EncodingError(e)),
        };

        match self.code {
            Code::AccessRequest | Code::StatusServer => Ok(bs),
            Code::AccessAccept
            | Code::AccessReject
            | Code::AccountingRequest
            | Code::AccountingResponse
            | Code::AccessChallenge
            | Code::DisconnectRequest
            | Code::DisconnectAck
            | Code::DisconnectNak
            | Code::CoaRequest
            | Code::CoaAck
            | Code::CoaNak => {
                // Compute md5(code|id|len | auth_for_hash | attributes | secret) without
                // allocating an intermediate Vec by using the scatter-gather md5_of.
                // For request types the authenticator field in the hash is all zeros (RFC 2866 §3).
                let auth_for_hash: &[u8] = match self.code {
                    Code::AccountingRequest // see "Request Authenticator" in https://tools.ietf.org/html/rfc2866#section-3
                    | Code::DisconnectRequest // same as "RFC2866"; https://tools.ietf.org/html/rfc5176#section-2.3
                    | Code::CoaRequest // same as "RFC2866"; https://tools.ietf.org/html/rfc5176#section-2.3
                    => &[0u8; 16],
                    _ => &self.authenticator,
                };
                // Compute the digest first (borrowing bs immutably), then store it.
                let digest = crypto::md5_of(&[
                    &bs[..4],
                    auth_for_hash,
                    &bs[RADIUS_PACKET_HEADER_LENGTH..],
                    &self.secret,
                ]);
                bs[4..20].copy_from_slice(&digest);

                Ok(bs)
            }
            _ => Err(PacketError::UnknownCodeError(format!("{:?}", self.code))),
        }
    }

    /*
     * Binary structure:
     *   0                   1                   2                   3
     *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |     Code      |  Identifier   |            Length             |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |                                                               |
     *  |                         Authenticator                         |
     *  |                                                               |
     *  |                                                               |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |  Attributes ...
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-
     */
    fn marshal_binary(&self) -> Result<Vec<u8>, String> {
        let total_size = RADIUS_PACKET_HEADER_LENGTH + self.attributes.total_size();
        if total_size > MAX_PACKET_LENGTH {
            return Err("packet is too large".to_owned());
        }
        let size = u16::try_from(total_size).expect("checked; MAX_PACKET_LENGTH fits in u16");

        let mut bs: Vec<u8> = Vec::with_capacity(total_size);
        bs.push(self.code as u8);
        bs.push(self.identifier);
        bs.extend_from_slice(&u16::to_be_bytes(size));
        bs.extend_from_slice(&self.authenticator);
        self.attributes.encode(&mut bs);
        Ok(bs)
    }

    /// Returns whether the Packet is authentic response or not.
    #[must_use]
    pub fn is_authentic_response(response: &[u8], request: &[u8], secret: &[u8]) -> bool {
        if response.len() < RADIUS_PACKET_HEADER_LENGTH
            || request.len() < RADIUS_PACKET_HEADER_LENGTH
            || secret.is_empty()
        {
            return false;
        }

        // md5(response[..4] || request[4..20] || response[20..] || secret)
        // Use md5_of to avoid allocating an intermediate Vec.
        crypto::md5_of(&[
            &response[..4],
            &request[4..RADIUS_PACKET_HEADER_LENGTH],
            &response[RADIUS_PACKET_HEADER_LENGTH..],
            secret,
        ]) == response[4..RADIUS_PACKET_HEADER_LENGTH]
    }

    /// Returns whether the Packet is authentic request or not.
    #[must_use]
    pub fn is_authentic_request(request: &[u8], secret: &[u8]) -> bool {
        if request.len() < RADIUS_PACKET_HEADER_LENGTH || secret.is_empty() {
            return false;
        }

        match Code::from(request[0]) {
            Code::AccessRequest | Code::StatusServer => true,
            Code::AccountingRequest | Code::DisconnectRequest | Code::CoaRequest => {
                // md5(request[..4] || 0x00*16 || request[20..] || secret)
                crypto::md5_of(&[
                    &request[..4],
                    &[0u8; 16],
                    &request[RADIUS_PACKET_HEADER_LENGTH..],
                    secret,
                ]) == request[4..RADIUS_PACKET_HEADER_LENGTH]
            }
            _ => false,
        }
    }

    /// Returns a mutable reference to the packet's AVP scratch buffer.
    ///
    /// Pass this to the `AVP::from_*_in` family of constructors so that
    /// successive attribute values are written into a single contiguous
    /// allocation rather than each getting their own heap block.
    pub fn avp_buf(&mut self) -> &mut BytesMut {
        &mut self.avp_buf
    }

    /// Add an AVP to the list of AVPs.
    pub fn add(&mut self, avp: AVP) {
        self.attributes.add(avp);
    }

    /// Add AVPs to the list of AVPs.
    pub fn extend(&mut self, avps: Vec<AVP>) {
        self.attributes.extend(avps);
    }

    /// Delete all of AVPs from the list according to given AVP type.
    pub fn delete(&mut self, typ: AVPType) {
        self.attributes.del(typ);
    }

    /// Returns an AVP that matches at first with the given AVP type. If there are not any matched ones, this returns `None`.
    #[must_use]
    pub fn lookup(&self, typ: AVPType) -> Option<&AVP> {
        self.attributes.lookup(typ)
    }

    /// Returns AVPs that match with the given AVP type.
    #[must_use]
    pub fn lookup_all(&self, typ: AVPType) -> Vec<&AVP> {
        self.attributes.lookup_all(typ)
    }

    /// Returns the value bytes of the first Vendor-Specific AVP (type 26) matching
    /// `(vendor_id, vendor_type)`. Returns `None` if no match is found.
    #[must_use]
    pub fn lookup_vsa(&self, vendor_id: u32, vendor_type: u8) -> Option<bytes::Bytes> {
        self.attributes
            .lookup_all(VENDOR_SPECIFIC_TYPE)
            .into_iter()
            .find_map(|avp| avp.decode_vsa(vendor_id, vendor_type))
    }

    /// Returns the value bytes of all Vendor-Specific AVPs (type 26) matching
    /// `(vendor_id, vendor_type)`.
    #[must_use]
    pub fn lookup_all_vsa(&self, vendor_id: u32, vendor_type: u8) -> Vec<bytes::Bytes> {
        self.attributes
            .lookup_all(VENDOR_SPECIFIC_TYPE)
            .into_iter()
            .filter_map(|avp| avp.decode_vsa(vendor_id, vendor_type))
            .collect()
    }

    /// Delete all Vendor-Specific AVPs (type 26) matching `(vendor_id, vendor_type)`.
    pub fn delete_vsa(&mut self, vendor_id: u32, vendor_type: u8) {
        self.attributes.del_vsa(vendor_id, vendor_type);
    }
}

// ── EAP helpers ──────────────────────────────────────────────────────────────

/// Maximum value bytes per `EAP-Message` AVP (RFC 3579 §3.1).
const EAP_MESSAGE_MAX_CHUNK: usize = 253;

impl Packet {
    /// Append one or more `EAP-Message` attributes (type 79) carrying `eap_data`.
    ///
    /// If `eap_data` exceeds 253 bytes it is split into consecutive 253-byte
    /// chunks as required by RFC 3579 §3.1.
    pub fn add_eap_message(&mut self, eap_data: &[u8]) {
        for chunk in eap_data.chunks(EAP_MESSAGE_MAX_CHUNK) {
            self.add(AVP::from_bytes(crate::core::eap::EAP_MESSAGE_TYPE, chunk));
        }
    }

    /// Reassemble and return the concatenated value of all `EAP-Message`
    /// attributes (type 79) in the packet.
    ///
    /// Returns `None` if no `EAP-Message` attribute is present.
    #[must_use]
    pub fn lookup_eap_message(&self) -> Option<Vec<u8>> {
        let avps = self
            .attributes
            .lookup_all(crate::core::eap::EAP_MESSAGE_TYPE);
        if avps.is_empty() {
            return None;
        }
        let mut out: Vec<u8> = Vec::new();
        for avp in avps {
            out.extend_from_slice(avp.value().as_ref());
        }
        Some(out)
    }

    /// Compute and add (or replace) the `Message-Authenticator` attribute
    /// (type 80, RFC 3579 §3.2).
    ///
    /// The MAC is HMAC-MD5 keyed with the packet's shared secret, computed
    /// over the wire-encoded packet with the `Message-Authenticator` value
    /// temporarily set to 16 zero bytes.
    ///
    /// **Call this as the last step before `encode()`**, because `encode()`
    /// updates the packet Authenticator field which is covered by the MAC.
    ///
    /// For response packets created via [`Packet::make_response_packet`] the
    /// internal `authenticator` field still holds the *request* authenticator,
    /// which is what RFC 3579 requires for response MAC computation.
    ///
    /// # Panics
    ///
    /// Panics if the `Message-Authenticator` placeholder that was just inserted
    /// cannot be found (should never happen).
    ///
    /// # Errors
    ///
    /// Returns [`PacketError`] if serialising the packet fails (e.g. it is
    /// too large).
    pub fn add_message_authenticator(&mut self) -> Result<(), PacketError> {
        use crate::core::eap::MESSAGE_AUTHENTICATOR_TYPE;

        // Replace any existing Message-Authenticator with a zeroed placeholder.
        self.attributes.del(MESSAGE_AUTHENTICATOR_TYPE);
        self.add(AVP::from_bytes(MESSAGE_AUTHENTICATOR_TYPE, &[0u8; 16]));

        // Serialise the packet with the zeroed placeholder in place.
        let wire = self.marshal_binary().map_err(PacketError::EncodingError)?;

        // Compute HMAC-MD5 over the wire bytes.
        let mac = crypto::hmac_md5(&self.secret, &wire);

        // Update the placeholder in-place (it is always the last attribute we
        // just added, so the unwrap is safe).
        let avp_ref = self
            .attributes
            .0
            .iter_mut()
            .rev()
            .find(|a| a.typ() == MESSAGE_AUTHENTICATOR_TYPE)
            .unwrap();
        *avp_ref = AVP::from_bytes(MESSAGE_AUTHENTICATOR_TYPE, &mac);

        Ok(())
    }

    /// Verify the `Message-Authenticator` attribute (type 80, RFC 3579 §3.2)
    /// in raw RADIUS wire bytes.
    ///
    /// `request_authenticator` must be the 16-byte authenticator from the
    /// *request* packet:
    /// - When verifying a received **request** (e.g. Access-Request): pass
    ///   `packet_bytes[4..20].try_into().unwrap()`.
    /// - When verifying a received **response** (e.g. Access-Accept): pass
    ///   the authenticator from the Access-Request that was sent.
    ///
    /// Returns `false` if no `Message-Authenticator` attribute is found, the
    /// packet is too short, or the MAC does not match.
    #[must_use]
    pub fn verify_message_authenticator(
        packet_bytes: &[u8],
        request_authenticator: &[u8; 16],
        secret: &[u8],
    ) -> bool {
        use crate::core::eap::MESSAGE_AUTHENTICATOR_TYPE;

        if packet_bytes.len() < RADIUS_PACKET_HEADER_LENGTH {
            return false;
        }

        // Scan the raw attribute list for the Message-Authenticator.
        let mut pos = RADIUS_PACKET_HEADER_LENGTH;
        let mut ma_value_offset: Option<usize> = None;
        let mut saved_mac = [0u8; 16];

        while pos + 2 <= packet_bytes.len() {
            let attr_type = packet_bytes[pos];
            let attr_len = packet_bytes[pos + 1] as usize;
            if attr_len < 2 || pos + attr_len > packet_bytes.len() {
                break;
            }
            if attr_type == MESSAGE_AUTHENTICATOR_TYPE && attr_len == 18 {
                ma_value_offset = Some(pos + 2);
                saved_mac.copy_from_slice(&packet_bytes[pos + 2..pos + 18]);
                // Keep scanning — RFC 3579 says the first one is used, so we
                // stop after finding it.
                break;
            }
            pos += attr_len;
        }

        let Some(ma_offset) = ma_value_offset else {
            return false;
        };

        // Build a modified copy: authenticator = request_authenticator,
        // Message-Authenticator value = 16 zero bytes.
        let mut modified = packet_bytes.to_vec();
        modified[4..20].copy_from_slice(request_authenticator);
        modified[ma_offset..ma_offset + 16].fill(0);

        let computed = crypto::hmac_md5(secret, &modified);
        computed == saved_mac
    }
}

#[allow(clippy::missing_fields_in_debug)] // avp_buf is an internal scratch buffer, not a logical field
impl Debug for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex_auth: String = {
            use std::fmt::Write as _;
            self.authenticator.iter().fold(
                String::with_capacity(self.authenticator.len() * 2),
                |mut s, b| {
                    write!(s, "{b:02x}").unwrap();
                    s
                },
            )
        };
        f.debug_struct("Packet")
            .field(
                "code",
                &format_args!("{} ({})", self.code.as_str(), self.code as u8),
            )
            .field("identifier", &self.identifier)
            .field("authenticator", &hex_auth)
            .field("secret", &"*redacted*")
            .field("attributes", &self.attributes)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::core::avp::AVP;
    use crate::core::code::Code;
    use crate::core::packet::{
        Packet, PacketError, MAX_PACKET_LENGTH, RADIUS_PACKET_HEADER_LENGTH,
    };
    use crate::dict::cisco;
    use crate::dict::rfc2865;

    #[test]
    fn test_for_rfc2865_7_1() -> Result<(), PacketError> {
        // ref: https://tools.ietf.org/html/rfc2865#section-7.1

        let secret: Vec<u8> = "xyzzy5461".as_bytes().to_vec();
        let request: Vec<u8> = vec![
            0x01, 0x00, 0x00, 0x38, 0x0f, 0x40, 0x3f, 0x94, 0x73, 0x97, 0x80, 0x57, 0xbd, 0x83,
            0xd5, 0xcb, 0x98, 0xf4, 0x22, 0x7a, 0x01, 0x06, 0x6e, 0x65, 0x6d, 0x6f, 0x02, 0x12,
            0x0d, 0xbe, 0x70, 0x8d, 0x93, 0xd4, 0x13, 0xce, 0x31, 0x96, 0xe4, 0x3f, 0x78, 0x2a,
            0x0a, 0xee, 0x04, 0x06, 0xc0, 0xa8, 0x01, 0x10, 0x05, 0x06, 0x00, 0x00, 0x00, 0x03,
        ];

        let request_packet = Packet::decode(&request, &secret)?;
        assert_eq!(request_packet.code, Code::AccessRequest);
        assert_eq!(request_packet.identifier, 0);
        assert_eq!(
            rfc2865::lookup_user_name(&request_packet).unwrap().unwrap(),
            "nemo"
        );
        assert_eq!(
            rfc2865::lookup_all_user_name(&request_packet).unwrap(),
            vec!["nemo"],
        );
        assert_eq!(
            rfc2865::lookup_user_password(&request_packet)
                .unwrap()
                .unwrap()
                .as_slice(),
            b"arctangent" as &[u8]
        );
        assert_eq!(
            rfc2865::lookup_nas_ip_address(&request_packet)
                .unwrap()
                .unwrap(),
            Ipv4Addr::from([192, 168, 1, 16]),
        );
        assert_eq!(
            rfc2865::lookup_nas_port(&request_packet).unwrap().unwrap(),
            3
        );
        assert_eq!(request_packet.encode().unwrap(), request);
        assert!(Packet::is_authentic_request(&request, &secret));

        let response: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x26, 0x86, 0xfe, 0x22, 0x0e, 0x76, 0x24, 0xba, 0x2a, 0x10, 0x05,
            0xf6, 0xbf, 0x9b, 0x55, 0xe0, 0xb2, 0x06, 0x06, 0x00, 0x00, 0x00, 0x01, 0x0f, 0x06,
            0x00, 0x00, 0x00, 0x00, 0x0e, 0x06, 0xc0, 0xa8, 0x01, 0x03,
        ];
        let mut response_packet = request_packet.make_response_packet(Code::AccessAccept);
        rfc2865::add_service_type(&mut response_packet, rfc2865::SERVICE_TYPE_LOGIN_USER);
        rfc2865::add_login_service(&mut response_packet, rfc2865::LOGIN_SERVICE_TELNET);
        rfc2865::add_login_ip_host(&mut response_packet, &Ipv4Addr::from([192, 168, 1, 3]));
        assert_eq!(response_packet.encode().unwrap(), response);
        assert!(Packet::is_authentic_response(&response, &request, &secret));

        // test removing a AVP
        assert!(rfc2865::lookup_service_type(&response_packet).is_some());
        rfc2865::delete_service_type(&mut response_packet);
        assert!(rfc2865::lookup_service_type(&response_packet).is_none());

        Ok(())
    }

    #[test]
    fn test_for_rfc2865_7_2() -> Result<(), PacketError> {
        let secret: Vec<u8> = "xyzzy5461".as_bytes().to_vec();
        let request: Vec<u8> = vec![
            0x01, 0x01, 0x00, 0x47, 0x2a, 0xee, 0x86, 0xf0, 0x8d, 0x0d, 0x55, 0x96, 0x9c, 0xa5,
            0x97, 0x8e, 0x0d, 0x33, 0x67, 0xa2, 0x01, 0x08, 0x66, 0x6c, 0x6f, 0x70, 0x73, 0x79,
            0x03, 0x13, 0x16, 0xe9, 0x75, 0x57, 0xc3, 0x16, 0x18, 0x58, 0x95, 0xf2, 0x93, 0xff,
            0x63, 0x44, 0x07, 0x72, 0x75, 0x04, 0x06, 0xc0, 0xa8, 0x01, 0x10, 0x05, 0x06, 0x00,
            0x00, 0x00, 0x14, 0x06, 0x06, 0x00, 0x00, 0x00, 0x02, 0x07, 0x06, 0x00, 0x00, 0x00,
            0x01,
        ];

        let request_packet = Packet::decode(&request, &secret)?;
        assert_eq!(request_packet.code(), Code::AccessRequest);
        assert_eq!(request_packet.identifier, 1);
        assert_eq!(
            rfc2865::lookup_user_name(&request_packet).unwrap().unwrap(),
            "flopsy"
        );
        assert_eq!(
            rfc2865::lookup_nas_ip_address(&request_packet)
                .unwrap()
                .unwrap(),
            Ipv4Addr::from([192, 168, 1, 16]),
        );
        assert_eq!(
            rfc2865::lookup_nas_port(&request_packet).unwrap().unwrap(),
            20
        );
        assert_eq!(
            rfc2865::lookup_service_type(&request_packet)
                .unwrap()
                .unwrap(),
            rfc2865::SERVICE_TYPE_FRAMED_USER,
        );
        assert_eq!(
            rfc2865::lookup_framed_protocol(&request_packet)
                .unwrap()
                .unwrap(),
            rfc2865::FRAMED_PROTOCOL_PPP,
        );

        let response: Vec<u8> = vec![
            0x02, 0x01, 0x00, 0x38, 0x15, 0xef, 0xbc, 0x7d, 0xab, 0x26, 0xcf, 0xa3, 0xdc, 0x34,
            0xd9, 0xc0, 0x3c, 0x86, 0x01, 0xa4, 0x06, 0x06, 0x00, 0x00, 0x00, 0x02, 0x07, 0x06,
            0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0xff, 0xff, 0xff, 0xfe, 0x0a, 0x06, 0x00, 0x00,
            0x00, 0x00, 0x0d, 0x06, 0x00, 0x00, 0x00, 0x01, 0x0c, 0x06, 0x00, 0x00, 0x05,
            //    ^ incorrectly a 2 in the document
            0xdc,
        ];
        let response_packet = Packet::decode(&response, &secret).unwrap();

        assert_eq!(response_packet.code(), Code::AccessAccept);
        assert_eq!(response_packet.identifier(), 1);
        assert_eq!(
            rfc2865::lookup_service_type(&response_packet)
                .unwrap()
                .unwrap(),
            rfc2865::SERVICE_TYPE_FRAMED_USER
        );
        assert_eq!(
            rfc2865::lookup_framed_protocol(&response_packet)
                .unwrap()
                .unwrap(),
            rfc2865::FRAMED_PROTOCOL_PPP,
        );
        assert_eq!(
            rfc2865::lookup_framed_ip_address(&response_packet)
                .unwrap()
                .unwrap(),
            Ipv4Addr::from([255, 255, 255, 254]),
        );
        assert_eq!(
            rfc2865::lookup_framed_routing(&response_packet)
                .unwrap()
                .unwrap(),
            rfc2865::FRAMED_ROUTING_NONE,
        );
        assert_eq!(
            rfc2865::lookup_framed_compression(&response_packet)
                .unwrap()
                .unwrap(),
            rfc2865::FRAMED_COMPRESSION_VAN_JACOBSON_TCP_IP,
        );
        assert_eq!(
            rfc2865::lookup_framed_mtu(&response_packet)
                .unwrap()
                .unwrap(),
            1500,
        );

        Ok(())
    }

    #[test]
    fn test_passwords() {
        let passwords = vec![
            b"".to_vec(),
            b"qwerty".to_vec(),
            b"helloworld1231231231231233489hegufudhsgdsfygdf8g".to_vec(),
        ];

        let secret = b"xyzzy5461";

        for password in passwords {
            let mut request_packet = Packet::new(Code::AccessRequest, secret);
            rfc2865::add_user_password(&mut request_packet, &password).unwrap();

            let encoded = request_packet.encode().unwrap();

            let decoded = Packet::decode(&encoded, secret).unwrap();
            assert_eq!(
                rfc2865::lookup_user_password(&decoded)
                    .unwrap()
                    .unwrap()
                    .as_slice(),
                password.as_slice()
            );
        }
    }

    #[test]
    fn test_parse_invalid() {
        struct TestCase<'a> {
            plain_text: &'a str,
            expected_error: PacketError,
        }

        let test_cases = &[
            TestCase {
                plain_text: "\x01",
                expected_error: PacketError::InsufficientPacketPayloadLengthError(RADIUS_PACKET_HEADER_LENGTH, 1),
            },
            TestCase {
                plain_text: "\x01\x7f\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
                expected_error: PacketError::InsufficientHeaderDefinedPacketLengthError(0, RADIUS_PACKET_HEADER_LENGTH),
            },
            TestCase {
                plain_text: "\x01\x7f\x7f\x7f\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
                expected_error: PacketError::HeaderDefinedPacketLengthExceedsMaximumLimitError(32639, MAX_PACKET_LENGTH),
            },
            TestCase {
                plain_text: "\x00\x7f\x00\x16\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00",
                expected_error: PacketError::InsufficientPacketPayloadLengthError(22, 21),
            },
            TestCase {
                plain_text: "\x01\x01\x00\x16\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00",
                expected_error: PacketError::DecodingError("invalid attribute length".to_owned()),
            }
        ];

        let secret = b"12345";
        for test_case in test_cases {
            let result = Packet::decode(test_case.plain_text.as_bytes(), secret);
            assert!(result.is_err());
            assert_eq!(result.err().unwrap(), test_case.expected_error);
        }
    }

    #[test]
    fn test_packet_attribute_length_boundary() {
        let mut packet = Packet::new(Code::AccessRequest, b"12345");
        packet.add(AVP::from_bytes(1, &vec![1u8; 253]));
        let encoded = packet.encode();
        assert!(encoded.is_ok());
    }

    #[test]
    #[should_panic(expected = "bytes AVP too large")]
    fn test_packet_attribute_too_large_panics() {
        let _ = AVP::from_bytes(1, &vec![1u8; 254]);
    }

    #[test]
    fn test_with_arbitrary_identifier() {
        let mut packet = Packet::new(Code::AccessRequest, b"12345");
        let random_ident = packet.identifier();
        let expected_ident = random_ident + 1;
        packet.set_identifier(expected_ident);
        assert_eq!(packet.identifier(), expected_ident);

        packet = Packet::new_with_identifier(Code::AccessRequest, b"12345", expected_ident);
        assert_eq!(packet.identifier(), expected_ident);
    }

    #[test]
    fn test_extend_adds_multiple_avps() {
        let mut packet = Packet::new(Code::AccessRequest, b"secret");
        let avps = vec![AVP::from_bytes(1, b"alice"), AVP::from_bytes(1, b"bob")];
        packet.extend(avps);
        let all = packet.lookup_all(1);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].encode_bytes().as_ref(), b"alice" as &[u8]);
        assert_eq!(all[1].encode_bytes().as_ref(), b"bob" as &[u8]);
    }

    #[test]
    fn test_is_authentic_response_rejects_invalid_inputs() {
        let valid = vec![0u8; RADIUS_PACKET_HEADER_LENGTH];
        // response too short
        assert!(!Packet::is_authentic_response(
            &valid[..10],
            &valid,
            b"secret"
        ));
        // request too short
        assert!(!Packet::is_authentic_response(
            &valid,
            &valid[..10],
            b"secret"
        ));
        // empty secret
        assert!(!Packet::is_authentic_response(&valid, &valid, b""));
    }

    #[test]
    fn test_is_authentic_request_rejects_invalid_inputs() {
        let valid = vec![0u8; RADIUS_PACKET_HEADER_LENGTH];
        // request too short
        assert!(!Packet::is_authentic_request(&valid[..10], b"secret"));
        // empty secret
        assert!(!Packet::is_authentic_request(&valid, b""));
        // unknown code → false
        let mut unknown_code_pkt = vec![0u8; RADIUS_PACKET_HEADER_LENGTH];
        unknown_code_pkt[0] = 0xff;
        assert!(!Packet::is_authentic_request(&unknown_code_pkt, b"secret"));
    }

    #[test]
    fn test_debug_format() {
        let secret = b"xyzzy5461";
        // RFC 2865 §7.1 Access-Request test vector
        let request: Vec<u8> = vec![
            0x01, 0x00, 0x00, 0x38, 0x0f, 0x40, 0x3f, 0x94, 0x73, 0x97, 0x80, 0x57, 0xbd, 0x83,
            0xd5, 0xcb, 0x98, 0xf4, 0x22, 0x7a, 0x01, 0x06, 0x6e, 0x65, 0x6d, 0x6f, 0x02, 0x12,
            0x0d, 0xbe, 0x70, 0x8d, 0x93, 0xd4, 0x13, 0xce, 0x31, 0x96, 0xe4, 0x3f, 0x78, 0x2a,
            0x0a, 0xee, 0x04, 0x06, 0xc0, 0xa8, 0x01, 0x10, 0x05, 0x06, 0x00, 0x00, 0x00, 0x03,
        ];
        let packet = Packet::decode(&request, secret).unwrap();
        let debug_output = format!("{packet:#?}");
        println!("{debug_output}");
        let expected = r#"Packet {
    code: Access-Request (1),
    identifier: 0,
    authenticator: "0f403f9473978057bd83d5cb98f4227a",
    secret: "*redacted*",
    attributes: Attributes(
        [
            AVP {
                typ: User-Name (1),
                value: "nemo",
            },
            AVP {
                typ: User-Password (2),
                value: <encrypted, 16 bytes>,
            },
            AVP {
                typ: NAS-IP-Address (4),
                value: 192.168.1.16,
            },
            AVP {
                typ: NAS-Port (5),
                value: 3,
            },
        ],
    ),
}"#;
        assert_eq!(debug_output, expected);
    }

    // ── VSA primitive tests ───────────────────────────────────────────────

    #[test]
    fn test_avp_from_vsa_decode_vsa_roundtrip() {
        let payload = b"shell:priv-lvl=15";
        let avp = AVP::from_vsa(9, 1, payload);
        assert_eq!(avp.typ(), 26); // VENDOR_SPECIFIC_TYPE
        let decoded = avp.decode_vsa(9, 1).unwrap();
        assert_eq!(decoded.as_ref(), payload);
    }

    #[test]
    fn test_avp_decode_vsa_wrong_vendor_id() {
        let avp = AVP::from_vsa(9, 1, b"value");
        assert!(avp.decode_vsa(11, 1).is_none());
    }

    #[test]
    fn test_avp_decode_vsa_wrong_vendor_type() {
        let avp = AVP::from_vsa(9, 1, b"value");
        assert!(avp.decode_vsa(9, 2).is_none());
    }

    #[test]
    fn test_avp_decode_vsa_non_vsa_type() {
        // An AVP whose typ is not 26 should never match decode_vsa.
        let avp = AVP::from_bytes(1, b"\x00\x00\x00\x09\x01\x07value");
        assert!(avp.decode_vsa(9, 1).is_none());
    }

    #[test]
    fn test_packet_lookup_vsa_and_lookup_all_vsa() {
        let mut packet = Packet::new(Code::AccessRequest, b"secret");
        packet.add(AVP::from_vsa(9, 1, b"shell:priv-lvl=15"));
        packet.add(AVP::from_vsa(9, 1, b"audit:event=login"));
        packet.add(AVP::from_vsa(9, 2, b"GigabitEthernet0/0"));

        // lookup_vsa returns the first match.
        let first = packet.lookup_vsa(9, 1).unwrap();
        assert_eq!(first.as_ref(), b"shell:priv-lvl=15");

        // lookup_vsa returns None for an absent vendor_type.
        assert!(packet.lookup_vsa(9, 99).is_none());

        // lookup_all_vsa returns every match.
        let all = packet.lookup_all_vsa(9, 1);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].as_ref(), b"shell:priv-lvl=15");
        assert_eq!(all[1].as_ref(), b"audit:event=login");

        // Different vendor_type is returned independently.
        let nas_port = packet.lookup_all_vsa(9, 2);
        assert_eq!(nas_port.len(), 1);
        assert_eq!(nas_port[0].as_ref(), b"GigabitEthernet0/0");
    }

    #[test]
    fn test_packet_delete_vsa() {
        let mut packet = Packet::new(Code::AccessRequest, b"secret");
        packet.add(AVP::from_vsa(9, 1, b"shell:priv-lvl=15"));
        packet.add(AVP::from_vsa(9, 1, b"audit:event=login"));
        packet.add(AVP::from_vsa(9, 2, b"GigabitEthernet0/0"));

        packet.delete_vsa(9, 1);
        assert!(packet.lookup_vsa(9, 1).is_none());
        assert_eq!(packet.lookup_all_vsa(9, 1).len(), 0);

        // A different vendor_type must not have been removed.
        assert!(packet.lookup_vsa(9, 2).is_some());
    }

    #[test]
    fn test_packet_delete_vsa_different_vendor_id_is_preserved() {
        let mut packet = Packet::new(Code::AccessRequest, b"secret");
        packet.add(AVP::from_vsa(9, 1, b"cisco-value"));
        packet.add(AVP::from_vsa(311, 1, b"microsoft-value")); // vendor 311 = Microsoft

        packet.delete_vsa(9, 1);
        assert!(packet.lookup_vsa(9, 1).is_none());
        // Microsoft VSA with the same sub-type must be untouched.
        assert!(packet.lookup_vsa(311, 1).is_some());
    }

    // ── Cisco dict helper tests ───────────────────────────────────────────

    #[test]
    fn test_cisco_av_pair_string_roundtrip() {
        let mut packet = Packet::new(Code::AccessRequest, b"secret");
        cisco::add_cisco_av_pair(&mut packet, "shell:priv-lvl=15");
        let val = cisco::lookup_cisco_av_pair(&packet).unwrap().unwrap();
        assert_eq!(val, "shell:priv-lvl=15");
    }

    #[test]
    fn test_cisco_av_pair_lookup_all() {
        let mut packet = Packet::new(Code::AccessRequest, b"secret");
        cisco::add_cisco_av_pair(&mut packet, "shell:priv-lvl=15");
        cisco::add_cisco_av_pair(&mut packet, "audit:event=login");
        let all = cisco::lookup_all_cisco_av_pair(&packet).unwrap();
        assert_eq!(all, vec!["shell:priv-lvl=15", "audit:event=login"]);
    }

    #[test]
    fn test_cisco_av_pair_delete() {
        let mut packet = Packet::new(Code::AccessRequest, b"secret");
        cisco::add_cisco_av_pair(&mut packet, "shell:priv-lvl=15");
        assert!(cisco::lookup_cisco_av_pair(&packet).is_some());
        cisco::delete_cisco_av_pair(&mut packet);
        assert!(cisco::lookup_cisco_av_pair(&packet).is_none());
    }

    #[test]
    fn test_cisco_nas_port_roundtrip() {
        let mut packet = Packet::new(Code::AccessRequest, b"secret");
        cisco::add_cisco_nas_port(&mut packet, "GigabitEthernet0/1");
        let val = cisco::lookup_cisco_nas_port(&packet).unwrap().unwrap();
        assert_eq!(val, "GigabitEthernet0/1");
    }

    #[test]
    fn test_cisco_multilink_id_integer_roundtrip() {
        let mut packet = Packet::new(Code::AccessRequest, b"secret");
        cisco::add_cisco_multilink_id(&mut packet, 42);
        let val = cisco::lookup_cisco_multilink_id(&packet).unwrap().unwrap();
        assert_eq!(val, 42_u32);
    }

    #[test]
    fn test_cisco_disconnect_cause_value_roundtrip() {
        let mut packet = Packet::new(Code::AccountingRequest, b"secret");
        cisco::add_cisco_disconnect_cause(
            &mut packet,
            cisco::CISCO_DISCONNECT_CAUSE_SESSION_TIMEOUT,
        );
        let val = cisco::lookup_cisco_disconnect_cause(&packet)
            .unwrap()
            .unwrap();
        assert_eq!(val, cisco::CISCO_DISCONNECT_CAUSE_SESSION_TIMEOUT);
        assert_eq!(val, 100);
    }

    #[test]
    fn test_cisco_vsa_encode_decode_wire_roundtrip() {
        // Full encode → wire bytes → decode cycle for a packet with mixed VSAs.
        let secret = b"testing123";
        let mut req = Packet::new_with_identifier(Code::AccessRequest, secret, 1);
        rfc2865::add_user_name(&mut req, "alice");
        cisco::add_cisco_av_pair(&mut req, "shell:priv-lvl=15");
        cisco::add_cisco_multilink_id(&mut req, 7);

        let wire = req.encode().unwrap();
        let decoded = Packet::decode(&wire, secret).unwrap();

        assert_eq!(
            rfc2865::lookup_user_name(&decoded).unwrap().unwrap(),
            "alice"
        );
        assert_eq!(
            cisco::lookup_cisco_av_pair(&decoded).unwrap().unwrap(),
            "shell:priv-lvl=15"
        );
        assert_eq!(
            cisco::lookup_cisco_multilink_id(&decoded).unwrap().unwrap(),
            7
        );
    }
}
