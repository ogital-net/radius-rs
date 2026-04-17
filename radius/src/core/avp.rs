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
    InvalidRequestAuthenticatorLength(),

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

    /// This error is raised when computation of hash fails using openssl hash
    #[error("computation of hash failed: {0}")]
    HashComputationFailed(String),
}

pub type AVPType = u8;

pub const TYPE_INVALID: AVPType = 255;

/// This struct represents a attribute-value pair.
#[derive(Debug, Clone, PartialEq)]
pub struct AVP {
    pub(crate) typ: AVPType,
    pub(crate) value: Bytes,
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
    #[must_use]
    pub fn from_tagged_u32(typ: AVPType, tag: Option<&Tag>, value: u32) -> Self {
        let tag_val = tag.map_or(UNUSED_TAG_VALUE, |t| t.value);
        let mut buf = BytesMut::with_capacity(5);
        buf.put_u8(tag_val);
        buf.put_slice(&u32::to_be_bytes(value));
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
            return Err(AVPError::InvalidRequestAuthenticatorLength());
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
            return Err(AVPError::InvalidRequestAuthenticatorLength());
        }

        let mut salt = [0u8; 2];
        crypto::fill_random(&mut salt);
        salt[0] |= 0x80;

        // NOTE: prepend one byte as a tag and two bytes as a salt
        let num_chunks = if plain_text.is_empty() {
            1
        } else {
            plain_text.len().div_ceil(16)
        };
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

        if plain_text.is_empty() {
            let enc_block = crypto::md5(&md5_input);
            enc.put_slice(&enc_block);
            return Ok(AVP {
                typ,
                value: enc.freeze(),
            });
        }

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

    /// (This method is for dictionary developers) encode an AVP into a u32 value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is not exactly 4 bytes.
    pub fn encode_u32(&self) -> Result<u32, AVPError> {
        const U32_SIZE: usize = std::mem::size_of::<u32>();
        if self.value.len() != U32_SIZE {
            return Err(AVPError::InvalidAttributeLengthError(
                format!("{U32_SIZE} bytes"),
                self.value.len(),
            ));
        }

        let (int_bytes, _) = self.value.split_at(U32_SIZE);
        // SAFETY: length was validated above; try_into cannot fail here.
        let array: [u8; U32_SIZE] = int_bytes.try_into().unwrap();
        Ok(u32::from_be_bytes(array))
    }

    /// (This method is for dictionary developers) encode an AVP into a u16 value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is not exactly 2 bytes.
    pub fn encode_u16(&self) -> Result<u16, AVPError> {
        const U16_SIZE: usize = std::mem::size_of::<u16>();
        if self.value.len() != U16_SIZE {
            return Err(AVPError::InvalidAttributeLengthError(
                format!("{U16_SIZE} bytes"),
                self.value.len(),
            ));
        }

        let (int_bytes, _) = self.value.split_at(U16_SIZE);
        // SAFETY: length was validated above; try_into cannot fail here.
        let array: [u8; U16_SIZE] = int_bytes.try_into().unwrap();
        Ok(u16::from_be_bytes(array))
    }

    /// (This method is for dictionary developers) encode an AVP into a tag and u32 value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError`] if the tag byte is missing, the tag value is invalid, or the
    /// payload is not exactly 4 bytes following the tag.
    pub fn encode_tagged_u32(&self) -> Result<(u32, Tag), AVPError> {
        const U32_SIZE: usize = std::mem::size_of::<u32>();
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

        if self.value[1..].len() != U32_SIZE {
            return Err(AVPError::InvalidAttributeLengthError(
                format!("{} bytes", U32_SIZE + 1),
                self.value.len(),
            ));
        }
        let (int_bytes, _) = self.value[1..].split_at(U32_SIZE);
        // SAFETY: length was validated above; try_into cannot fail here.
        let array: [u8; U32_SIZE] = int_bytes.try_into().unwrap();
        Ok((u32::from_be_bytes(array), tag))
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
    pub fn encode_bytes(&self) -> Vec<u8> {
        self.value.to_vec()
    }

    /// (This method is for dictionary developers) encode an AVP into Ipv4 value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is not exactly 4 bytes.
    pub fn encode_ipv4(&self) -> Result<Ipv4Addr, AVPError> {
        const IPV4_SIZE: usize = std::mem::size_of::<Ipv4Addr>();
        if self.value.len() != IPV4_SIZE {
            return Err(AVPError::InvalidAttributeLengthError(
                format!("{IPV4_SIZE} bytes"),
                self.value.len(),
            ));
        }

        let (int_bytes, _) = self.value.split_at(IPV4_SIZE);
        // SAFETY: length was validated above; try_into cannot fail here.
        let array: [u8; IPV4_SIZE] = int_bytes.try_into().unwrap();
        Ok(Ipv4Addr::from(array))
    }

    /// (This method is for dictionary developers) encode an AVP into Ipv4-prefix value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is not exactly 6 bytes.
    pub fn encode_ipv4_prefix(&self) -> Result<Vec<u8>, AVPError> {
        if self.value.len() == 6 {
            Ok(self.value[2..].to_vec())
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
        if self.value.len() != IPV6_SIZE {
            return Err(AVPError::InvalidAttributeLengthError(
                format!("{IPV6_SIZE} bytes"),
                self.value.len(),
            ));
        }

        let (int_bytes, _) = self.value.split_at(IPV6_SIZE);
        // SAFETY: length was validated above; try_into cannot fail here.
        let array: [u8; IPV6_SIZE] = int_bytes.try_into().unwrap();
        Ok(Ipv6Addr::from(array))
    }

    /// (This method is for dictionary developers) encode an AVP into Ipv6-prefix value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is shorter than 2 bytes.
    pub fn encode_ipv6_prefix(&self) -> Result<Vec<u8>, AVPError> {
        if self.value.len() >= 2 {
            Ok(self.value[2..].to_vec())
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
            return Err(AVPError::InvalidRequestAuthenticatorLength());
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

        // remove trailing zero bytes
        let end = memchr::memchr(0, &dec).unwrap_or(dec.len());
        Ok(dec[..end].to_vec())
    }

    /// (This method is for dictionary developers) encode an AVP into date value.
    ///
    /// # Errors
    ///
    /// Returns [`AVPError::InvalidAttributeLengthError`] if the value is not exactly 4 bytes.
    pub fn encode_date(&self) -> Result<SystemTime, AVPError> {
        const U32_SIZE: usize = std::mem::size_of::<u32>();
        if self.value.len() != U32_SIZE {
            return Err(AVPError::InvalidAttributeLengthError(
                format!("{U32_SIZE}"),
                self.value.len(),
            ));
        }

        let (int_bytes, _) = self.value.split_at(U32_SIZE);
        // SAFETY: length was validated above; try_into cannot fail here.
        let array: [u8; U32_SIZE] = int_bytes.try_into().unwrap();
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
            return Err(AVPError::InvalidRequestAuthenticatorLength());
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

        // remove trailing zero bytes
        let end = memchr::memchr(0, &dec).unwrap_or(dec.len());
        Ok((dec[..end].to_vec(), tag))
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
        let given_u32 = 16909060;
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
        let given_u32 = 16909060;
        let avp = AVP::from_tagged_u32(1, None, given_u32);
        assert_eq!(avp.encode_tagged_u32()?, (given_u32, Tag::new_unused()));

        let tag = Tag::new(2);
        let avp = AVP::from_tagged_u32(1, Some(&tag), given_u32);
        assert_eq!(avp.encode_tagged_u32()?, (given_u32, tag));
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
        assert_eq!(avp.encode_bytes(), given_bytes);
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
        let secret = b"12345".to_vec();
        let request_authenticator = b"0123456789abcdef".to_vec();

        struct TestCase<'a> {
            plain_text: &'a str,
            expected_encoded_len: usize,
        }

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
                String::from_utf8(decoded_password).unwrap(),
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
    fn it_should_convert_tunnel_password() -> Result<(), AVPError> {
        let tag = Tag { value: 0x1e };
        let secret = b"12345".to_vec();
        let request_authenticator = b"0123456789abcdef".to_vec();

        struct TestCase<'a> {
            plain_text: &'a str,
            expected_encoded_len: usize,
        }

        let test_cases = &[
            TestCase {
                plain_text: "",
                expected_encoded_len: 16 + 3,
            },
            TestCase {
                plain_text: "abc",
                expected_encoded_len: 16 + 3,
            },
            TestCase {
                plain_text: "0123456789abcde",
                expected_encoded_len: 16 + 3,
            },
            TestCase {
                plain_text: "0123456789abcdef",
                expected_encoded_len: 16 + 3,
            },
            TestCase {
                plain_text: "0123456789abcdef0",
                expected_encoded_len: 32 + 3,
            },
            TestCase {
                plain_text: "0123456789abcdef0123456789abcdef0123456789abcdef",
                expected_encoded_len: 48 + 3,
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
                String::from_utf8(decoded_password).unwrap(),
                test_case.plain_text
            );
        }

        Ok(())
    }

    #[test]
    fn should_convert_ipv4_prefix() -> Result<(), AVPError> {
        let prefix = vec![0x01, 0x02, 0x03, 0x04];
        let avp = AVP::from_ipv4_prefix(1, &prefix)?;
        assert_eq!(avp.encode_ipv4_prefix()?, prefix);

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
        assert_eq!(avp.encode_ipv6_prefix()?, prefix);

        let prefix = vec![0x00, 0x01, 0x02, 0x03];
        let avp = AVP::from_ipv6_prefix(1, &prefix)?;
        assert_eq!(avp.encode_ipv6_prefix()?, prefix);

        let prefix = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let avp = AVP::from_ipv6_prefix(1, &prefix)?;
        assert_eq!(avp.encode_ipv6_prefix()?, prefix);

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
        // Valid tag 0x01 but only 3 bytes of payload instead of 4
        let avp = AVP {
            typ: 1,
            value: bytes::Bytes::from_static(b"\x01\x00\x00\x01"),
        };
        assert_eq!(
            avp.encode_tagged_u32().unwrap_err(),
            AVPError::InvalidAttributeLengthError("5 bytes".to_owned(), 4)
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
            AVPError::InvalidRequestAuthenticatorLength()
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
            AVPError::InvalidRequestAuthenticatorLength()
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
            AVPError::InvalidRequestAuthenticatorLength()
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
            AVPError::InvalidRequestAuthenticatorLength()
        );
    }
}
