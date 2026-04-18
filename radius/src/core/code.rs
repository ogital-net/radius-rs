use std::convert::TryFrom;
use std::fmt;

/// RADIUS packet-type code as defined in [RFC 2865 §3](https://tools.ietf.org/html/rfc2865#section-3).
///
/// # Example
///
/// ```
/// use radius::core::code::Code;
///
/// let code = Code::from(1u8);
/// assert_eq!(code, Code::AccessRequest);
/// assert_eq!(code.as_str(), "Access-Request");
/// assert_eq!(format!("{code}"), "Access-Request");
/// assert_eq!(u8::from(code), 1u8);
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Code {
    AccessRequest = 1,
    AccessAccept = 2,
    AccessReject = 3,
    AccountingRequest = 4,
    AccountingResponse = 5,
    AccessChallenge = 11,
    StatusServer = 12,
    StatusClient = 13,
    DisconnectRequest = 40,
    DisconnectAck = 41,
    DisconnectNak = 42,
    CoaRequest = 43,
    CoaAck = 44,
    CoaNak = 45,
    Reserved = 255,
    Invalid = 0,
}

impl Code {
    /// Returns the RADIUS protocol name for this code as a static string slice.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Code::AccessRequest => "Access-Request",
            Code::AccessAccept => "Access-Accept",
            Code::AccessReject => "Access-Reject",
            Code::AccountingRequest => "Accounting-Request",
            Code::AccountingResponse => "Accounting-Response",
            Code::AccessChallenge => "Access-Challenge",
            Code::StatusServer => "Status-Server",
            Code::StatusClient => "Status-Client",
            Code::DisconnectRequest => "Disconnect-Request",
            Code::DisconnectAck => "Disconnect-ACK",
            Code::DisconnectNak => "Disconnect-NAK",
            Code::CoaRequest => "CoA-Request",
            Code::CoaAck => "CoA-ACK",
            Code::CoaNak => "CoA-NAK",
            Code::Reserved => "Reserved",
            Code::Invalid => "Invalid",
        }
    }

    #[must_use]
    pub fn from(value: u8) -> Self {
        match Code::try_from(value) {
            Ok(code) => code,
            Err(_) => Code::Invalid,
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<Code> for u8 {
    fn from(code: Code) -> u8 {
        code as u8
    }
}

impl TryFrom<u8> for Code {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Code::AccessRequest),
            2 => Ok(Code::AccessAccept),
            3 => Ok(Code::AccessReject),
            4 => Ok(Code::AccountingRequest),
            5 => Ok(Code::AccountingResponse),
            11 => Ok(Code::AccessChallenge),
            12 => Ok(Code::StatusServer),
            13 => Ok(Code::StatusClient),
            40 => Ok(Code::DisconnectRequest),
            41 => Ok(Code::DisconnectAck),
            42 => Ok(Code::DisconnectNak),
            43 => Ok(Code::CoaRequest),
            44 => Ok(Code::CoaAck),
            45 => Ok(Code::CoaNak),
            255 => Ok(Code::Reserved),
            0 => Ok(Code::Invalid),
            v => Err(v),
        }
    }
}
