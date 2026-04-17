use std::convert::TryFrom;

#[derive(Debug, Copy, Clone, PartialEq)]
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
    DisconnectACK = 41,
    DisconnectNAK = 42,
    CoARequest = 43,
    CoAACK = 44,
    CoANAK = 45,
    Reserved = 255,
    Invalid = 0,
}

impl Code {
    pub fn string(&self) -> &'static str {
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
            Code::DisconnectACK => "Disconnect-ACK",
            Code::DisconnectNAK => "Disconnect-NAK",
            Code::CoARequest => "CoA-Request",
            Code::CoAACK => "CoA-ACK",
            Code::CoANAK => "CoA-NAK",
            Code::Reserved => "Reserved",
            Code::Invalid => "Invalid",
        }
    }

    pub fn from(value: u8) -> Self {
        match Code::try_from(value) {
            Ok(code) => code,
            Err(_) => Code::Invalid,
        }
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
            41 => Ok(Code::DisconnectACK),
            42 => Ok(Code::DisconnectNAK),
            43 => Ok(Code::CoARequest),
            44 => Ok(Code::CoAACK),
            45 => Ok(Code::CoANAK),
            255 => Ok(Code::Reserved),
            0 => Ok(Code::Invalid),
            v => Err(v),
        }
    }
}
