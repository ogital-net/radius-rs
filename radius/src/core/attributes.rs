use bytes::Bytes;

use crate::core::avp::{AVPType, AVP, VENDOR_SPECIFIC_TYPE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attributes(pub(crate) Vec<AVP>);

impl Attributes {
    pub(crate) fn decode(bs: &Bytes) -> Result<Attributes, String> {
        let mut i = 0;
        let mut attrs = Vec::new();
        let len = bs.len();

        while len > i {
            if bs[i..].len() < 2 {
                return Err("short buffer".to_owned());
            }

            let length = bs[i + 1] as usize;
            if length > bs[i..].len() || !(2..=255).contains(&length) {
                return Err("invalid attribute length".to_owned());
            }

            attrs.push(AVP {
                raw: bs.slice(i..i + length),
            });

            i += length;
        }

        Ok(Attributes(attrs))
    }

    pub(crate) fn add(&mut self, avp: AVP) {
        self.0.push(avp);
    }

    pub(crate) fn extend(&mut self, avps: Vec<AVP>) {
        self.0.extend(avps);
    }

    pub(crate) fn del(&mut self, typ: AVPType) {
        self.0.retain(|avp| avp.typ() != typ);
    }

    pub(crate) fn del_vsa(&mut self, vendor_id: u32, vendor_type: u8) {
        self.0.retain(|avp| {
            avp.typ() != VENDOR_SPECIFIC_TYPE || avp.decode_vsa(vendor_id, vendor_type).is_none()
        });
    }

    pub(crate) fn lookup(&self, typ: AVPType) -> Option<&AVP> {
        self.0.iter().find(|avp| avp.typ() == typ)
    }

    pub(crate) fn lookup_all(&self, typ: AVPType) -> Vec<&AVP> {
        self.0.iter().filter(|&avp| avp.typ() == typ).collect()
    }

    pub(crate) fn total_size(&self) -> usize {
        self.0.iter().map(|avp| avp.raw.len()).sum()
    }

    pub(crate) fn encode(&self, dst: &mut Vec<u8>) {
        for avp in &self.0 {
            dst.extend_from_slice(&avp.raw);
        }
    }
}
