use super::ipv4::Ipv4Header;
use crate::engine::Desicion;
use tracing::info;

#[derive(Debug, Clone)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence: u16,
    pub payload: Vec<u8>,
}

impl IcmpHeader {
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }

        Some(Self {
            icmp_type: buf[0],
            code: buf[1],
            checksum: u16::from_be_bytes([buf[2], buf[3]]),
            identifier: u16::from_be_bytes([buf[4], buf[5]]),
            sequence: u16::from_be_bytes([buf[6], buf[7]]),
            payload: buf[8..].to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + self.payload.len());
        buf.push(self.icmp_type);
        buf.push(self.code);
        buf.extend_from_slice(&self.checksum.to_be_bytes());
        buf.extend_from_slice(&self.identifier.to_be_bytes());
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn compute_checksum(&mut self) {
        self.checksum = 0;
        let bytes = self.to_bytes();
        let mut sum = 0u32;

        for word in bytes.chunks(2) {
            let val = if word.len() == 2 {
                u16::from_be_bytes([word[0], word[1]]) as u32
            } else {
                (word[0] as u32) << 8
            };
            sum = sum.wrapping_add(val);
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        self.checksum = !(sum as u16);
    }

    pub fn handle_request(&self, ipv4_header: &Ipv4Header) -> Desicion {
        match (self.icmp_type, self.code) {
            // Echo Request
            (8, 0) => {
                info!(
                    "Echo Request detected: id={} seq={}",
                    self.identifier, self.sequence
                );

                let mut reply_icmp_header = self.clone();
                reply_icmp_header.icmp_type = 0;
                reply_icmp_header.compute_checksum();

                let mut reply_ipv4_header = ipv4_header.clone();
                std::mem::swap(&mut reply_ipv4_header.src, &mut reply_ipv4_header.dst);
                reply_ipv4_header.total_length = (reply_ipv4_header.ihl as usize * 4
                    + reply_icmp_header.to_bytes().len())
                    as u16;
                reply_ipv4_header.compute_checksum();

                let mut reply_packet = Vec::new();
                reply_packet.extend_from_slice(&(libc::AF_INET as u32).to_be_bytes());
                reply_packet.extend_from_slice(&reply_ipv4_header.to_bytes());
                reply_packet.extend_from_slice(&reply_icmp_header.to_bytes());

                Desicion::Reply(reply_packet)
            }
            _ => Desicion::Drop,
        }
    }
}
