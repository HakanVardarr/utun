use crate::net::ipv4::Ipv4Header;

pub type UdpHandler = Box<dyn FnMut(&Ipv4Header, &UdpHeader) -> Option<Vec<u8>>>;
pub struct UdpSocket {
    pub port: u16,
    pub handler: UdpHandler,
}

#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub data: Vec<u8>,
}

impl UdpHeader {
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }
        let source_port = u16::from_be_bytes([buf[0], buf[1]]);
        let destination_port = u16::from_be_bytes([buf[2], buf[3]]);
        let length = u16::from_be_bytes([buf[4], buf[5]]);
        let checksum = u16::from_be_bytes([buf[6], buf[7]]);
        let data = buf[8..].to_vec();

        Some(Self {
            source_port,
            destination_port,
            length,
            checksum,
            data,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let length = 8 + self.data.len() as u16;
        let mut buf = Vec::with_capacity(length as usize);

        buf.extend_from_slice(&self.source_port.to_be_bytes());
        buf.extend_from_slice(&self.destination_port.to_be_bytes());
        buf.extend_from_slice(&length.to_be_bytes());
        buf.extend_from_slice(&self.checksum.to_be_bytes());
        buf.extend_from_slice(&self.data);

        buf
    }

    pub fn compute_checksum(&mut self, src: &[u8; 4], dst: &[u8; 4]) {
        self.checksum = 0;
        let mut sum = 0u32;

        // --- PSEUDO HEADER ---
        // Source IP
        sum += u16::from_be_bytes([src[0], src[1]]) as u32;
        sum += u16::from_be_bytes([src[2], src[3]]) as u32;

        // Destination IP
        sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
        sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;

        // protocol (17) + UDP length
        sum += 17u32;
        sum += self.length as u32;

        // --- UDP HEADER + DATA ---
        let bytes = self.to_bytes();
        for chunk in bytes.chunks(2) {
            let val = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]]) as u32
            } else {
                (chunk[0] as u32) << 8
            };
            sum += val;
        }

        // --- Fold carries ---
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        self.checksum = !(sum as u16);

        // RFC 768: checksum 0 olamaz
        if self.checksum == 0 {
            self.checksum = 0xFFFF;
        }
    }

    pub fn build_udp_echo(&self, ipv4: &super::ipv4::Ipv4Header) -> Vec<u8> {
        let mut reply_udp = self.clone();
        std::mem::swap(&mut reply_udp.source_port, &mut reply_udp.destination_port);

        reply_udp.length = (8 + reply_udp.data.len()) as u16;

        reply_udp.compute_checksum(&ipv4.dst, &ipv4.src);

        let mut reply_ip = ipv4.clone();
        std::mem::swap(&mut reply_ip.src, &mut reply_ip.dst);
        reply_ip.ttl = 64;
        reply_ip.protocol = 17;
        reply_ip.total_length = (reply_ip.ihl as usize * 4 + reply_udp.to_bytes().len()) as u16;
        reply_ip.compute_checksum();

        let mut packet = Vec::new();
        packet.extend_from_slice(&(libc::AF_INET as u32).to_be_bytes());
        packet.extend_from_slice(&reply_ip.to_bytes());
        packet.extend_from_slice(&reply_udp.to_bytes());

        packet
    }
}
