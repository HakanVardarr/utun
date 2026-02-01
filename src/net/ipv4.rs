#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

impl Ipv4Header {
    pub fn from_bytes(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 {
            return None;
        }

        let version = packet[0] >> 4;
        let ihl = packet[0] & 0x0F;
        let tos = packet[1];
        let total_length = u16::from_be_bytes([packet[2], packet[3]]);
        let identification = u16::from_be_bytes([packet[4], packet[5]]);

        let flags = packet[6] >> 5;
        let fragment_offset = u16::from_be_bytes([packet[6] & 0x1F, packet[7]]);

        let ttl = packet[8];
        let protocol = packet[9];
        let checksum = u16::from_be_bytes([packet[10], packet[11]]);

        let src = [packet[12], packet[13], packet[14], packet[15]];
        let dst = [packet[16], packet[17], packet[18], packet[19]];

        Some(Self {
            version,
            ihl,
            tos,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            src,
            dst,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity((self.ihl * 4) as usize);
        let version_ihl = (self.version << 4) | (self.ihl & 0x0F);
        buf.push(version_ihl);
        buf.push(self.tos);
        buf.extend_from_slice(&self.total_length.to_be_bytes());
        buf.extend_from_slice(&self.identification.to_be_bytes());
        let flags_fragment = ((self.flags as u16) << 13) | (self.fragment_offset & 0x1FFF);
        buf.extend_from_slice(&flags_fragment.to_be_bytes());
        buf.push(self.ttl);
        buf.push(self.protocol);
        buf.extend_from_slice(&self.checksum.to_be_bytes());
        buf.extend_from_slice(&self.src);
        buf.extend_from_slice(&self.dst);
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
}
