use crate::{
    firewall::Banlist,
    net::{
        icmp::IcmpHeader,
        ipv4::Ipv4Header,
        udp::{UdpHeader, UdpSocket},
    },
};
use std::collections::HashMap;

pub enum Desicion {
    Reply(Vec<u8>),
    Drop,
}

#[derive(Default)]
pub struct Dispatcher {
    banlist: Banlist,
    udp_sockets: HashMap<u16, UdpSocket>,
}

impl Dispatcher {
    pub fn udp_bind<F>(&mut self, port: u16, handler: F)
    where
        F: FnMut(&Ipv4Header, &UdpHeader) -> Option<Vec<u8>> + 'static,
    {
        self.udp_sockets.insert(
            port,
            UdpSocket {
                port,
                handler: Box::new(handler),
            },
        );
    }

    pub fn handle_packet(&mut self, buf: &[u8]) -> Option<Vec<u8>> {
        if !(buf.len() >= 4
            && u32::from_be_bytes(buf[0..4].try_into().unwrap()) == libc::AF_INET as u32)
        {
            return None;
        }

        if let Some(ipv4_header) = Ipv4Header::from_bytes(&buf[4..buf.len()]) {
            let header_len = (ipv4_header.ihl * 4) as usize;
            let payload = &buf[4 + header_len..];

            if self.banlist.is_banned(&ipv4_header.dst) {
                return None;
            }

            match ipv4_header.protocol {
                1 => {
                    // ICMP
                    if let Some(icmp_header) = IcmpHeader::from_bytes(payload) {
                        match icmp_header.handle_request(&ipv4_header) {
                            Desicion::Reply(pkt) => Some(pkt),
                            Desicion::Drop => None,
                        }
                    } else {
                        None
                    }
                }
                17 => {
                    // UDP
                    if let Some(udp_header) = UdpHeader::from_bytes(payload)
                        && let Some(sock) = self.udp_sockets.get_mut(&udp_header.destination_port)
                    {
                        return (sock.handler)(&ipv4_header, &udp_header);
                    }
                    None
                }
                _ => None,
            }
        } else {
            None
        }
    }
}
