use crate::net::{ipv4::Ipv4Header, udp::UdpHeader};
use std::collections::HashMap;

#[derive(Default)]
pub struct UdpKvService {
    store: HashMap<String, String>,
}

impl UdpKvService {
    pub fn handle(&mut self, ip: &Ipv4Header, udp: &UdpHeader) -> Option<Vec<u8>> {
        let msg = String::from_utf8_lossy(&udp.data);
        let parts: Vec<_> = msg.split_whitespace().collect();

        match parts.as_slice() {
            ["SET", key, value] => {
                self.store.insert(key.to_string(), value.to_string());

                let mut resp = udp.clone();
                resp.data = b"OK".to_vec();
                Some(resp.build_udp_echo(ip))
            }

            ["GET", key] => {
                let reply = match self.store.get(*key) {
                    Some(v) => format!("VALUE {}", v),
                    None => "NOTFOUND".to_string(),
                };

                let mut resp = udp.clone();
                resp.data = reply.into_bytes();
                Some(resp.build_udp_echo(ip))
            }

            ["DEL", key] => {
                self.store.remove(*key);

                let mut resp = udp.clone();
                resp.data = b"OK".to_vec();
                Some(resp.build_udp_echo(ip))
            }

            _ => None,
        }
    }
}
