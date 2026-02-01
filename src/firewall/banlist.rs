use std::collections::HashSet;

#[derive(Default)]
pub struct Banlist {
    banned: HashSet<[u8; 4]>,
}

impl Banlist {
    pub fn is_banned(&self, ip: &[u8; 4]) -> bool {
        self.banned.contains(ip)
    }

    pub fn ban(&mut self, ip: [u8; 4]) {
        self.banned.insert(ip);
    }

    pub fn unban(&mut self, ip: &[u8; 4]) {
        self.banned.remove(ip);
    }
}
