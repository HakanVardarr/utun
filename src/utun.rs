use libc::*;
use std::ffi::CStr;
use std::ffi::CString;
use std::mem;
use std::process::Command;
use std::ptr;
use thiserror::Error;

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};

#[derive(Error, Debug)]
pub enum UtunError {
    #[error("Failed to create socket.")]
    CreateSocket,
    #[error("Ioctl failed.")]
    IoctlFailed,
    #[error("Connect failed.")]
    ConnectFailed,
    #[error("ifconfig failed.")]
    IfconfigFailed,
}

pub struct Utun {
    pub fd: RawFd,
    name: String,
    file: File,
}

impl Utun {
    pub fn new() -> Result<Self, UtunError> {
        unsafe {
            let fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
            if fd < 0 {
                return Err(UtunError::CreateSocket);
            }

            let mut info: ctl_info = mem::zeroed();
            let name = CString::new("com.apple.net.utun_control").unwrap();
            ptr::copy_nonoverlapping(
                name.as_ptr(),
                info.ctl_name.as_mut_ptr(),
                name.as_bytes().len(),
            );

            if ioctl(fd, CTLIOCGINFO, &info) < 0 {
                return Err(UtunError::IoctlFailed);
            }

            let addr = sockaddr_ctl {
                sc_len: mem::size_of::<sockaddr_ctl>() as u8,
                sc_family: AF_SYSTEM as u8,
                ss_sysaddr: AF_SYS_CONTROL as u16,
                sc_id: info.ctl_id,
                sc_unit: 0,
                sc_reserved: [0; 5],
            };

            if connect(
                fd,
                &addr as *const _ as *const sockaddr,
                mem::size_of::<sockaddr_ctl>() as u32,
            ) < 0
            {
                return Err(UtunError::ConnectFailed);
            }

            let mut ifname = [0u8; 16];
            let mut ifname_len = ifname.len() as u32;

            getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                ifname.as_mut_ptr() as *mut _,
                &mut ifname_len,
            );

            let name = CStr::from_ptr(ifname.as_ptr() as *const _)
                .to_str()
                .unwrap()
                .to_string();

            let file = File::from_raw_fd(fd);

            Ok(Self { fd, name, file })
        }
    }
    pub fn configure(&self, local_ip: &str, peer_ip: &str) -> Result<(), UtunError> {
        let status = Command::new("ifconfig")
            .args([&self.name, "inet", local_ip, peer_ip, "up"])
            .status()
            .expect("Failed to run ifconfig");
        if !status.success() {
            return Err(UtunError::IfconfigFailed);
        }
        Ok(())
    }

    pub fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }

    pub fn write_packet(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }
}
