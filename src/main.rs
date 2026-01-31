use libc::*;
use std::ffi::CStr;
use std::ffi::CString;
use std::mem;
use std::process::Command;
use std::ptr;

fn setup_utun(ifname: &str) {
    let mut status = Command::new("ifconfig")
        .args([ifname, "inet", "10.0.0.1", "10.0.0.2", "up"])
        .status()
        .expect("Failed to run ifconfig");

    if !status.success() {
        panic!("ifconfig failed");
    }

    status = Command::new("route")
        .args(["add", "8.8.8.8", "-interface", ifname])
        .status()
        .expect("Failed to run route");

    if !status.success() {
        panic!("route failed");
    }
}

fn main() {
    let fd = unsafe { socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) };
    if fd < 0 {
        unsafe {
            panic!("Socket failed {}", *libc::__error());
        }
    }

    let mut info: ctl_info = unsafe { mem::zeroed() };
    let name = CString::new("com.apple.net.utun_control").unwrap();
    unsafe {
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            info.ctl_name.as_mut_ptr(),
            name.as_bytes().len(),
        );
    }
    if unsafe { ioctl(fd, CTLIOCGINFO, &mut info) } < 0 {
        panic!("ioctl failed");
    }
    let addr = sockaddr_ctl {
        sc_len: mem::size_of::<sockaddr_ctl>() as u8,
        sc_family: AF_SYSTEM as u8,
        ss_sysaddr: AF_SYS_CONTROL as u16,
        sc_id: info.ctl_id,
        sc_unit: 0,
        sc_reserved: [0; 5],
    };
    if unsafe {
        connect(
            fd,
            &addr as *const _ as *const sockaddr,
            mem::size_of::<sockaddr_ctl>() as u32,
        ) < 0
    } {
        panic!("conect failed");
    }

    let mut ifname = [0u8; 16];
    let mut ifname_len = ifname.len() as u32;

    unsafe {
        getsockopt(
            fd,
            SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            ifname.as_mut_ptr() as *mut _,
            &mut ifname_len,
        );
    }

    let name = unsafe { CStr::from_ptr(ifname.as_ptr() as *const _) };
    println!("Utun interface name {name:?}");

    setup_utun(name.to_str().unwrap());

    let mut buf = [0u8; 2048];
    unsafe {
        loop {
            let n = read(fd, buf.as_mut_ptr() as *mut _, buf.len());
            if n < 0 {
                panic!("Read failed {}", *libc::__error());
            }

            let af = u32::from_be_bytes(buf[0..4].try_into().unwrap());
            if af != AF_INET as u32 {
                return;
            }
            let ip_packet = &buf[4..n as usize];

            println!("Recieved {} bytes", n);
            std::thread::yield_now();
        }
    }
}
