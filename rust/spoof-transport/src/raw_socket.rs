/// Shared raw socket helpers for Linux.

use std::io;

/// Create a raw sending socket (IPPROTO_RAW + IP_HDRINCL + large SO_SNDBUF).
pub fn create_raw_send_socket() -> io::Result<i32> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    // Set SO_SNDBUF to 4 MB for high-throughput sending
    let buf_size: libc::c_int = 4 * 1024 * 1024;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &buf_size as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    Ok(fd)
}

/// Create a raw receiving socket for any protocol with SO_RCVTIMEO.
pub fn create_raw_recv_socket(proto: i32, buf_size: i32) -> io::Result<i32> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, proto) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    if buf_size > 0 {
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &buf_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    // 1-second read timeout for graceful shutdown
    let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    Ok(fd)
}

/// Create a raw receiving socket (IPPROTO_TCP) — backward compat wrapper.
pub fn create_raw_recv_tcp_socket(buf_size: i32) -> io::Result<i32> {
    create_raw_recv_socket(libc::IPPROTO_TCP, buf_size)
}

/// Send raw bytes to an IPv4 destination. Retries on EINTR.
#[inline]
pub fn sendto_raw(fd: i32, pkt: &[u8], dst_ip: &[u8; 4]) -> io::Result<()> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_addr.s_addr = u32::from_ne_bytes(*dst_ip);

    loop {
        let rc = unsafe {
            libc::sendto(
                fd,
                pkt.as_ptr() as *const libc::c_void,
                pkt.len(),
                0,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        return Ok(());
    }
}

/// Close a file descriptor.
#[inline]
pub fn close_fd(fd: i32) {
    unsafe { libc::close(fd); }
}

/// Fast xorshift32 PRNG for IP identification field.
#[inline]
pub fn random_ip_id() -> u16 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u32> = Cell::new(0);
    }
    STATE.with(|s| {
        let mut v = s.get();
        if v == 0 {
            let t = unsafe { libc::time(std::ptr::null_mut()) };
            v = t as u32 ^ 0xDEAD_BEEF;
        }
        v ^= v << 13;
        v ^= v >> 17;
        v ^= v << 5;
        s.set(v);
        v as u16
    })
}
