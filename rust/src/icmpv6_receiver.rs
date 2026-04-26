/// ICMPv6 receiver over IPv4 (non-standard, proto 58).
///
/// Filters ICMPv6 Echo Request (type 128) packets.

use crate::raw_socket::{close_fd, create_raw_recv_socket};
use std::sync::atomic::{AtomicBool, Ordering};

const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_PROTO: i32 = 58;

pub struct Icmpv6Receiver {
    fd: i32,
    peer_ip: Option<[u8; 4]>,
    closed: AtomicBool,
    recv_buf: Vec<u8>,
}

unsafe impl Send for Icmpv6Receiver {}
unsafe impl Sync for Icmpv6Receiver {}

pub struct Icmpv6RecvResult {
    pub payload_len: usize,
    pub src_ip: [u8; 4],
}

impl Icmpv6Receiver {
    pub fn new(peer_ip: Option<[u8; 4]>, buf_size: i32) -> Result<Box<Self>, String> {
        let fd = create_raw_recv_socket(ICMPV6_PROTO, buf_size)
            .map_err(|e| format!("create ICMPv6 recv socket: {e}"))?;

        Ok(Box::new(Icmpv6Receiver {
            fd,
            peer_ip,
            closed: AtomicBool::new(false),
            recv_buf: vec![0u8; 65536],
        }))
    }

    pub fn recv(&mut self, out_buf: &mut [u8]) -> Result<Icmpv6RecvResult, String> {
        loop {
            if self.closed.load(Ordering::Relaxed) {
                return Err("closed".into());
            }

            let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut addr_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

            let n = unsafe {
                libc::recvfrom(
                    self.fd,
                    self.recv_buf.as_mut_ptr() as *mut libc::c_void,
                    self.recv_buf.len(),
                    0,
                    &mut addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
                    &mut addr_len,
                )
            };

            if n < 0 {
                if self.closed.load(Ordering::Relaxed) {
                    return Err("closed".into());
                }
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EBADF) {
                    return Err("closed".into());
                }
                continue;
            }

            let n = n as usize;
            let src_ip = addr.sin_addr.s_addr.to_ne_bytes();

            if let Some(ref expected) = self.peer_ip {
                if src_ip != *expected {
                    continue;
                }
            }

            if let Some(result) = self.parse_icmpv6(n, &src_ip, out_buf) {
                return Ok(result);
            }
        }
    }

    #[inline]
    fn parse_icmpv6(&self, n: usize, src_ip: &[u8; 4], out_buf: &mut [u8]) -> Option<Icmpv6RecvResult> {
        let buf = &self.recv_buf[..n];
        if n < 20 { return None; }

        let ihl = ((buf[0] & 0x0F) as usize) * 4;
        if n < ihl + 8 { return None; }

        // Check protocol
        if buf[9] != ICMPV6_PROTO as u8 { return None; }

        let icmp = &buf[ihl..];

        // Filter: ICMPv6 Echo Request (type 128)
        if icmp[0] != ICMPV6_ECHO_REQUEST { return None; }

        let payload_start = ihl + 8;
        if payload_start >= n { return None; }

        let payload_len = n - payload_start;
        if payload_len == 0 { return None; }
        if payload_len > out_buf.len() { return None; }

        out_buf[..payload_len].copy_from_slice(&buf[payload_start..n]);

        Some(Icmpv6RecvResult {
            payload_len,
            src_ip: *src_ip,
        })
    }

    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            close_fd(self.fd);
        }
    }
}

impl Drop for Icmpv6Receiver {
    fn drop(&mut self) {
        self.close();
    }
}
