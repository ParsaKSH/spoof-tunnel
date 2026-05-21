/// ICMP Echo receiver — raw socket IPPROTO_ICMP.
///
/// Filters ICMP Echo Request (type 8) packets by peer IP,
/// extracts payload after 8-byte ICMP header.

use crate::raw_socket::{close_fd, create_raw_recv_socket};
use std::sync::atomic::{AtomicBool, Ordering};

const ICMP_ECHO_REQUEST: u8 = 8;

pub struct IcmpReceiver {
    fd: i32,
    peer_ip: Option<[u8; 4]>,
    closed: AtomicBool,
    recv_buf: Vec<u8>,
}

unsafe impl Send for IcmpReceiver {}
unsafe impl Sync for IcmpReceiver {}

/// Result of a successful receive.
pub struct IcmpRecvResult {
    pub payload_len: usize,
    pub src_ip: [u8; 4],
}

impl IcmpReceiver {
    pub fn new(peer_ip: Option<[u8; 4]>, buf_size: i32) -> Result<Box<Self>, String> {
        let fd = create_raw_recv_socket(libc::IPPROTO_ICMP, buf_size)
            .map_err(|e| format!("create ICMP recv socket: {e}"))?;

        Ok(Box::new(IcmpReceiver {
            fd,
            peer_ip,
            closed: AtomicBool::new(false),
            recv_buf: vec![0u8; 65536],
        }))
    }

    /// Blocking receive. Extracts payload from ICMP Echo Request.
    pub fn recv(&mut self, out_buf: &mut [u8]) -> Result<IcmpRecvResult, String> {
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

            if let Some(result) = self.parse_icmp(n, &src_ip, out_buf) {
                return Ok(result);
            }
        }
    }

    #[inline]
    fn parse_icmp(&self, n: usize, src_ip: &[u8; 4], out_buf: &mut [u8]) -> Option<IcmpRecvResult> {
        let buf = &self.recv_buf[..n];
        if n < 20 { return None; }

        let ihl = ((buf[0] & 0x0F) as usize) * 4;
        if n < ihl + 8 { return None; } // Need at least ICMP header

        // Check protocol is ICMP
        if buf[9] != libc::IPPROTO_ICMP as u8 { return None; }

        let icmp = &buf[ihl..];

        // Filter: ICMP Echo Request (type 8)
        if icmp[0] != ICMP_ECHO_REQUEST { return None; }

        let payload_start = ihl + 8; // After ICMP header
        if payload_start >= n { return None; }

        let payload_len = n - payload_start;
        if payload_len == 0 { return None; }
        if payload_len > out_buf.len() { return None; }

        out_buf[..payload_len].copy_from_slice(&buf[payload_start..n]);

        Some(IcmpRecvResult {
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

impl Drop for IcmpReceiver {
    fn drop(&mut self) {
        self.close();
    }
}
