/// Raw TCP SYN receiver with zero-copy header parsing.
///
/// Blocking recvfrom() on IPPROTO_TCP raw socket, parses IP+TCP headers
/// in-place, filters by port/flags/peer IP, returns payload.

use crate::raw_socket::{close_fd, create_raw_recv_tcp_socket};
use std::sync::atomic::{AtomicBool, Ordering};

/// Result of a successful receive.
#[repr(C)]
pub struct RecvResult {
    pub payload_len: usize,
    pub src_ip: [u8; 4],
    pub src_port: u16,
}

pub struct TcpReceiver {
    fd: i32,
    listen_port: u16,
    peer_spoof_ip: Option<[u8; 4]>,
    closed: AtomicBool,
    recv_buf: Vec<u8>,
}

unsafe impl Send for TcpReceiver {}
unsafe impl Sync for TcpReceiver {}

impl TcpReceiver {
    pub fn new(
        listen_port: u16,
        peer_spoof_ip: Option<[u8; 4]>,
        buf_size: i32,
    ) -> Result<Box<Self>, String> {
        let fd = create_raw_recv_tcp_socket(buf_size)
            .map_err(|e| format!("create raw socket: {e}"))?;

        Ok(Box::new(TcpReceiver {
            fd,
            listen_port,
            peer_spoof_ip,
            closed: AtomicBool::new(false),
            recv_buf: vec![0u8; 65536],
        }))
    }

    /// Blocking receive. Loops internally on transient errors.
    /// Copies payload into out_buf, returns metadata.
    pub fn recv(&mut self, out_buf: &mut [u8]) -> Result<RecvResult, String> {
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
                // EAGAIN, EINTR, timeout → retry
                continue;
            }

            let n = n as usize;
            let src_ip = addr.sin_addr.s_addr.to_ne_bytes();

            // Filter by peer spoof IP
            if let Some(ref expected) = self.peer_spoof_ip {
                if src_ip != *expected {
                    continue;
                }
            }

            // Parse packet
            if let Some(result) = self.parse_packet(n, &src_ip, out_buf) {
                return Ok(result);
            }
        }
    }

    #[inline]
    fn parse_packet(&self, n: usize, src_ip: &[u8; 4], out_buf: &mut [u8]) -> Option<RecvResult> {
        let buf = &self.recv_buf[..n];

        if n < 20 { return None; }

        let ihl = ((buf[0] & 0x0F) as usize) * 4;
        if n < ihl + 20 { return None; }
        if buf[9] != libc::IPPROTO_TCP as u8 { return None; }

        let tcp = &buf[ihl..];

        // Destination port
        let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        if dst_port != self.listen_port { return None; }

        // Source port
        let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);

        // Flags: SYN
        if tcp[13] & 0x02 != 0x02 { return None; }

        // Data offset
        let data_offset = ((tcp[12] >> 4) as usize) * 4;
        let payload_start = ihl + data_offset;
        if payload_start > n { return None; }

        let payload_len = n - payload_start;
        if payload_len == 0 { return None; }
        if payload_len > out_buf.len() { return None; }

        out_buf[..payload_len].copy_from_slice(&buf[payload_start..n]);

        Some(RecvResult {
            payload_len,
            src_ip: *src_ip,
            src_port,
        })
    }

    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            close_fd(self.fd);
        }
    }
}

impl Drop for TcpReceiver {
    fn drop(&mut self) {
        self.close();
    }
}
