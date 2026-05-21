/// Spoofed UDP sender with round-robin multi-IP.
///
/// Sends complete UDP datagrams with spoofed source IP via raw socket.
/// No application-level fragmentation — each payload is sent as a single UDP packet.

use crate::raw_socket::{close_fd, create_raw_send_socket, sendto_raw};
use crate::tcp_sender::write_ip_header_only;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const IP_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

pub struct UdpSender {
    fd: i32,
    src_ips: Vec<[u8; 4]>,
    ip_index: AtomicUsize,
    src_port: u16,
    closed: AtomicBool,
}

unsafe impl Send for UdpSender {}
unsafe impl Sync for UdpSender {}

impl UdpSender {
    pub fn new(
        src_ip: [u8; 4],
        src_port: u16,
        _mtu: i32,
    ) -> Result<Box<Self>, String> {
        Self::new_multi(vec![src_ip], src_port, _mtu)
    }

    pub fn new_multi(
        src_ips: Vec<[u8; 4]>,
        src_port: u16,
        _mtu: i32,
    ) -> Result<Box<Self>, String> {
        if src_ips.is_empty() {
            return Err("at least one source IP is required".into());
        }

        let fd = create_raw_send_socket().map_err(|e| format!("create raw socket: {e}"))?;

        Ok(Box::new(UdpSender {
            fd,
            src_ips,
            ip_index: AtomicUsize::new(0),
            src_port,
            closed: AtomicBool::new(false),
        }))
    }

    #[inline]
    fn next_src_ip(&self) -> &[u8; 4] {
        let idx = self.ip_index.fetch_add(1, Ordering::Relaxed);
        &self.src_ips[idx % self.src_ips.len()]
    }

    pub fn send(&self, payload: &[u8], dst_ip: &[u8; 4], dst_port: u16) -> Result<(), String> {
        if self.closed.load(Ordering::Relaxed) {
            return Err("connection closed".into());
        }

        let src_ip = *self.next_src_ip();

        let udp_total_len = UDP_HEADER_LEN + payload.len();
        let ip_pkt_len = IP_HEADER_LEN + udp_total_len;

        use std::cell::RefCell;
        thread_local! {
            static PKT_BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; 1500]);
        }

        PKT_BUF.with(|pkt_cell| {
            let mut pkt = pkt_cell.borrow_mut();

            if pkt.len() < ip_pkt_len {
                pkt.resize(ip_pkt_len, 0);
            }

            // IP header
            write_ip_header_only(
                &mut pkt,
                &src_ip,
                dst_ip,
                0, 0, false,
                libc::IPPROTO_UDP as u8,
                udp_total_len,
            );

            // UDP header at pkt[20..28]
            let u = IP_HEADER_LEN;
            pkt[u]     = (self.src_port >> 8) as u8;
            pkt[u + 1] = self.src_port as u8;
            pkt[u + 2] = (dst_port >> 8) as u8;
            pkt[u + 3] = dst_port as u8;
            pkt[u + 4] = (udp_total_len >> 8) as u8;
            pkt[u + 5] = udp_total_len as u8;
            pkt[u + 6] = 0; // checksum (optional IPv4)
            pkt[u + 7] = 0;

            // Payload at pkt[28..]
            let d = u + UDP_HEADER_LEN;
            if !payload.is_empty() {
                pkt[d..d + payload.len()].copy_from_slice(payload);
            }

            sendto_raw(self.fd, &pkt[..ip_pkt_len], dst_ip)
                .map_err(|e| format!("sendto: {e}"))
        })
    }

    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            close_fd(self.fd);
        }
    }
}

impl Drop for UdpSender {
    fn drop(&mut self) {
        self.close();
    }
}
