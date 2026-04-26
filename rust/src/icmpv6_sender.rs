/// ICMPv6 sender over IPv4 (non-standard, proto 58).
///
/// Same as ICMP sender but uses protocol number 58 and type 128 (Echo Request).

use crate::checksum::checksum_rfc1071;
use crate::raw_socket::{close_fd, create_raw_send_socket, random_ip_id, sendto_raw};
use crate::tcp_sender::write_ip_header_only;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};

const IP_HEADER_LEN: usize = 20;
const ICMPV6_HEADER_LEN: usize = 8;
pub const ICMPV6_PROTO: u8 = 58;

pub struct Icmpv6Sender {
    fd: i32,
    src_ips: Vec<[u8; 4]>,
    ip_index: AtomicUsize,
    icmp_id: u16,
    seq: AtomicU16,
    mtu: usize,
    closed: AtomicBool,
}

unsafe impl Send for Icmpv6Sender {}
unsafe impl Sync for Icmpv6Sender {}

impl Icmpv6Sender {
    pub fn new_multi(src_ips: Vec<[u8; 4]>, icmp_id: u16, mtu: i32) -> Result<Box<Self>, String> {
        if src_ips.is_empty() {
            return Err("at least one source IP is required".into());
        }
        let fd = create_raw_send_socket().map_err(|e| format!("create raw socket: {e}"))?;
        let mtu = if mtu <= 0 || mtu > 1500 { 1500 } else { mtu as usize };

        Ok(Box::new(Icmpv6Sender {
            fd,
            src_ips,
            ip_index: AtomicUsize::new(0),
            icmp_id,
            seq: AtomicU16::new(1),
            mtu,
            closed: AtomicBool::new(false),
        }))
    }

    #[inline]
    fn next_src_ip(&self) -> &[u8; 4] {
        let idx = self.ip_index.fetch_add(1, Ordering::Relaxed);
        &self.src_ips[idx % self.src_ips.len()]
    }

    pub fn send(&self, payload: &[u8], dst_ip: &[u8; 4]) -> Result<(), String> {
        if self.closed.load(Ordering::Relaxed) {
            return Err("connection closed".into());
        }

        let src_ip = *self.next_src_ip();
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);

        let icmp_len = ICMPV6_HEADER_LEN + payload.len();
        let mut icmp_msg = vec![0u8; icmp_len];

        icmp_msg[0] = 128;  // Type: Echo Request (ICMPv6)
        icmp_msg[1] = 0;
        icmp_msg[2] = 0;
        icmp_msg[3] = 0;
        icmp_msg[4] = (self.icmp_id >> 8) as u8;
        icmp_msg[5] = self.icmp_id as u8;
        icmp_msg[6] = (seq >> 8) as u8;
        icmp_msg[7] = seq as u8;
        icmp_msg[ICMPV6_HEADER_LEN..].copy_from_slice(payload);

        let csum = checksum_rfc1071(&icmp_msg);
        icmp_msg[2] = (csum >> 8) as u8;
        icmp_msg[3] = csum as u8;

        let full_size = IP_HEADER_LEN + icmp_len;
        if full_size <= self.mtu {
            let mut pkt = vec![0u8; full_size];
            write_ip_header_only(&mut pkt, &src_ip, dst_ip, 0, 0, false, ICMPV6_PROTO, icmp_len);
            pkt[IP_HEADER_LEN..].copy_from_slice(&icmp_msg);
            sendto_raw(self.fd, &pkt, dst_ip).map_err(|e| format!("sendto: {e}"))?;
        } else {
            let max_data = ((self.mtu - IP_HEADER_LEN) / 8) * 8;
            let ip_id = random_ip_id();
            let mut offset = 0;
            while offset < icmp_msg.len() {
                let end = std::cmp::min(offset + max_data, icmp_msg.len());
                let more = end < icmp_msg.len();
                let chunk = &icmp_msg[offset..end];
                let mut pkt = vec![0u8; IP_HEADER_LEN + chunk.len()];
                write_ip_header_only(&mut pkt, &src_ip, dst_ip, ip_id, offset as u16, more, ICMPV6_PROTO, chunk.len());
                pkt[IP_HEADER_LEN..IP_HEADER_LEN + chunk.len()].copy_from_slice(chunk);
                sendto_raw(self.fd, &pkt, dst_ip).map_err(|e| format!("sendto frag: {e}"))?;
                offset = end;
            }
        }

        Ok(())
    }

    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            close_fd(self.fd);
        }
    }
}

impl Drop for Icmpv6Sender {
    fn drop(&mut self) {
        self.close();
    }
}
