/// Spoofed TCP SYN sender with round-robin multi-IP and IP-level fragmentation.
///
/// Supports a list of spoofed source IPs that rotate per-packet (round-robin).
/// Uses stack-allocated buffers for non-fragmented packets (the common path)
/// and thread-local buffers for the rare fragmented case.

use crate::checksum::tcp_checksum;
use crate::raw_socket::{close_fd, create_raw_send_socket, random_ip_id, sendto_raw};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

const IP_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20; // 20 base, no options for SYN

/// Maximum single-packet size (non-fragmented). Stack-allocated.
const MAX_PKT_STACK: usize = 1520;

/// Maximum TCP segment size for thread-local buffer (for fragmented case).
const MAX_TCP_SEG: usize = 65536 + TCP_HEADER_LEN;

pub struct TcpSender {
    fd: i32,
    src_ips: Vec<[u8; 4]>,
    ip_index: AtomicUsize,
    src_port: u16,
    mtu: usize,
    seq: AtomicU32,
    closed: AtomicBool,
}

unsafe impl Send for TcpSender {}
unsafe impl Sync for TcpSender {}

impl TcpSender {
    /// Create with a single source IP (backward compatible).
    pub fn new(src_ip: [u8; 4], src_port: u16, mtu: i32) -> Result<Box<Self>, String> {
        Self::new_multi(vec![src_ip], src_port, mtu)
    }

    /// Create with multiple source IPs for round-robin rotation.
    pub fn new_multi(src_ips: Vec<[u8; 4]>, src_port: u16, mtu: i32) -> Result<Box<Self>, String> {
        if src_ips.is_empty() {
            return Err("at least one source IP is required".into());
        }

        let fd = create_raw_send_socket().map_err(|e| format!("create raw socket: {e}"))?;
        let mtu = if mtu <= 0 || mtu > 1500 { 1500 } else { mtu as usize };

        Ok(Box::new(TcpSender {
            fd,
            src_ips,
            ip_index: AtomicUsize::new(0),
            src_port,
            mtu,
            seq: AtomicU32::new(1),
            closed: AtomicBool::new(false),
        }))
    }

    /// Get the next source IP via round-robin.
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
        let tcp_seg_len = TCP_HEADER_LEN + payload.len();
        let full_size = IP_HEADER_LEN + tcp_seg_len;

        if full_size <= self.mtu {
            // Fast path: entire packet fits in MTU → stack-allocated buffer, zero heap alloc
            self.send_no_frag(&src_ip, dst_ip, dst_port, payload, tcp_seg_len, full_size)
        } else {
            // Slow path: needs IP-level fragmentation → thread-local buffers
            self.send_fragmented(&src_ip, dst_ip, dst_port, payload, tcp_seg_len)
        }
    }

    /// Fast path: build and send a single non-fragmented TCP packet on the stack.
    #[inline]
    fn send_no_frag(
        &self,
        src_ip: &[u8; 4],
        dst_ip: &[u8; 4],
        dst_port: u16,
        payload: &[u8],
        tcp_seg_len: usize,
        full_size: usize,
    ) -> Result<(), String> {
        let mut pkt = [0u8; MAX_PKT_STACK];

        // Build TCP segment at pkt[IP_HEADER_LEN..]
        self.build_tcp_segment(
            &mut pkt[IP_HEADER_LEN..IP_HEADER_LEN + tcp_seg_len],
            src_ip,
            dst_ip,
            dst_port,
            payload,
        );

        // Write IP header at pkt[0..20] (payload already in place)
        write_ip_header_only(
            &mut pkt,
            src_ip,
            dst_ip,
            0,
            0,
            false,
            libc::IPPROTO_TCP as u8,
            tcp_seg_len,
        );

        sendto_raw(self.fd, &pkt[..full_size], dst_ip)
            .map_err(|e| format!("sendto: {e}"))
    }

    /// Slow path: fragment the TCP segment.
    fn send_fragmented(
        &self,
        src_ip: &[u8; 4],
        dst_ip: &[u8; 4],
        dst_port: u16,
        payload: &[u8],
        tcp_seg_len: usize,
    ) -> Result<(), String> {
        use std::cell::RefCell;

        thread_local! {
            static TCP_SEG_BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; MAX_TCP_SEG]);
            static FRAG_PKT_BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; 1520]);
        }

        TCP_SEG_BUF.with(|seg_cell| {
            let mut seg_buf = seg_cell.borrow_mut();
            if seg_buf.len() < tcp_seg_len {
                seg_buf.resize(tcp_seg_len, 0);
            }

            self.build_tcp_segment(
                &mut seg_buf[..tcp_seg_len],
                src_ip,
                dst_ip,
                dst_port,
                payload,
            );

            FRAG_PKT_BUF.with(|pkt_cell| {
                let mut pkt_buf = pkt_cell.borrow_mut();
                let max_data = ((self.mtu - IP_HEADER_LEN) / 8) * 8;
                let ip_id = random_ip_id();

                let mut offset = 0;
                while offset < tcp_seg_len {
                    let end = std::cmp::min(offset + max_data, tcp_seg_len);
                    let more = end < tcp_seg_len;
                    let chunk_len = end - offset;
                    let pkt_len = IP_HEADER_LEN + chunk_len;

                    if pkt_buf.len() < pkt_len {
                        pkt_buf.resize(pkt_len, 0);
                    }

                    write_ip_header_only(
                        &mut pkt_buf,
                        src_ip,
                        dst_ip,
                        ip_id,
                        offset as u16,
                        more,
                        libc::IPPROTO_TCP as u8,
                        chunk_len,
                    );
                    pkt_buf[IP_HEADER_LEN..pkt_len]
                        .copy_from_slice(&seg_buf[offset..end]);

                    sendto_raw(self.fd, &pkt_buf[..pkt_len], dst_ip)
                        .map_err(|e| format!("sendto frag offset={offset}: {e}"))?;

                    offset = end;
                }

                Ok(())
            })
        })
    }

    fn build_tcp_segment(
        &self,
        seg: &mut [u8],
        src_ip: &[u8; 4],
        dst_ip: &[u8; 4],
        dst_port: u16,
        payload: &[u8],
    ) {
        let seq = self.seq.fetch_add(payload.len() as u32, Ordering::Relaxed);

        // Source port
        seg[0] = (self.src_port >> 8) as u8;
        seg[1] = self.src_port as u8;
        // Dest port
        seg[2] = (dst_port >> 8) as u8;
        seg[3] = dst_port as u8;
        // Sequence
        seg[4..8].copy_from_slice(&seq.to_be_bytes());
        // Acknowledgment (0 for SYN)
        seg[8..12].copy_from_slice(&0u32.to_be_bytes());
        // Data offset (20/4=5 << 4)
        seg[12] = (TCP_HEADER_LEN as u8 / 4) << 4;
        // Flags: SYN
        seg[13] = 0x02;
        // Window: 65535
        seg[14] = 0xFF;
        seg[15] = 0xFF;
        // Checksum placeholder
        seg[16] = 0;
        seg[17] = 0;
        // Urgent pointer
        seg[18] = 0;
        seg[19] = 0;

        // Payload (starts right after 20-byte TCP header)
        seg[TCP_HEADER_LEN..TCP_HEADER_LEN + payload.len()].copy_from_slice(payload);

        // Checksum (zero-allocation)
        let csum = tcp_checksum(src_ip, dst_ip, seg);
        seg[16] = (csum >> 8) as u8;
        seg[17] = csum as u8;
    }

    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            close_fd(self.fd);
        }
    }
}

impl Drop for TcpSender {
    fn drop(&mut self) {
        self.close();
    }
}

/// Write ONLY the IP header into pkt[0..20]. Does NOT copy payload data.
#[inline]
pub fn write_ip_header_only(
    pkt: &mut [u8],
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    ip_id: u16,
    frag_offset: u16,
    more_fragments: bool,
    protocol: u8,
    payload_len: usize,
) {
    let total_len = (IP_HEADER_LEN + payload_len) as u16;

    pkt[0] = 0x45; // Version=4, IHL=5
    pkt[1] = 0x00;
    pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
    pkt[4..6].copy_from_slice(&ip_id.to_be_bytes());

    let mut flags_offset = frag_offset / 8;
    if more_fragments {
        flags_offset |= 0x2000;
    }
    pkt[6..8].copy_from_slice(&flags_offset.to_be_bytes());

    pkt[8] = 64; // TTL
    pkt[9] = protocol;
    pkt[10] = 0; // checksum (kernel fills)
    pkt[11] = 0;
    pkt[12..16].copy_from_slice(src_ip);
    pkt[16..20].copy_from_slice(dst_ip);
}
