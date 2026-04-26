/// RFC 1071 Internet Checksum computation.
///
/// The hot inner loop for every packet — LLVM auto-vectorizes
/// the 16-bit word accumulation when compiled with opt-level=3.

/// Compute the one's complement checksum over `data` (RFC 1071).
#[inline]
pub fn checksum_rfc1071(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let len = data.len();
    let mut i = 0;

    // Unrolled: process 8 bytes (4 words) per iteration
    while i + 7 < len {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        sum += u16::from_be_bytes([data[i + 2], data[i + 3]]) as u32;
        sum += u16::from_be_bytes([data[i + 4], data[i + 5]]) as u32;
        sum += u16::from_be_bytes([data[i + 6], data[i + 7]]) as u32;
        i += 8;
    }

    // Remaining full 16-bit words
    while i + 1 < len {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Odd trailing byte
    if i < len {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}

/// TCP checksum including IPv4 pseudo-header — ZERO allocation version.
/// Computes the pseudo-header sum inline instead of building a temporary Vec.
#[inline]
pub fn tcp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_segment: &[u8]) -> u16 {
    let tcp_len = tcp_segment.len();

    // Pseudo-header sum (computed directly, no allocation)
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += libc::IPPROTO_TCP as u32; // protocol
    sum += tcp_len as u32;           // TCP length

    // Add TCP segment data (unrolled)
    let mut i = 0;
    while i + 7 < tcp_len {
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        sum += u16::from_be_bytes([tcp_segment[i + 2], tcp_segment[i + 3]]) as u32;
        sum += u16::from_be_bytes([tcp_segment[i + 4], tcp_segment[i + 5]]) as u32;
        sum += u16::from_be_bytes([tcp_segment[i + 6], tcp_segment[i + 7]]) as u32;
        i += 8;
    }
    while i + 1 < tcp_len {
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_len {
        sum += (tcp_segment[i] as u32) << 8;
    }

    // Fold to 16 bits
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_even() {
        let data = [0x00, 0x01, 0x00, 0x02];
        assert_eq!(checksum_rfc1071(&data), 0xFFFC);
    }

    #[test]
    fn test_checksum_consistent() {
        let data = b"Hello, World!";
        let c1 = checksum_rfc1071(data);
        let c2 = checksum_rfc1071(data);
        assert_eq!(c1, c2);
        assert_ne!(c1, 0);
    }

    #[test]
    fn test_tcp_checksum_consistent() {
        let src = [10, 0, 0, 1];
        let dst = [10, 0, 0, 2];
        let seg = vec![0u8; 32];
        assert_eq!(tcp_checksum(&src, &dst, &seg), tcp_checksum(&src, &dst, &seg));
    }

    #[test]
    fn test_tcp_checksum_matches_rfc1071() {
        // Verify the zero-alloc version gives same result as allocating version
        let src = [192, 168, 1, 1];
        let dst = [10, 0, 0, 2];
        let seg = vec![0xAA; 64];

        // Build pseudo-header + segment the old way
        let tcp_len = seg.len();
        let mut buf = Vec::with_capacity(12 + tcp_len);
        buf.extend_from_slice(&src);
        buf.extend_from_slice(&dst);
        buf.push(0);
        buf.push(libc::IPPROTO_TCP as u8);
        buf.push((tcp_len >> 8) as u8);
        buf.push(tcp_len as u8);
        buf.extend_from_slice(&seg);
        let expected = checksum_rfc1071(&buf);

        let actual = tcp_checksum(&src, &dst, &seg);
        assert_eq!(actual, expected);
    }
}
