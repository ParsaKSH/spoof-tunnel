//! spoof-transport: High-performance raw socket transport layer.
//!
//! Exposes a C ABI for Go via CGo. Supports TCP, UDP, ICMP, ICMPv6.

mod checksum;
mod raw_socket;
mod tcp_receiver;
mod tcp_sender;
mod udp_sender;
mod icmp_sender;
mod icmp_receiver;
mod icmpv6_sender;
mod icmpv6_receiver;

use std::ffi::c_void;
use std::ptr;

unsafe fn parse_ip_array(ip_array: *const u8, ip_count: usize) -> Vec<[u8; 4]> {
    let mut ips = Vec::with_capacity(ip_count);
    for i in 0..ip_count {
        let mut ip = [0u8; 4];
        ptr::copy_nonoverlapping(ip_array.add(i * 4), ip.as_mut_ptr(), 4);
        ips.push(ip);
    }
    ips
}

// ═══════════════════════════════════════════════════════════
// TCP Sender
// ═══════════════════════════════════════════════════════════

#[no_mangle]
pub extern "C" fn spoof_tcp_sender_new(src_ip: *const u8, src_port: u16, mtu: i32) -> *mut c_void {
    if src_ip.is_null() { return ptr::null_mut(); }
    let ip: [u8; 4] = unsafe { *(src_ip as *const [u8; 4]) };
    match tcp_sender::TcpSender::new(ip, src_port, mtu) {
        Ok(s) => Box::into_raw(s) as *mut c_void,
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn spoof_tcp_sender_new_multi(ip_array: *const u8, ip_count: usize, src_port: u16, mtu: i32) -> *mut c_void {
    if ip_array.is_null() || ip_count == 0 { return ptr::null_mut(); }
    let ips = unsafe { parse_ip_array(ip_array, ip_count) };
    match tcp_sender::TcpSender::new_multi(ips, src_port, mtu) {
        Ok(s) => Box::into_raw(s) as *mut c_void,
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn spoof_tcp_sender_send(handle: *mut c_void, payload: *const u8, payload_len: usize, dst_ip: *const u8, dst_port: u16) -> i32 {
    if handle.is_null() || payload.is_null() || dst_ip.is_null() { return -1; }
    let sender = unsafe { &*(handle as *const tcp_sender::TcpSender) };
    let data = unsafe { std::slice::from_raw_parts(payload, payload_len) };
    let ip: [u8; 4] = unsafe { *(dst_ip as *const [u8; 4]) };
    match sender.send(data, &ip, dst_port) { Ok(()) => 0, Err(_) => -1 }
}

#[no_mangle]
pub extern "C" fn spoof_tcp_sender_close(handle: *mut c_void) {
    if !handle.is_null() { let s = unsafe { Box::from_raw(handle as *mut tcp_sender::TcpSender) }; s.close(); }
}

// ═══════════════════════════════════════════════════════════
// TCP Receiver
// ═══════════════════════════════════════════════════════════

#[no_mangle]
pub extern "C" fn spoof_tcp_receiver_new(listen_port: u16, peer_spoof_ip: *const u8, buf_size: i32) -> *mut c_void {
    let peer = if peer_spoof_ip.is_null() { None } else { Some(unsafe { *(peer_spoof_ip as *const [u8; 4]) }) };
    match tcp_receiver::TcpReceiver::new(listen_port, peer, buf_size) {
        Ok(r) => Box::into_raw(r) as *mut c_void,
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn spoof_tcp_receiver_recv(handle: *mut c_void, out_buf: *mut u8, out_buf_len: usize, src_ip_out: *mut u8, src_port_out: *mut u16) -> i32 {
    if handle.is_null() || out_buf.is_null() { return -1; }
    let receiver = unsafe { &mut *(handle as *mut tcp_receiver::TcpReceiver) };
    let buf = unsafe { std::slice::from_raw_parts_mut(out_buf, out_buf_len) };
    match receiver.recv(buf) {
        Ok(result) => {
            if !src_ip_out.is_null() { unsafe { ptr::copy_nonoverlapping(result.src_ip.as_ptr(), src_ip_out, 4); } }
            if !src_port_out.is_null() { unsafe { *src_port_out = result.src_port; } }
            result.payload_len as i32
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn spoof_tcp_receiver_close(handle: *mut c_void) {
    if !handle.is_null() { let r = unsafe { Box::from_raw(handle as *mut tcp_receiver::TcpReceiver) }; r.close(); }
}

// ═══════════════════════════════════════════════════════════
// UDP Sender
// ═══════════════════════════════════════════════════════════

#[no_mangle]
pub extern "C" fn spoof_udp_sender_new(src_ip: *const u8, src_port: u16, mtu: i32) -> *mut c_void {
    if src_ip.is_null() { return ptr::null_mut(); }
    let ip: [u8; 4] = unsafe { *(src_ip as *const [u8; 4]) };
    match udp_sender::UdpSender::new(ip, src_port, mtu) {
        Ok(s) => Box::into_raw(s) as *mut c_void,
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn spoof_udp_sender_new_multi(ip_array: *const u8, ip_count: usize, src_port: u16, mtu: i32) -> *mut c_void {
    if ip_array.is_null() || ip_count == 0 { return ptr::null_mut(); }
    let ips = unsafe { parse_ip_array(ip_array, ip_count) };
    match udp_sender::UdpSender::new_multi(ips, src_port, mtu) {
        Ok(s) => Box::into_raw(s) as *mut c_void,
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn spoof_udp_sender_send(handle: *mut c_void, payload: *const u8, payload_len: usize, dst_ip: *const u8, dst_port: u16) -> i32 {
    if handle.is_null() || payload.is_null() || dst_ip.is_null() { return -1; }
    let sender = unsafe { &*(handle as *const udp_sender::UdpSender) };
    let data = unsafe { std::slice::from_raw_parts(payload, payload_len) };
    let ip: [u8; 4] = unsafe { *(dst_ip as *const [u8; 4]) };
    match sender.send(data, &ip, dst_port) { Ok(()) => 0, Err(_) => -1 }
}

#[no_mangle]
pub extern "C" fn spoof_udp_sender_close(handle: *mut c_void) {
    if !handle.is_null() { let s = unsafe { Box::from_raw(handle as *mut udp_sender::UdpSender) }; s.close(); }
}

// ═══════════════════════════════════════════════════════════
// ICMP Sender (proto 1, type 8)
// ═══════════════════════════════════════════════════════════

#[no_mangle]
pub extern "C" fn spoof_icmp_sender_new_multi(ip_array: *const u8, ip_count: usize, icmp_id: u16, mtu: i32) -> *mut c_void {
    if ip_array.is_null() || ip_count == 0 { return ptr::null_mut(); }
    let ips = unsafe { parse_ip_array(ip_array, ip_count) };
    match icmp_sender::IcmpSender::new_multi(ips, icmp_id, mtu) {
        Ok(s) => Box::into_raw(s) as *mut c_void,
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn spoof_icmp_sender_send(handle: *mut c_void, payload: *const u8, payload_len: usize, dst_ip: *const u8) -> i32 {
    if handle.is_null() || payload.is_null() || dst_ip.is_null() { return -1; }
    let sender = unsafe { &*(handle as *const icmp_sender::IcmpSender) };
    let data = unsafe { std::slice::from_raw_parts(payload, payload_len) };
    let ip: [u8; 4] = unsafe { *(dst_ip as *const [u8; 4]) };
    match sender.send(data, &ip) { Ok(()) => 0, Err(_) => -1 }
}

#[no_mangle]
pub extern "C" fn spoof_icmp_sender_close(handle: *mut c_void) {
    if !handle.is_null() { let s = unsafe { Box::from_raw(handle as *mut icmp_sender::IcmpSender) }; s.close(); }
}

// ═══════════════════════════════════════════════════════════
// ICMP Receiver (proto 1, type 8)
// ═══════════════════════════════════════════════════════════

#[no_mangle]
pub extern "C" fn spoof_icmp_receiver_new(peer_ip: *const u8, buf_size: i32) -> *mut c_void {
    let peer = if peer_ip.is_null() { None } else { Some(unsafe { *(peer_ip as *const [u8; 4]) }) };
    match icmp_receiver::IcmpReceiver::new(peer, buf_size) {
        Ok(r) => Box::into_raw(r) as *mut c_void,
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn spoof_icmp_receiver_recv(handle: *mut c_void, out_buf: *mut u8, out_buf_len: usize, src_ip_out: *mut u8) -> i32 {
    if handle.is_null() || out_buf.is_null() { return -1; }
    let receiver = unsafe { &mut *(handle as *mut icmp_receiver::IcmpReceiver) };
    let buf = unsafe { std::slice::from_raw_parts_mut(out_buf, out_buf_len) };
    match receiver.recv(buf) {
        Ok(result) => {
            if !src_ip_out.is_null() { unsafe { ptr::copy_nonoverlapping(result.src_ip.as_ptr(), src_ip_out, 4); } }
            result.payload_len as i32
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn spoof_icmp_receiver_close(handle: *mut c_void) {
    if !handle.is_null() { let r = unsafe { Box::from_raw(handle as *mut icmp_receiver::IcmpReceiver) }; r.close(); }
}

// ═══════════════════════════════════════════════════════════
// ICMPv6 Sender (proto 58, type 128)
// ═══════════════════════════════════════════════════════════

#[no_mangle]
pub extern "C" fn spoof_icmpv6_sender_new_multi(ip_array: *const u8, ip_count: usize, icmp_id: u16, mtu: i32) -> *mut c_void {
    if ip_array.is_null() || ip_count == 0 { return ptr::null_mut(); }
    let ips = unsafe { parse_ip_array(ip_array, ip_count) };
    match icmpv6_sender::Icmpv6Sender::new_multi(ips, icmp_id, mtu) {
        Ok(s) => Box::into_raw(s) as *mut c_void,
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn spoof_icmpv6_sender_send(handle: *mut c_void, payload: *const u8, payload_len: usize, dst_ip: *const u8) -> i32 {
    if handle.is_null() || payload.is_null() || dst_ip.is_null() { return -1; }
    let sender = unsafe { &*(handle as *const icmpv6_sender::Icmpv6Sender) };
    let data = unsafe { std::slice::from_raw_parts(payload, payload_len) };
    let ip: [u8; 4] = unsafe { *(dst_ip as *const [u8; 4]) };
    match sender.send(data, &ip) { Ok(()) => 0, Err(_) => -1 }
}

#[no_mangle]
pub extern "C" fn spoof_icmpv6_sender_close(handle: *mut c_void) {
    if !handle.is_null() { let s = unsafe { Box::from_raw(handle as *mut icmpv6_sender::Icmpv6Sender) }; s.close(); }
}

// ═══════════════════════════════════════════════════════════
// ICMPv6 Receiver (proto 58, type 128)
// ═══════════════════════════════════════════════════════════

#[no_mangle]
pub extern "C" fn spoof_icmpv6_receiver_new(peer_ip: *const u8, buf_size: i32) -> *mut c_void {
    let peer = if peer_ip.is_null() { None } else { Some(unsafe { *(peer_ip as *const [u8; 4]) }) };
    match icmpv6_receiver::Icmpv6Receiver::new(peer, buf_size) {
        Ok(r) => Box::into_raw(r) as *mut c_void,
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn spoof_icmpv6_receiver_recv(handle: *mut c_void, out_buf: *mut u8, out_buf_len: usize, src_ip_out: *mut u8) -> i32 {
    if handle.is_null() || out_buf.is_null() { return -1; }
    let receiver = unsafe { &mut *(handle as *mut icmpv6_receiver::Icmpv6Receiver) };
    let buf = unsafe { std::slice::from_raw_parts_mut(out_buf, out_buf_len) };
    match receiver.recv(buf) {
        Ok(result) => {
            if !src_ip_out.is_null() { unsafe { ptr::copy_nonoverlapping(result.src_ip.as_ptr(), src_ip_out, 4); } }
            result.payload_len as i32
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn spoof_icmpv6_receiver_close(handle: *mut c_void) {
    if !handle.is_null() { let r = unsafe { Box::from_raw(handle as *mut icmpv6_receiver::Icmpv6Receiver) }; r.close(); }
}
