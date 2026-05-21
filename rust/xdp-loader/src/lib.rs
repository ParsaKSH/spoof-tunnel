//! XDP Loader — userspace component that loads the eBPF XDP program,
//! configures BPF maps, and reads packets from the ring buffer.
//!
//! Exports a C ABI matching the existing spoof_*_receiver_* pattern
//! so Go can use it via CGo with zero changes to the relay logic.

use aya::maps::{HashMap, RingBuf};
use aya::programs::{Xdp, XdpFlags};
use aya::{EbpfLoader, Pod};
use std::ffi::CStr;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};

/// Matches the eBPF-side struct.
#[repr(C)]
#[derive(Clone, Copy)]
struct XdpConfig {
    peer_ip: u32,
    dst_port: u16,
    protocol: u8,
    _pad: u8,
}

unsafe impl Pod for XdpConfig {}

/// Matches the eBPF-side struct.
#[repr(C)]
#[derive(Clone, Copy)]
struct PktMeta {
    src_ip: u32,
    src_port: u16,
    payload_len: u16,
}

/// Internal state for one XDP receiver instance.
struct XdpReceiver {
    ring: RingBuf<aya::maps::MapData>,
    closed: AtomicBool,
    interface: String,
    // Keep bpf alive so the XDP program stays attached.
    // It's not directly used after setup, but dropping it detaches the program.
    _bpf: aya::Ebpf,
}

// We manage thread safety ourselves
unsafe impl Send for XdpReceiver {}
unsafe impl Sync for XdpReceiver {}

/// Embedded eBPF bytecode — compiled from xdp-ebpf crate.
/// Included at compile time so the binary is self-contained.
static XDP_ELF_RAW: &[u8] = include_bytes!(
    "../../xdp-ebpf/target/bpfel-unknown-none/release/xdp-ebpf"
);

/// Return an aligned copy of the eBPF ELF.
/// The `object` crate requires 8-byte alignment for ELF header parsing.
fn aligned_elf_copy() -> Vec<u8> {
    // Vec<u8> is always properly aligned (allocator guarantees ≥ pointer alignment)
    XDP_ELF_RAW.to_vec()
}

/// Create and attach an XDP receiver.
///
/// # Safety
/// `interface_name` must be a valid C string.
/// `peer_spoof_ip` may be null (accept all) or point to 4 bytes.
#[no_mangle]
pub unsafe extern "C" fn spoof_xdp_receiver_new(
    interface_name: *const libc::c_char,
    peer_spoof_ip: *const u8,
    listen_port: u16,
    protocol: u8,
) -> *mut libc::c_void {
    let iface = match CStr::from_ptr(interface_name).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return std::ptr::null_mut(),
    };

    let _ = env_logger::try_init();

    // Load eBPF program from aligned copy of embedded ELF
    let elf_data = aligned_elf_copy();
    let mut bpf = match EbpfLoader::new().load(&elf_data) {
        Ok(b) => b,
        Err(e) => {
            log::error!("[xdp-loader] failed to load eBPF: {}", e);
            return std::ptr::null_mut();
        }
    };

    // Attach XDP program to interface
    {
        let prog: &mut Xdp = match bpf.program_mut("spoof_xdp_recv") {
            Some(p) => match p.try_into() {
                Ok(x) => x,
                Err(e) => {
                    log::error!("[xdp-loader] program type error: {}", e);
                    return std::ptr::null_mut();
                }
            },
            None => {
                log::error!("[xdp-loader] program 'spoof_xdp_recv' not found");
                return std::ptr::null_mut();
            }
        };

        if let Err(e) = prog.load() {
            log::error!("[xdp-loader] failed to load program: {}", e);
            return std::ptr::null_mut();
        }

        // Try SKB mode first (works everywhere), then native driver mode
        let attach_result = prog
            .attach(&iface, XdpFlags::SKB_MODE)
            .or_else(|_| prog.attach(&iface, XdpFlags::default()));

        if let Err(e) = attach_result {
            log::error!("[xdp-loader] attach to '{}' failed: {}", iface, e);
            return std::ptr::null_mut();
        }

        log::info!("[xdp-loader] attached XDP to '{}'", iface);
    }

    // Write config to BPF map
    {
        let peer_ip = if peer_spoof_ip.is_null() {
            0u32
        } else {
            u32::from_ne_bytes([
                *peer_spoof_ip,
                *peer_spoof_ip.add(1),
                *peer_spoof_ip.add(2),
                *peer_spoof_ip.add(3),
            ])
        };

        let cfg = XdpConfig {
            peer_ip,
            dst_port: listen_port,
            protocol,
            _pad: 0,
        };

        let mut config_map: HashMap<_, u32, XdpConfig> =
            match HashMap::try_from(bpf.map_mut("CONFIG").unwrap()) {
                Ok(m) => m,
                Err(e) => {
                    log::error!("[xdp-loader] CONFIG map error: {}", e);
                    return std::ptr::null_mut();
                }
            };

        if let Err(e) = config_map.insert(0u32, cfg, 0) {
            log::error!("[xdp-loader] config insert error: {}", e);
            return std::ptr::null_mut();
        }
    }

    // Get ring buffer handle (take ownership of the map)
    let ring: RingBuf<aya::maps::MapData> =
        match RingBuf::try_from(bpf.take_map("PAYLOADS").unwrap()) {
            Ok(r) => r,
            Err(e) => {
                log::error!("[xdp-loader] PAYLOADS ring error: {}", e);
                return std::ptr::null_mut();
            }
        };

    let receiver = Box::new(XdpReceiver {
        ring,
        closed: AtomicBool::new(false),
        interface: iface.clone(),
        _bpf: bpf,
    });

    log::info!("[xdp-loader] receiver ready on '{}'", iface);
    Box::into_raw(receiver) as *mut libc::c_void
}

/// Blocking receive — reads next packet from ring buffer.
/// Returns payload length, or -1 on error, or -2 if closed.
///
/// # Safety
/// `handle` must have been returned by `spoof_xdp_receiver_new`.
#[no_mangle]
pub unsafe extern "C" fn spoof_xdp_receiver_recv(
    handle: *mut libc::c_void,
    out_buf: *mut u8,
    out_buf_len: usize,
    src_ip_out: *mut u8,
    src_port_out: *mut u16,
) -> i32 {
    if handle.is_null() || out_buf.is_null() {
        return -1;
    }

    let receiver = &mut *(handle as *mut XdpReceiver);
    let ring_raw_fd = receiver.ring.as_raw_fd();

    loop {
        if receiver.closed.load(Ordering::Relaxed) {
            return -2;
        }

        // Try to read from ring buffer
        if let Some(item) = receiver.ring.next() {
            let data = &*item;
            let meta_size = std::mem::size_of::<PktMeta>();

            if data.len() < meta_size {
                continue;
            }

            let meta: PktMeta = std::ptr::read_unaligned(data.as_ptr() as *const PktMeta);
            let payload_len = meta.payload_len as usize;
            let payload_start = meta_size;

            if payload_start + payload_len > data.len() || payload_len > out_buf_len {
                continue;
            }

            // Copy payload
            std::ptr::copy_nonoverlapping(
                data[payload_start..payload_start + payload_len].as_ptr(),
                out_buf,
                payload_len,
            );

            if !src_ip_out.is_null() {
                let ip_bytes = meta.src_ip.to_ne_bytes();
                std::ptr::copy_nonoverlapping(ip_bytes.as_ptr(), src_ip_out, 4);
            }
            if !src_port_out.is_null() {
                *src_port_out = meta.src_port;
            }

            return payload_len as i32;
        }

        // No data — use epoll to wait efficiently (100ms timeout)
        let epfd = libc::epoll_create1(0);
        if epfd < 0 {
            std::thread::sleep(std::time::Duration::from_micros(100));
            continue;
        }

        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: 0,
        };
        libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, ring_raw_fd, &mut ev);

        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
        libc::epoll_wait(epfd, events.as_mut_ptr(), 1, 100);
        libc::close(epfd);
    }
}

/// Close the XDP receiver and detach the program.
#[no_mangle]
pub unsafe extern "C" fn spoof_xdp_receiver_close(handle: *mut libc::c_void) {
    if handle.is_null() {
        return;
    }
    let receiver = Box::from_raw(handle as *mut XdpReceiver);
    receiver.closed.store(true, Ordering::SeqCst);
    log::info!("[xdp-loader] detaching XDP from '{}'", receiver.interface);
    drop(receiver);
}

/// Check if XDP is available on this system (returns 1=yes, 0=no).
#[no_mangle]
pub extern "C" fn spoof_xdp_available() -> i32 {
    let elf_data = aligned_elf_copy();
    match EbpfLoader::new().load(&elf_data) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}
