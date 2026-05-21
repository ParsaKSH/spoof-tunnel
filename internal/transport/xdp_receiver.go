package transport

// #include "spoof_transport.h"
// #include <stdlib.h>
import "C"
import (
	"fmt"
	"net"
	"sync/atomic"
	"unsafe"
)

// XDPReceiver provides high-performance packet reception using eBPF/XDP.
// Packets are filtered and parsed in kernel space before being delivered
// via a BPF ring buffer, eliminating sk_buff allocation overhead.
//
// Falls back to raw socket receivers if XDP is not available.
type XDPReceiver struct {
	handle C.SpoofHandle
	closed atomic.Bool

	pktCh  chan receivedPacket
	doneCh chan struct{}
}

// XDPAvailable checks if XDP/eBPF is supported on this kernel.
func XDPAvailable() bool {
	return C.spoof_xdp_available() == 1
}

// NewXDPReceiver creates an XDP-based receiver attached to a network interface.
//   - iface: network interface name (e.g. "eth0", "enp1s0")
//   - peerSpoofIP: only accept packets from this source IP (nil = accept all)
//   - listenPort: only accept packets to this dest port (0 = accept all)
//   - protocol: IP protocol number (6=TCP, 17=UDP, 1=ICMP)
func NewXDPReceiver(iface string, peerSpoofIP net.IP, listenPort uint16, protocol uint8) (*XDPReceiver, error) {
	ifaceC := C.CString(iface)
	defer C.free(unsafe.Pointer(ifaceC))

	var peerIP *C.uint8_t
	if peerSpoofIP != nil {
		ip4 := peerSpoofIP.To4()
		if ip4 != nil {
			peerIP = (*C.uint8_t)(unsafe.Pointer(&ip4[0]))
		}
	}

	h := C.spoof_xdp_receiver_new(
		ifaceC,
		peerIP,
		C.uint16_t(listenPort),
		C.uint8_t(protocol),
	)
	if h == nil {
		return nil, fmt.Errorf("XDP attach to %q failed (need root + kernel ≥5.8)", iface)
	}

	r := &XDPReceiver{
		handle: h,
		pktCh:  make(chan receivedPacket, 4096),
		doneCh: make(chan struct{}),
	}
	go r.readLoop()
	return r, nil
}

// readLoop calls the Rust XDP recv in a loop, delivering packets to pktCh.
func (r *XDPReceiver) readLoop() {
	buf := make([]byte, 65536)
	var srcIPBuf [4]byte
	var srcPort C.uint16_t

	for {
		select {
		case <-r.doneCh:
			return
		default:
		}

		n := C.spoof_xdp_receiver_recv(
			r.handle,
			(*C.uint8_t)(unsafe.Pointer(&buf[0])),
			C.uintptr_t(len(buf)),
			(*C.uint8_t)(unsafe.Pointer(&srcIPBuf[0])),
			&srcPort,
		)

		if n < 0 {
			if r.closed.Load() {
				return
			}
			continue
		}
		if n == 0 {
			continue
		}

		data := make([]byte, int(n))
		copy(data, buf[:int(n)])

		pkt := receivedPacket{
			data:    data,
			srcIP:   net.IPv4(srcIPBuf[0], srcIPBuf[1], srcIPBuf[2], srcIPBuf[3]),
			srcPort: uint16(srcPort),
		}

		select {
		case r.pktCh <- pkt:
		default:
			// Drop oldest if channel full
			select {
			case <-r.pktCh:
			default:
			}
			r.pktCh <- pkt
		}
	}
}

// Receive blocks until a packet arrives from XDP.
func (r *XDPReceiver) Receive() ([]byte, net.IP, uint16, error) {
	pkt, ok := <-r.pktCh
	if !ok {
		return nil, nil, 0, ErrConnectionClosed
	}
	return pkt.data, pkt.srcIP, pkt.srcPort, nil
}

// Close detaches the XDP program and cleans up.
func (r *XDPReceiver) Close() error {
	if r.closed.Swap(true) {
		return nil
	}
	close(r.doneCh)
	C.spoof_xdp_receiver_close(r.handle)
	close(r.pktCh)
	return nil
}
