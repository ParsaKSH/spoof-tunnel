package transport

// #include "spoof_transport.h"
import "C"
import (
	"fmt"
	"net"
	"sync/atomic"
	"unsafe"
)

// TCPSender sends spoofed TCP SYN packets via the Rust transport layer.
type TCPSender struct {
	handle C.SpoofHandle
	closed atomic.Bool
}

// NewTCPSender creates a raw socket sender backed by Rust.
func NewTCPSender(cfg SenderConfig) (*TCPSender, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1400
	}

	ips := cfg.GetIPList()

	// Build flat byte array: [ip0_b0..ip0_b3, ip1_b0..ip1_b3, ...]
	ipBuf := make([]byte, 0, len(ips)*4)
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("TCPSender only supports IPv4")
		}
		ipBuf = append(ipBuf, ip4...)
	}

	var h C.SpoofHandle
	if len(ips) == 1 {
		h = C.spoof_tcp_sender_new(
			(*C.uint8_t)(unsafe.Pointer(&ipBuf[0])),
			C.uint16_t(cfg.SourcePort),
			C.int32_t(mtu),
		)
	} else {
		h = C.spoof_tcp_sender_new_multi(
			(*C.uint8_t)(unsafe.Pointer(&ipBuf[0])),
			C.uintptr_t(len(ips)),
			C.uint16_t(cfg.SourcePort),
			C.int32_t(mtu),
		)
	}

	if h == nil {
		return nil, fmt.Errorf("create raw socket failed (need root/CAP_NET_RAW)")
	}

	return &TCPSender{
		handle: h,
	}, nil
}

// Send builds and sends a spoofed TCP SYN packet via Rust.
func (t *TCPSender) Send(payload []byte, dstIP net.IP, dstPort uint16) error {
	if t.closed.Load() {
		return ErrConnectionClosed
	}

	dst4 := dstIP.To4()
	if dst4 == nil {
		return fmt.Errorf("TCPSender only supports IPv4")
	}

	rc := C.spoof_tcp_sender_send(
		t.handle,
		(*C.uint8_t)(unsafe.Pointer(&payload[0])),
		C.uintptr_t(len(payload)),
		(*C.uint8_t)(unsafe.Pointer(&dst4[0])),
		C.uint16_t(dstPort),
	)
	if rc != 0 {
		return fmt.Errorf("sendto failed")
	}
	return nil
}

// Close releases the Rust handle and raw socket.
func (t *TCPSender) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	C.spoof_tcp_sender_close(t.handle)
	return nil
}
