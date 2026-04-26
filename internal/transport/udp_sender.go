package transport

// #include "spoof_transport.h"
import "C"
import (
	"fmt"
	"net"
	"sync/atomic"
	"unsafe"
)

// UDPSender sends spoofed UDP packets via the Rust transport layer.
type UDPSender struct {
	handle C.SpoofHandle
	closed atomic.Bool
}

// NewUDPSender creates a sender backed by Rust that emits standard UDP packets.
func NewUDPSender(cfg SenderConfig) (*UDPSender, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1400
	}

	ips := cfg.GetIPList()

	ipBuf := make([]byte, 0, len(ips)*4)
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("UDPSender only supports IPv4")
		}
		ipBuf = append(ipBuf, ip4...)
	}

	var h C.SpoofHandle
	if len(ips) == 1 {
		h = C.spoof_udp_sender_new(
			(*C.uint8_t)(unsafe.Pointer(&ipBuf[0])),
			C.uint16_t(cfg.SourcePort),
			C.int32_t(mtu),
		)
	} else {
		h = C.spoof_udp_sender_new_multi(
			(*C.uint8_t)(unsafe.Pointer(&ipBuf[0])),
			C.uintptr_t(len(ips)),
			C.uint16_t(cfg.SourcePort),
			C.int32_t(mtu),
		)
	}

	if h == nil {
		return nil, fmt.Errorf("create raw socket failed (need root/CAP_NET_RAW)")
	}

	return &UDPSender{
		handle: h,
	}, nil
}

// Send builds and sends a spoofed UDP packet via Rust.
func (s *UDPSender) Send(payload []byte, dstIP net.IP, dstPort uint16) error {
	if s.closed.Load() {
		return ErrConnectionClosed
	}

	dst4 := dstIP.To4()
	if dst4 == nil {
		return fmt.Errorf("UDPSender only supports IPv4")
	}

	rc := C.spoof_udp_sender_send(
		s.handle,
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

// Close releases the Rust handle.
func (s *UDPSender) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	C.spoof_udp_sender_close(s.handle)
	return nil
}
