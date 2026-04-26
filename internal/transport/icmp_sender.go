package transport

// #include "spoof_transport.h"
import "C"
import (
	"fmt"
	"net"
	"sync/atomic"
	"unsafe"
)

// ICMPSender sends spoofed ICMP Echo Request packets via Rust.
type ICMPSender struct {
	handle C.SpoofHandle
	closed atomic.Bool
}

// NewICMPSender creates an ICMP sender backed by Rust.
func NewICMPSender(cfg SenderConfig) (*ICMPSender, error) {
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
			return nil, fmt.Errorf("ICMPSender only supports IPv4")
		}
		ipBuf = append(ipBuf, ip4...)
	}

	h := C.spoof_icmp_sender_new_multi(
		(*C.uint8_t)(unsafe.Pointer(&ipBuf[0])),
		C.uintptr_t(len(ips)),
		C.uint16_t(cfg.SourcePort), // used as ICMP identifier
		C.int32_t(mtu),
	)
	if h == nil {
		return nil, fmt.Errorf("create ICMP raw socket failed (need root/CAP_NET_RAW)")
	}

	return &ICMPSender{handle: h}, nil
}

func (s *ICMPSender) Send(payload []byte, dstIP net.IP, _ uint16) error {
	if s.closed.Load() {
		return ErrConnectionClosed
	}
	dst4 := dstIP.To4()
	if dst4 == nil {
		return fmt.Errorf("ICMPSender only supports IPv4")
	}

	rc := C.spoof_icmp_sender_send(
		s.handle,
		(*C.uint8_t)(unsafe.Pointer(&payload[0])),
		C.uintptr_t(len(payload)),
		(*C.uint8_t)(unsafe.Pointer(&dst4[0])),
	)
	if rc != 0 {
		return fmt.Errorf("ICMP sendto failed")
	}
	return nil
}

func (s *ICMPSender) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	C.spoof_icmp_sender_close(s.handle)
	return nil
}

