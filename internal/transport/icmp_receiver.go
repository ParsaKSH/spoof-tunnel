package transport

// #include "spoof_transport.h"
import "C"
import (
	"net"
	"sync/atomic"
	"unsafe"
)

// ICMPReceiver listens for ICMP Echo Request packets.
type ICMPReceiver struct {
	handle C.SpoofHandle
	closed atomic.Bool
	pktCh  chan receivedPacket
	doneCh chan struct{}
}

// NewICMPReceiver creates an ICMP receiver backed by Rust.
func NewICMPReceiver(cfg ReceiverConfig) (*ICMPReceiver, error) {
	var peerIP *C.uint8_t
	if cfg.PeerSpoofIP != nil {
		ip4 := cfg.PeerSpoofIP.To4()
		if ip4 != nil {
			peerIP = (*C.uint8_t)(unsafe.Pointer(&ip4[0]))
		}
	}

	h := C.spoof_icmp_receiver_new(peerIP, C.int32_t(cfg.BufferSize))
	if h == nil {
		return nil, &rawSocketError{msg: "create ICMP recv socket", err: ErrConnectionClosed}
	}

	r := &ICMPReceiver{
		handle: h,
		pktCh:  make(chan receivedPacket, 256),
		doneCh: make(chan struct{}),
	}
	go r.readLoop()
	return r, nil
}

func (r *ICMPReceiver) readLoop() {
	buf := make([]byte, 65536)
	var srcIPBuf [4]byte

	for {
		select {
		case <-r.doneCh:
			return
		default:
		}

		n := C.spoof_icmp_receiver_recv(
			r.handle,
			(*C.uint8_t)(unsafe.Pointer(&buf[0])),
			C.uintptr_t(len(buf)),
			(*C.uint8_t)(unsafe.Pointer(&srcIPBuf[0])),
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
			data:  data,
			srcIP: net.IPv4(srcIPBuf[0], srcIPBuf[1], srcIPBuf[2], srcIPBuf[3]),
		}

		select {
		case r.pktCh <- pkt:
		default:
			select {
			case <-r.pktCh:
			default:
			}
			r.pktCh <- pkt
		}
	}
}

func (r *ICMPReceiver) Receive() ([]byte, net.IP, uint16, error) {
	pkt, ok := <-r.pktCh
	if !ok {
		return nil, nil, 0, ErrConnectionClosed
	}
	return pkt.data, pkt.srcIP, 0, nil
}

func (r *ICMPReceiver) Close() error {
	if r.closed.Swap(true) {
		return nil
	}
	close(r.doneCh)
	C.spoof_icmp_receiver_close(r.handle)
	close(r.pktCh)
	return nil
}
