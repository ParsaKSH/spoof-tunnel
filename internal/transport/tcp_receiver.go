package transport

// #include "spoof_transport.h"
import "C"
import (
	"net"
	"sync/atomic"
	"unsafe"
)

// receivedPacket holds a parsed TCP packet payload and its source address.
type receivedPacket struct {
	data    []byte
	srcIP   net.IP
	srcPort uint16
}

// TCPReceiver listens for incoming spoofed TCP SYN packets.
// Uses Rust for the raw socket recv+parse, Go for goroutine+channel delivery.
type TCPReceiver struct {
	handle C.SpoofHandle
	closed atomic.Bool

	pktCh  chan receivedPacket
	doneCh chan struct{}
}

// NewTCPReceiver creates a raw socket listener backed by Rust.
func NewTCPReceiver(cfg ReceiverConfig) (*TCPReceiver, error) {
	var peerIP *C.uint8_t
	if cfg.PeerSpoofIP != nil {
		ip4 := cfg.PeerSpoofIP.To4()
		if ip4 != nil {
			peerIP = (*C.uint8_t)(unsafe.Pointer(&ip4[0]))
		}
	}

	h := C.spoof_tcp_receiver_new(
		C.uint16_t(cfg.ListenPort),
		peerIP,
		C.int32_t(cfg.BufferSize),
	)
	if h == nil {
		return nil, &rawSocketError{msg: "create raw TCP recv socket", err: ErrConnectionClosed}
	}

	r := &TCPReceiver{
		handle: h,
		pktCh:  make(chan receivedPacket, 4096),
		doneCh: make(chan struct{}),
	}
	go r.readLoop()
	return r, nil
}

// readLoop calls Rust's blocking recv in a loop, delivering packets to pktCh.
func (r *TCPReceiver) readLoop() {
	buf := make([]byte, 65536)
	var srcIPBuf [4]byte
	var srcPort C.uint16_t

	for {
		select {
		case <-r.doneCh:
			return
		default:
		}

		n := C.spoof_tcp_receiver_recv(
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
			select {
			case <-r.pktCh:
			default:
			}
			r.pktCh <- pkt
		}
	}
}

// Receive blocks until a matching TCP SYN packet arrives.
func (r *TCPReceiver) Receive() ([]byte, net.IP, uint16, error) {
	pkt, ok := <-r.pktCh
	if !ok {
		return nil, nil, 0, ErrConnectionClosed
	}
	return pkt.data, pkt.srcIP, pkt.srcPort, nil
}

// Close closes the Rust handle and stops the read goroutine.
func (r *TCPReceiver) Close() error {
	if r.closed.Swap(true) {
		return nil
	}
	close(r.doneCh)
	C.spoof_tcp_receiver_close(r.handle)
	close(r.pktCh)
	return nil
}
