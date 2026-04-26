package transport

import (
	"net"
	"sync/atomic"
	"time"
)

// UDPReceiver listens for incoming UDP packets.
type UDPReceiver struct {
	cfg     ReceiverConfig
	udpConn *net.UDPConn
	closed  atomic.Bool

	pktCh  chan receivedPacket
	doneCh chan struct{}
}

// NewUDPReceiver creates a standard UDP receiver.
func NewUDPReceiver(cfg ReceiverConfig) (*UDPReceiver, error) {
	addr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: int(cfg.ListenPort),
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, &rawSocketError{msg: "listen UDP", err: err}
	}

	if cfg.BufferSize > 0 {
		conn.SetReadBuffer(cfg.BufferSize)
	}

	r := &UDPReceiver{
		cfg:     cfg,
		udpConn: conn,
		pktCh:   make(chan receivedPacket, 4096),
		doneCh:  make(chan struct{}),
	}
	go r.readLoop()
	return r, nil
}

// readLoop reads individual UDP datagrams.
func (r *UDPReceiver) readLoop() {
	buf := make([]byte, 65536)
	r.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))

	for {
		n, addr, err := r.udpConn.ReadFromUDP(buf)
		if err != nil {
			if r.closed.Load() {
				return
			}
			select {
			case <-r.doneCh:
				return
			default:
			}
			r.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			continue
		}
		r.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))

		// Filter by expected source IP
		if r.cfg.PeerSpoofIP != nil && !addr.IP.Equal(r.cfg.PeerSpoofIP) {
			continue
		}

		if n == 0 {
			continue
		}

		srcIP := addr.IP
		srcPort := uint16(addr.Port)

		data := make([]byte, n)
		copy(data, buf[:n])

		pkt := receivedPacket{data: data, srcIP: srcIP, srcPort: srcPort}
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

// Receive blocks until a packet is ready.
func (r *UDPReceiver) Receive() ([]byte, net.IP, uint16, error) {
	pkt, ok := <-r.pktCh
	if !ok {
		return nil, nil, 0, ErrConnectionClosed
	}
	return pkt.data, pkt.srcIP, pkt.srcPort, nil
}

// Close shuts down the receiver.
func (r *UDPReceiver) Close() error {
	if r.closed.Swap(true) {
		return nil
	}
	close(r.doneCh)
	err := r.udpConn.Close()
	close(r.pktCh)
	return err
}
