package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RawTransport implements Transport using raw IP sockets with custom protocol number
type RawTransport struct {
	cfg *Config

	// Raw socket for sending spoofed packets (requires root/CAP_NET_RAW)
	rawFd  int
	rawFd6 int
	isIPv6 bool

	// Raw socket for receiving packets with our protocol number
	recvFd  int
	recvFd6 int

	// State
	closed atomic.Bool
	mu     sync.Mutex

	// Buffer pool
	bufPool sync.Pool
}

// NewRawTransport creates a new raw transport with custom IP protocol number
func NewRawTransport(cfg *Config) (*RawTransport, error) {
	if cfg.ProtocolNumber < 1 || cfg.ProtocolNumber > 255 {
		return nil, fmt.Errorf("invalid protocol number: %d (must be 1-255)", cfg.ProtocolNumber)
	}

	t := &RawTransport{
		cfg:     cfg,
		rawFd:   -1,
		rawFd6:  -1,
		recvFd:  -1,
		recvFd6: -1,
		isIPv6:  cfg.SourceIP == nil || cfg.SourceIP.To4() == nil,
		bufPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, cfg.BufferSize)
				return &buf
			},
		},
	}

	// Create raw socket for IPv4 sending with IP_HDRINCL
	if cfg.SourceIP != nil && cfg.SourceIP.To4() != nil {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			return nil, fmt.Errorf("create raw send socket: %w (need root or CAP_NET_RAW)", err)
		}

		// Enable IP_HDRINCL to include our own IP header
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("set IP_HDRINCL: %w", err)
		}

		t.rawFd = fd

		// Create raw socket for receiving with our protocol number
		recvFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, cfg.ProtocolNumber)
		if err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("create raw recv socket for protocol %d: %w", cfg.ProtocolNumber, err)
		}

		// Set receive buffer size
		if cfg.BufferSize > 0 {
			syscall.SetsockoptInt(recvFd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, cfg.BufferSize)
		}

		t.recvFd = recvFd
	}

	// Create raw socket for IPv6
	if cfg.SourceIPv6 != nil {
		fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			// IPv6 raw might not be available
			t.rawFd6 = -1
		} else {
			t.rawFd6 = fd
		}

		// Create IPv6 receive socket
		recvFd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, cfg.ProtocolNumber)
		if err != nil {
			t.recvFd6 = -1
		} else {
			if cfg.BufferSize > 0 {
				syscall.SetsockoptInt(recvFd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, cfg.BufferSize)
			}
			t.recvFd6 = recvFd
		}
	}

	// Ensure we have at least one working socket pair
	if t.rawFd < 0 && t.rawFd6 < 0 {
		return nil, errors.New("no raw socket available (need root or CAP_NET_RAW)")
	}
	if t.recvFd < 0 && t.recvFd6 < 0 {
		t.Close()
		return nil, errors.New("no receive socket available")
	}

	return t, nil
}

// Send sends a packet with spoofed source IP and custom protocol number
func (t *RawTransport) Send(payload []byte, dstIP net.IP, dstPort uint16) error {
	if t.closed.Load() {
		return ErrConnectionClosed
	}

	// Determine if IPv6
	isIPv6 := dstIP.To4() == nil

	if isIPv6 {
		return t.sendIPv6(payload, dstIP, dstPort)
	}
	return t.sendIPv4(payload, dstIP, dstPort)
}

func (t *RawTransport) sendIPv4(payload []byte, dstIP net.IP, dstPort uint16) error {
	if t.rawFd < 0 {
		return errors.New("raw socket not available")
	}

	srcIP := t.cfg.SourceIP.To4()
	dstIP4 := dstIP.To4()
	if srcIP == nil || dstIP4 == nil {
		return errors.New("invalid IPv4 addresses")
	}

	// Build raw IP packet with custom protocol number
	// The payload already contains application data
	// We prepend a minimal header with port info for compatibility
	packetPayload := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(packetPayload[0:2], t.cfg.ListenPort) // src port
	binary.BigEndian.PutUint16(packetPayload[2:4], dstPort)          // dst port
	copy(packetPayload[4:], payload)

	// Use gopacket to build the IP header
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocol(t.cfg.ProtocolNumber),
		SrcIP:    srcIP,
		DstIP:    dstIP4,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts,
		ipLayer,
		gopacket.Payload(packetPayload),
	)
	if err != nil {
		return fmt.Errorf("serialize packet: %w", err)
	}

	// Build destination sockaddr
	var destAddr syscall.SockaddrInet4
	copy(destAddr.Addr[:], dstIP4)

	// Send via raw socket
	t.mu.Lock()
	err = syscall.Sendto(t.rawFd, buf.Bytes(), 0, &destAddr)
	t.mu.Unlock()

	if err != nil {
		return fmt.Errorf("sendto: %w", err)
	}

	return nil
}

func (t *RawTransport) sendIPv6(payload []byte, dstIP net.IP, dstPort uint16) error {
	if t.rawFd6 < 0 {
		return errors.New("IPv6 raw socket not available")
	}

	srcIP := t.cfg.SourceIPv6.To16()
	dstIP16 := dstIP.To16()
	if srcIP == nil || dstIP16 == nil {
		return errors.New("invalid IPv6 addresses")
	}

	// Build packet payload with port info header
	packetPayload := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(packetPayload[0:2], t.cfg.ListenPort)
	binary.BigEndian.PutUint16(packetPayload[2:4], dstPort)
	copy(packetPayload[4:], payload)

	// Build IPv6 packet
	ipLayer := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocol(t.cfg.ProtocolNumber),
		SrcIP:      srcIP,
		DstIP:      dstIP16,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts,
		ipLayer,
		gopacket.Payload(packetPayload),
	)
	if err != nil {
		return fmt.Errorf("serialize packet: %w", err)
	}

	// Build destination sockaddr
	var destAddr syscall.SockaddrInet6
	copy(destAddr.Addr[:], dstIP16)

	t.mu.Lock()
	err = syscall.Sendto(t.rawFd6, buf.Bytes(), 0, &destAddr)
	t.mu.Unlock()

	if err != nil {
		return fmt.Errorf("sendto ipv6: %w", err)
	}

	return nil
}

// Receive receives a packet from the raw socket
func (t *RawTransport) Receive() ([]byte, net.IP, uint16, error) {
	if t.closed.Load() {
		return nil, nil, 0, ErrConnectionClosed
	}

	bufPtr := t.bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer t.bufPool.Put(bufPtr)

	var n int
	var srcIP net.IP
	var srcPort uint16
	var err error

	if t.recvFd >= 0 && !t.isIPv6 {
		n, srcIP, srcPort, err = t.recvIPv4(buf)
	} else if t.recvFd6 >= 0 {
		n, srcIP, srcPort, err = t.recvIPv6(buf)
	} else {
		return nil, nil, 0, errors.New("no receive socket available")
	}

	if err != nil {
		return nil, nil, 0, err
	}

	// Copy data to new buffer
	data := make([]byte, n)
	copy(data, buf[:n])

	return data, srcIP, srcPort, nil
}

func (t *RawTransport) recvIPv4(buf []byte) (int, net.IP, uint16, error) {
	n, from, err := syscall.Recvfrom(t.recvFd, buf, 0)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("recvfrom: %w", err)
	}

	// Parse source address
	var srcIP net.IP
	if sa, ok := from.(*syscall.SockaddrInet4); ok {
		srcIP = net.IP(sa.Addr[:])
	} else {
		return 0, nil, 0, errors.New("unexpected sockaddr type")
	}

	// Raw socket receives IP header + payload
	// Parse IP header to get to payload
	if n < 20 {
		return 0, nil, 0, errors.New("packet too short")
	}

	// IP header length is in the lower 4 bits of first byte, in 32-bit words
	ihl := int(buf[0]&0x0f) * 4
	if n < ihl+4 {
		return 0, nil, 0, errors.New("packet too short for header")
	}

	// Extract port info from our custom header (first 4 bytes after IP header)
	srcPort := binary.BigEndian.Uint16(buf[ihl : ihl+2])
	// dstPort := binary.BigEndian.Uint16(buf[ihl+2 : ihl+4])

	// Return payload after our port header
	payloadStart := ihl + 4
	payloadLen := n - payloadStart
	if payloadLen < 0 {
		return 0, nil, 0, errors.New("no payload")
	}

	// Move payload to beginning of buffer
	copy(buf, buf[payloadStart:n])

	return payloadLen, srcIP, srcPort, nil
}

func (t *RawTransport) recvIPv6(buf []byte) (int, net.IP, uint16, error) {
	n, from, err := syscall.Recvfrom(t.recvFd6, buf, 0)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("recvfrom ipv6: %w", err)
	}

	var srcIP net.IP
	if sa, ok := from.(*syscall.SockaddrInet6); ok {
		srcIP = net.IP(sa.Addr[:])
	} else {
		return 0, nil, 0, errors.New("unexpected sockaddr type")
	}

	// IPv6 raw sockets don't include the IP header in received data
	// So we directly get the payload with our port header
	if n < 4 {
		return 0, nil, 0, errors.New("packet too short")
	}

	srcPort := binary.BigEndian.Uint16(buf[0:2])
	// dstPort := binary.BigEndian.Uint16(buf[2:4])

	// Move payload to beginning
	payloadLen := n - 4
	copy(buf, buf[4:n])

	return payloadLen, srcIP, srcPort, nil
}

// Close closes the transport
func (t *RawTransport) Close() error {
	if t.closed.Swap(true) {
		return nil
	}

	var errs []error

	if t.rawFd >= 0 {
		if err := syscall.Close(t.rawFd); err != nil {
			errs = append(errs, err)
		}
	}

	if t.rawFd6 >= 0 {
		if err := syscall.Close(t.rawFd6); err != nil {
			errs = append(errs, err)
		}
	}

	if t.recvFd >= 0 {
		if err := syscall.Close(t.recvFd); err != nil {
			errs = append(errs, err)
		}
	}

	if t.recvFd6 >= 0 {
		if err := syscall.Close(t.recvFd6); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// LocalPort returns the local port (from config)
func (t *RawTransport) LocalPort() uint16 {
	return t.cfg.ListenPort
}

// SetReadBuffer sets the read buffer size
func (t *RawTransport) SetReadBuffer(size int) error {
	var err error
	if t.recvFd >= 0 {
		err = syscall.SetsockoptInt(t.recvFd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, size)
	}
	if t.recvFd6 >= 0 {
		err = syscall.SetsockoptInt(t.recvFd6, syscall.SOL_SOCKET, syscall.SO_RCVBUF, size)
	}
	return err
}

// SetWriteBuffer sets the write buffer size
func (t *RawTransport) SetWriteBuffer(size int) error {
	var err error
	if t.rawFd >= 0 {
		err = syscall.SetsockoptInt(t.rawFd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, size)
	}
	if t.rawFd6 >= 0 {
		err = syscall.SetsockoptInt(t.rawFd6, syscall.SOL_SOCKET, syscall.SO_SNDBUF, size)
	}
	return err
}
