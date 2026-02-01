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

// UDPTransport implements Transport using raw UDP sockets with IP spoofing
type UDPTransport struct {
	cfg *Config

	// Raw socket for sending spoofed packets (requires root/CAP_NET_RAW)
	rawFd   int
	rawFd6  int
	isIPv6  bool

	// Regular UDP socket for receiving
	recvConn *net.UDPConn

	// State
	closed atomic.Bool
	mu     sync.Mutex

	// Buffer pool
	bufPool sync.Pool
}

// NewUDPTransport creates a new UDP transport with IP spoofing capability
func NewUDPTransport(cfg *Config) (*UDPTransport, error) {
	t := &UDPTransport{
		cfg:    cfg,
		rawFd:  -1,
		rawFd6: -1,
		isIPv6: cfg.SourceIP == nil || cfg.SourceIP.To4() == nil,
		bufPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, cfg.BufferSize)
				return &buf
			},
		},
	}

	// Create raw socket for IPv4 with IP_HDRINCL
	if cfg.SourceIP != nil && cfg.SourceIP.To4() != nil {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			return nil, fmt.Errorf("create raw socket: %w (need root or CAP_NET_RAW)", err)
		}

		// Enable IP_HDRINCL to include our own IP header
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("set IP_HDRINCL: %w", err)
		}

		t.rawFd = fd
	}

	// Create raw socket for IPv6
	if cfg.SourceIPv6 != nil {
		fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			// IPv6 raw might not be available, that's ok
			t.rawFd6 = -1
		} else {
			t.rawFd6 = fd
		}
	}

	// Create UDP listener for receiving
	var listenAddr string
	if t.isIPv6 {
		listenAddr = fmt.Sprintf("[::]:%d", cfg.ListenPort)
	} else {
		listenAddr = fmt.Sprintf("0.0.0.0:%d", cfg.ListenPort)
	}

	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("resolve listen addr: %w", err)
	}

	recvConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	t.recvConn = recvConn

	// Set buffer sizes
	if cfg.BufferSize > 0 {
		recvConn.SetReadBuffer(cfg.BufferSize)
		recvConn.SetWriteBuffer(cfg.BufferSize)
	}

	return t, nil
}

// Send sends a packet with spoofed source IP
func (t *UDPTransport) Send(payload []byte, dstIP net.IP, dstPort uint16) error {
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

func (t *UDPTransport) sendIPv4(payload []byte, dstIP net.IP, dstPort uint16) error {
	if t.rawFd < 0 {
		return errors.New("raw socket not available")
	}

	srcIP := t.cfg.SourceIP.To4()
	dstIP4 := dstIP.To4()
	if srcIP == nil || dstIP4 == nil {
		return errors.New("invalid IPv4 addresses")
	}

	// Use gopacket to build the packet
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP,
		DstIP:    dstIP4,
	}

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(t.LocalPort()),
		DstPort: layers.UDPPort(dstPort),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts,
		ipLayer,
		udpLayer,
		gopacket.Payload(payload),
	)
	if err != nil {
		return fmt.Errorf("serialize packet: %w", err)
	}

	// Build destination sockaddr
	var destAddr syscall.SockaddrInet4
	copy(destAddr.Addr[:], dstIP4)
	destAddr.Port = int(dstPort)

	// Send via raw socket
	t.mu.Lock()
	err = syscall.Sendto(t.rawFd, buf.Bytes(), 0, &destAddr)
	t.mu.Unlock()

	if err != nil {
		return fmt.Errorf("sendto: %w", err)
	}

	return nil
}

func (t *UDPTransport) sendIPv6(payload []byte, dstIP net.IP, dstPort uint16) error {
	if t.rawFd6 < 0 {
		return errors.New("IPv6 raw socket not available")
	}

	srcIP := t.cfg.SourceIPv6.To16()
	dstIP16 := dstIP.To16()
	if srcIP == nil || dstIP16 == nil {
		return errors.New("invalid IPv6 addresses")
	}

	// Build IPv6 + UDP packet
	ipLayer := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolUDP,
		SrcIP:      srcIP,
		DstIP:      dstIP16,
	}

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(t.LocalPort()),
		DstPort: layers.UDPPort(dstPort),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts,
		ipLayer,
		udpLayer,
		gopacket.Payload(payload),
	)
	if err != nil {
		return fmt.Errorf("serialize packet: %w", err)
	}

	// Build destination sockaddr
	var destAddr syscall.SockaddrInet6
	copy(destAddr.Addr[:], dstIP16)
	destAddr.Port = int(dstPort)

	t.mu.Lock()
	err = syscall.Sendto(t.rawFd6, buf.Bytes(), 0, &destAddr)
	t.mu.Unlock()

	if err != nil {
		return fmt.Errorf("sendto ipv6: %w", err)
	}

	return nil
}

// Receive receives a packet from the UDP socket
func (t *UDPTransport) Receive() ([]byte, net.IP, uint16, error) {
	if t.closed.Load() {
		return nil, nil, 0, ErrConnectionClosed
	}

	bufPtr := t.bufPool.Get().(*[]byte)
	buf := *bufPtr

	n, addr, err := t.recvConn.ReadFromUDP(buf)
	if err != nil {
		t.bufPool.Put(bufPtr)
		return nil, nil, 0, err
	}

	// Copy data to new buffer before returning to pool
	data := make([]byte, n)
	copy(data, buf[:n])
	t.bufPool.Put(bufPtr)

	return data, addr.IP, uint16(addr.Port), nil
}

// Close closes the transport
func (t *UDPTransport) Close() error {
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

	if t.recvConn != nil {
		if err := t.recvConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// LocalPort returns the local port
func (t *UDPTransport) LocalPort() uint16 {
	if t.recvConn != nil {
		return uint16(t.recvConn.LocalAddr().(*net.UDPAddr).Port)
	}
	return t.cfg.ListenPort
}

// SetReadBuffer sets the read buffer size
func (t *UDPTransport) SetReadBuffer(size int) error {
	if t.recvConn != nil {
		return t.recvConn.SetReadBuffer(size)
	}
	return nil
}

// SetWriteBuffer sets the write buffer size
func (t *UDPTransport) SetWriteBuffer(size int) error {
	if t.recvConn != nil {
		return t.recvConn.SetWriteBuffer(size)
	}
	return nil
}

// Helper to calculate IP checksum
func ipChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	if len(header)%2 == 1 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
