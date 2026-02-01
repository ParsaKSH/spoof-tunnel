package transport

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ICMPMode determines how ICMP packets are sent/received
type ICMPMode int

const (
	// ICMPModeEcho uses ICMP Echo Request (type 8) for sending
	ICMPModeEcho ICMPMode = iota
	// ICMPModeReply uses ICMP Echo Reply (type 0) for sending
	ICMPModeReply
)

// ICMPTransport implements Transport using raw ICMP sockets with IP spoofing
type ICMPTransport struct {
	cfg  *Config
	mode ICMPMode

	// Raw socket for sending spoofed packets
	rawFd  int
	rawFd6 int
	isIPv6 bool

	// ICMP listener for receiving
	icmpConn4 *icmp.PacketConn
	icmpConn6 *icmp.PacketConn

	// Underlying net.PacketConn for setting socket options
	rawConn4 net.PacketConn
	rawConn6 net.PacketConn

	// ICMP ID and sequence
	icmpID  uint16
	icmpSeq atomic.Uint32

	// State
	closed atomic.Bool
	mu     sync.Mutex

	// Buffer pool
	bufPool sync.Pool
}

// NewICMPTransport creates a new ICMP transport with IP spoofing
func NewICMPTransport(cfg *Config, mode ICMPMode) (*ICMPTransport, error) {
	t := &ICMPTransport{
		cfg:    cfg,
		mode:   mode,
		rawFd:  -1,
		rawFd6: -1,
		icmpID: 0x5350, // Fixed ID = "SP" (SPooftunnel) - same for both client and server
		isIPv6: cfg.SourceIP == nil || cfg.SourceIP.To4() == nil,
		bufPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, cfg.BufferSize)
				return &buf
			},
		},
	}

	// Create raw socket for IPv4 with IP_HDRINCL (for full control including IP header)
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
			t.rawFd6 = -1
		} else {
			t.rawFd6 = fd
		}
	}

	// Create ICMP listener for receiving
	if !t.isIPv6 {
		conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("listen icmp4: %w", err)
		}
		t.icmpConn4 = conn

		// Try to set large socket buffers using SyscallConn
		if sc, ok := interface{}(conn).(interface {
			SyscallConn() (syscall.RawConn, error)
		}); ok {
			if rawConn, err := sc.SyscallConn(); err == nil {
				rawConn.Control(func(fd uintptr) {
					// Set 8MB receive buffer
					syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 8*1024*1024)
					// Set 8MB send buffer
					syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 8*1024*1024)
				})
			}
		}
	}

	if t.isIPv6 || cfg.SourceIPv6 != nil {
		conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
		if err != nil {
			// IPv6 might not be available
			t.icmpConn6 = nil
		} else {
			t.icmpConn6 = conn

			// Try to set large socket buffers using SyscallConn
			if sc, ok := interface{}(conn).(interface {
				SyscallConn() (syscall.RawConn, error)
			}); ok {
				if rawConn, err := sc.SyscallConn(); err == nil {
					rawConn.Control(func(fd uintptr) {
						syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 8*1024*1024)
						syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 8*1024*1024)
					})
				}
			}
		}
	}

	return t, nil
}

// Send sends a packet with spoofed source IP via ICMP
func (t *ICMPTransport) Send(payload []byte, dstIP net.IP, dstPort uint16) error {
	if t.closed.Load() {
		return ErrConnectionClosed
	}

	// dstPort is ignored for ICMP, but we use it as part of sequence
	_ = dstPort

	isIPv6 := dstIP.To4() == nil

	if isIPv6 {
		return t.sendIPv6(payload, dstIP)
	}
	return t.sendIPv4(payload, dstIP)
}

func (t *ICMPTransport) sendIPv4(payload []byte, dstIP net.IP) error {
	if t.rawFd < 0 {
		return errors.New("raw socket not available")
	}

	srcIP := t.cfg.SourceIP.To4()
	dstIP4 := dstIP.To4()
	if srcIP == nil || dstIP4 == nil {
		return errors.New("invalid IPv4 addresses")
	}

	// Use Echo Request for sending - these pass through networks better
	// NOTE: On server, disable kernel auto-response with:
	//   echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
	icmpType := layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)

	seq := uint16(t.icmpSeq.Add(1) & 0xFFFF)

	// Build IP + ICMP packet using gopacket
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    srcIP,
		DstIP:    dstIP4,
	}

	icmpLayer := &layers.ICMPv4{
		TypeCode: icmpType,
		Id:       t.icmpID,
		Seq:      seq,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts,
		ipLayer,
		icmpLayer,
		gopacket.Payload(payload),
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

func (t *ICMPTransport) sendIPv6(payload []byte, dstIP net.IP) error {
	if t.rawFd6 < 0 {
		return errors.New("IPv6 raw socket not available")
	}

	srcIP := t.cfg.SourceIPv6.To16()
	dstIP16 := dstIP.To16()
	if srcIP == nil || dstIP16 == nil {
		return errors.New("invalid IPv6 addresses")
	}

	// Use Echo Request for sending
	icmpType := layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)

	seq := uint16(t.icmpSeq.Add(1) & 0xFFFF)

	ipLayer := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      srcIP,
		DstIP:      dstIP16,
	}

	icmpLayer := &layers.ICMPv6{
		TypeCode: icmpType,
	}
	icmpLayer.SetNetworkLayerForChecksum(ipLayer)

	// ICMPv6 Echo has ID and Seq in the payload area
	echoData := make([]byte, 4+len(payload))
	echoData[0] = byte(t.icmpID >> 8)
	echoData[1] = byte(t.icmpID)
	echoData[2] = byte(seq >> 8)
	echoData[3] = byte(seq)
	copy(echoData[4:], payload)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts,
		ipLayer,
		icmpLayer,
		gopacket.Payload(echoData),
	)
	if err != nil {
		return fmt.Errorf("serialize packet: %w", err)
	}

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

// Receive receives an ICMP packet
func (t *ICMPTransport) Receive() ([]byte, net.IP, uint16, error) {
	if t.closed.Load() {
		return nil, nil, 0, ErrConnectionClosed
	}

	if t.isIPv6 && t.icmpConn6 != nil {
		return t.receiveIPv6()
	}
	return t.receiveIPv4()
}

func (t *ICMPTransport) receiveIPv4() ([]byte, net.IP, uint16, error) {
	if t.icmpConn4 == nil {
		return nil, nil, 0, errors.New("icmp4 listener not available")
	}

	bufPtr := t.bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer t.bufPool.Put(bufPtr)

	// Debug counters
	var totalPkts, wrongType, wrongID, parsed uint64

	for {
		n, cm, src, err := t.icmpConn4.IPv4PacketConn().ReadFrom(buf)
		if err != nil {
			return nil, nil, 0, err
		}
		totalPkts++

		// Get source IP
		var srcIP net.IP
		if cm != nil {
			srcIP = cm.Src
		} else if src != nil {
			srcIP = src.(*net.IPAddr).IP
		}

		// Parse ICMP message
		msg, err := icmp.ParseMessage(1, buf[:n]) // 1 = ICMPv4
		if err != nil {
			continue
		}
		parsed++

		// DEBUG: Log all ICMP types we receive
		if totalPkts%1000 == 1 {
			fmt.Printf("[ICMP-RX] total=%d parsed=%d wrongType=%d wrongID=%d, this: type=%v from %v\n",
				totalPkts, parsed, wrongType, wrongID, msg.Type, srcIP)
		}

		// Both sides send Echo Request, so we listen for Echo Request
		// NOTE: Kernel must NOT auto-respond: echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
		if msg.Type != ipv4.ICMPTypeEcho {
			wrongType++
			// Log first few wrong types for debugging
			if wrongType <= 10 {
				fmt.Printf("[ICMP-RX] WRONG TYPE: got %v from %v (expected Echo), wrongType count=%d\n", msg.Type, srcIP, wrongType)
			}
			continue
		}

		// Extract echo body
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		// Verify ICMP ID
		if echo.ID != int(t.icmpID) {
			wrongID++
			if wrongID <= 10 {
				fmt.Printf("[ICMP-RX] WRONG ID: got %d, expected %d, from %v\n", echo.ID, t.icmpID, srcIP)
			}
			continue
		}

		// Copy data
		data := make([]byte, len(echo.Data))
		copy(data, echo.Data)

		return data, srcIP, uint16(echo.Seq), nil
	}
}

func (t *ICMPTransport) receiveIPv6() ([]byte, net.IP, uint16, error) {
	if t.icmpConn6 == nil {
		return nil, nil, 0, errors.New("icmp6 listener not available")
	}

	bufPtr := t.bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer t.bufPool.Put(bufPtr)

	for {
		n, cm, src, err := t.icmpConn6.IPv6PacketConn().ReadFrom(buf)
		if err != nil {
			return nil, nil, 0, err
		}

		// Parse ICMPv6 message
		msg, err := icmp.ParseMessage(58, buf[:n]) // 58 = ICMPv6
		if err != nil {
			continue
		}

		// Both sides send Echo Request, so we listen for Echo Request
		if msg.Type != ipv6.ICMPTypeEchoRequest {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		if echo.ID != int(t.icmpID) {
			continue
		}

		var srcIP net.IP
		if cm != nil {
			srcIP = cm.Src
		} else if src != nil {
			srcIP = src.(*net.IPAddr).IP
		}

		data := make([]byte, len(echo.Data))
		copy(data, echo.Data)

		return data, srcIP, uint16(echo.Seq), nil
	}
}

// Close closes the transport
func (t *ICMPTransport) Close() error {
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

	if t.icmpConn4 != nil {
		if err := t.icmpConn4.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if t.icmpConn6 != nil {
		if err := t.icmpConn6.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// LocalPort returns the ICMP ID as a pseudo-port
func (t *ICMPTransport) LocalPort() uint16 {
	return t.icmpID
}

// SetReadBuffer sets the read buffer size
func (t *ICMPTransport) SetReadBuffer(size int) error {
	if t.icmpConn4 != nil {
		// icmp.PacketConn wraps net.PacketConn which supports SetReadBuffer
		if conn, ok := interface{}(t.icmpConn4).(interface{ SetReadBuffer(int) error }); ok {
			return conn.SetReadBuffer(size)
		}
	}
	if t.icmpConn6 != nil {
		if conn, ok := interface{}(t.icmpConn6).(interface{ SetReadBuffer(int) error }); ok {
			return conn.SetReadBuffer(size)
		}
	}
	return nil
}

// SetWriteBuffer sets the write buffer size
func (t *ICMPTransport) SetWriteBuffer(size int) error {
	if t.icmpConn4 != nil {
		if conn, ok := interface{}(t.icmpConn4).(interface{ SetWriteBuffer(int) error }); ok {
			return conn.SetWriteBuffer(size)
		}
	}
	if t.icmpConn6 != nil {
		if conn, ok := interface{}(t.icmpConn6).(interface{ SetWriteBuffer(int) error }); ok {
			return conn.SetWriteBuffer(size)
		}
	}
	return nil
}
