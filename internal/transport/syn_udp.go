package transport

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// SynUDPTransport implements an asymmetric Transport:
//   - Client mode: Send() = raw TCP SYN (spoofed), Receive() = plain UDP listen
//   - Server mode: Send() = raw UDP (spoofed), Receive() = raw TCP socket (filter SYN)
//
// This is designed for DPI evasion: uplink looks like TCP SYN flood,
// downlink looks like normal UDP traffic.
type SynUDPTransport struct {
	cfg    *Config
	isServ bool // true = server mode

	// --- Client mode ---
	// Send: raw TCP SYN via IPPROTO_RAW
	synFd int
	seq   uint32
	synMu sync.Mutex

	// Receive: standard UDP listener
	udpRecvConn *net.UDPConn

	// --- Server mode ---
	// Receive: raw TCP socket to capture SYN packets
	tcpRecvFd int

	// Send: raw UDP with spoofed source (reuses gopacket)
	udpSendFd int

	// --- Common ---
	closed  atomic.Bool
	bufPool sync.Pool
}

// NewSynUDPTransport creates a new asymmetric SYN+UDP transport.
// If listenPort == 0 and peerSpoofIP is not set → client mode.
// If listenPort > 0 → server mode.
func NewSynUDPTransport(cfg *Config) (*SynUDPTransport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	isServer := cfg.ListenPort > 0

	t := &SynUDPTransport{
		cfg:       cfg,
		isServ:    isServer,
		synFd:     -1,
		tcpRecvFd: -1,
		udpSendFd: -1,
		seq:       1,
		bufPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, cfg.BufferSize)
				return &buf
			},
		},
	}

	if isServer {
		if err := t.initServer(); err != nil {
			t.Close()
			return nil, err
		}
	} else {
		if err := t.initClient(); err != nil {
			t.Close()
			return nil, err
		}
	}

	return t, nil
}

// ── Client init ──

func (t *SynUDPTransport) initClient() error {
	// Raw socket for sending TCP SYN packets
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("create raw socket for SYN: %w (need root/CAP_NET_RAW)", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("set IP_HDRINCL: %w", err)
	}
	t.synFd = fd

	// UDP listener for receiving server responses
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("0.0.0.0:%d", t.cfg.ListenPort))
	if err != nil {
		return fmt.Errorf("resolve UDP addr: %w", err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	t.udpRecvConn = conn

	if t.cfg.BufferSize > 0 {
		conn.SetReadBuffer(t.cfg.BufferSize)
		conn.SetWriteBuffer(t.cfg.BufferSize)
	}

	return nil
}

// ── Server init ──

func (t *SynUDPTransport) initServer() error {
	// Raw TCP socket for receiving SYN packets
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("create raw TCP recv socket: %w (need root/CAP_NET_RAW)", err)
	}
	t.tcpRecvFd = fd

	// Raw socket for sending UDP responses with spoofed source IP
	udpFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		syscall.Close(fd)
		return fmt.Errorf("create raw UDP send socket: %w", err)
	}
	if err := syscall.SetsockoptInt(udpFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		syscall.Close(udpFd)
		return fmt.Errorf("set IP_HDRINCL on UDP send: %w", err)
	}
	t.udpSendFd = udpFd

	return nil
}

// ── Send ──

func (t *SynUDPTransport) Send(payload []byte, dstIP net.IP, dstPort uint16) error {
	if t.closed.Load() {
		return ErrConnectionClosed
	}
	if t.isServ {
		return t.sendUDP(payload, dstIP, dstPort)
	}
	return t.sendSyn(payload, dstIP, dstPort)
}

// sendSyn builds and sends a raw TCP SYN packet with payload.
func (t *SynUDPTransport) sendSyn(payload []byte, dstIP net.IP, dstPort uint16) error {
	srcIP := t.cfg.SourceIP.To4()
	dst4 := dstIP.To4()
	if srcIP == nil || dst4 == nil {
		return errors.New("SYN transport only supports IPv4")
	}

	const ipHL = 20
	const tcpHL = 32 // 20 base + 12 timestamp option

	// Build TCP segment
	tcpSeg := make([]byte, tcpHL+len(payload))

	t.synMu.Lock()
	seq := t.seq
	t.seq += uint32(len(payload))
	t.synMu.Unlock()

	srcPort := t.LocalPort()

	// TCP header
	binary.BigEndian.PutUint16(tcpSeg[0:2], srcPort)   // Src port
	binary.BigEndian.PutUint16(tcpSeg[2:4], dstPort)    // Dst port
	binary.BigEndian.PutUint32(tcpSeg[4:8], seq)        // Sequence
	binary.BigEndian.PutUint32(tcpSeg[8:12], 0)         // Ack = 0 (SYN)
	tcpSeg[12] = byte(tcpHL/4) << 4                     // Data offset
	tcpSeg[13] = 0x02                                   // Flags: SYN only
	binary.BigEndian.PutUint16(tcpSeg[14:16], 65535)    // Window

	// TCP timestamp option: NOP+NOP+Timestamps
	tcpSeg[20] = 0x01
	tcpSeg[21] = 0x01
	tcpSeg[22] = 0x08
	tcpSeg[23] = 0x0A
	binary.BigEndian.PutUint32(tcpSeg[24:28], seq)
	binary.BigEndian.PutUint32(tcpSeg[28:32], 0)

	// Payload
	copy(tcpSeg[tcpHL:], payload)

	// TCP checksum
	csum := tcpChecksum(srcIP, dst4, tcpSeg)
	binary.BigEndian.PutUint16(tcpSeg[16:18], csum)

	// Check if we need IP fragmentation
	mtu := t.cfg.MTU
	if mtu <= 0 || mtu > 1500 {
		mtu = 1500
	}
	fullSize := ipHL + len(tcpSeg)

	var dest syscall.SockaddrInet4
	copy(dest.Addr[:], dst4)

	if fullSize <= mtu {
		// Fits in one packet
		pkt := buildIPPacket(srcIP, dst4, 0, 0, false, syscall.IPPROTO_TCP, tcpSeg)
		return t.sendRaw(t.synFd, pkt, &dest)
	}

	// Need IP fragmentation
	return t.sendFragmented(srcIP, dst4, tcpSeg, mtu, syscall.IPPROTO_TCP, t.synFd, &dest)
}

// sendUDP builds and sends a raw UDP packet with spoofed source IP.
func (t *SynUDPTransport) sendUDP(payload []byte, dstIP net.IP, dstPort uint16) error {
	srcIP := t.cfg.SourceIP.To4()
	dst4 := dstIP.To4()
	if srcIP == nil || dst4 == nil {
		return errors.New("UDP send only supports IPv4")
	}

	srcPort := t.LocalPort()

	// Use gopacket for UDP
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP,
		DstIP:    dst4,
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, ipLayer, udpLayer, gopacket.Payload(payload)); err != nil {
		return fmt.Errorf("serialize UDP: %w", err)
	}

	var dest syscall.SockaddrInet4
	copy(dest.Addr[:], dst4)

	t.synMu.Lock()
	err := syscall.Sendto(t.udpSendFd, buf.Bytes(), 0, &dest)
	t.synMu.Unlock()
	return err
}

// ── Receive ──

func (t *SynUDPTransport) Receive() ([]byte, net.IP, uint16, error) {
	if t.closed.Load() {
		return nil, nil, 0, ErrConnectionClosed
	}
	if t.isServ {
		return t.receiveSyn()
	}
	return t.receiveUDP()
}

// receiveUDP reads from the standard UDP socket (client mode).
func (t *SynUDPTransport) receiveUDP() ([]byte, net.IP, uint16, error) {
	bufPtr := t.bufPool.Get().(*[]byte)
	buf := *bufPtr

	n, addr, err := t.udpRecvConn.ReadFromUDP(buf)
	if err != nil {
		t.bufPool.Put(bufPtr)
		return nil, nil, 0, err
	}

	data := make([]byte, n)
	copy(data, buf[:n])
	t.bufPool.Put(bufPtr)

	return data, addr.IP, uint16(addr.Port), nil
}

// receiveSyn reads raw TCP packets and extracts payload from SYN packets.
func (t *SynUDPTransport) receiveSyn() ([]byte, net.IP, uint16, error) {
	buf := make([]byte, 65536)

	for {
		n, _, err := syscall.Recvfrom(t.tcpRecvFd, buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return nil, nil, 0, fmt.Errorf("recvfrom tcp: %w", err)
		}
		if n < 40 { // min IP(20) + TCP(20)
			continue
		}

		// Parse IP header
		ihl := int(buf[0]&0x0F) * 4
		if ihl < 20 || n < ihl+20 {
			continue
		}
		proto := buf[9]
		if proto != syscall.IPPROTO_TCP {
			continue
		}

		srcIP := net.IP(make([]byte, 4))
		copy(srcIP, buf[12:16])

		// Filter by peer spoof IP
		if t.cfg.PeerSpoofIP != nil && !srcIP.Equal(t.cfg.PeerSpoofIP) {
			continue
		}

		// Parse TCP header
		tcp := buf[ihl:]
		srcPort := binary.BigEndian.Uint16(tcp[0:2])
		dstPort := binary.BigEndian.Uint16(tcp[2:4])

		// Filter by our listen port
		if dstPort != t.cfg.ListenPort {
			continue
		}

		// Check SYN flag (0x02)
		flags := tcp[13]
		if flags&0x02 == 0 {
			continue // Not a SYN packet
		}

		// Extract data offset
		dataOffset := int(tcp[12]>>4) * 4
		if dataOffset < 20 {
			continue
		}

		// Extract payload
		totalTCPLen := n - ihl
		if dataOffset >= totalTCPLen {
			continue // No payload (bare SYN, ignore)
		}

		payload := make([]byte, totalTCPLen-dataOffset)
		copy(payload, tcp[dataOffset:totalTCPLen])

		if len(payload) == 0 {
			continue
		}

		return payload, srcIP, srcPort, nil
	}
}

// ── Helpers ──

func buildIPPacket(srcIP, dstIP net.IP, ipID uint16, fragOffset uint16, moreFragments bool, proto byte, data []byte) []byte {
	const ipHL = 20
	pkt := make([]byte, ipHL+len(data))
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(ipHL+len(data)))
	binary.BigEndian.PutUint16(pkt[4:6], ipID)

	flagsOffset := fragOffset / 8
	if moreFragments {
		flagsOffset |= 0x2000
	}
	binary.BigEndian.PutUint16(pkt[6:8], flagsOffset)

	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], srcIP)
	copy(pkt[16:20], dstIP)
	copy(pkt[ipHL:], data)
	return pkt
}

func tcpChecksum(srcIP, dstIP net.IP, tcpSegment []byte) uint16 {
	tcpLen := len(tcpSegment)
	pseudo := make([]byte, 12+tcpLen)
	copy(pseudo[0:4], srcIP)
	copy(pseudo[4:8], dstIP)
	pseudo[8] = 0
	pseudo[9] = syscall.IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))
	copy(pseudo[12:], tcpSegment)
	return checksumRFC1071(pseudo)
}

func checksumRFC1071(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (t *SynUDPTransport) sendRaw(fd int, pkt []byte, dest *syscall.SockaddrInet4) error {
	for {
		err := syscall.Sendto(fd, pkt, 0, dest)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			log.Printf("[SynUDP] sendto ERROR: %v (%d bytes)", err, len(pkt))
		}
		return err
	}
}

func (t *SynUDPTransport) sendFragmented(srcIP, dstIP net.IP, segment []byte, mtu int, proto byte, fd int, dest *syscall.SockaddrInet4) error {
	const ipHL = 20
	maxData := ((mtu - ipHL) / 8) * 8

	var idBuf [2]byte
	rand.Read(idBuf[:])
	ipID := binary.BigEndian.Uint16(idBuf[:])

	offset := 0
	for offset < len(segment) {
		end := offset + maxData
		moreFrags := true
		if end >= len(segment) {
			end = len(segment)
			moreFrags = false
		}
		pkt := buildIPPacket(srcIP, dstIP, ipID, uint16(offset), moreFrags, proto, segment[offset:end])
		if err := t.sendRaw(fd, pkt, dest); err != nil {
			return fmt.Errorf("fragment offset=%d: %w", offset, err)
		}
		offset = end
	}
	return nil
}

// ── Interface methods ──

func (t *SynUDPTransport) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	if t.synFd >= 0 {
		syscall.Close(t.synFd)
	}
	if t.tcpRecvFd >= 0 {
		syscall.Close(t.tcpRecvFd)
	}
	if t.udpSendFd >= 0 {
		syscall.Close(t.udpSendFd)
	}
	if t.udpRecvConn != nil {
		t.udpRecvConn.Close()
	}
	return nil
}

func (t *SynUDPTransport) LocalPort() uint16 {
	if t.udpRecvConn != nil {
		return uint16(t.udpRecvConn.LocalAddr().(*net.UDPAddr).Port)
	}
	return t.cfg.ListenPort
}

func (t *SynUDPTransport) SetReadBuffer(size int) error {
	if t.udpRecvConn != nil {
		return t.udpRecvConn.SetReadBuffer(size)
	}
	return nil
}

func (t *SynUDPTransport) SetWriteBuffer(size int) error {
	if t.udpRecvConn != nil {
		return t.udpRecvConn.SetWriteBuffer(size)
	}
	return nil
}
