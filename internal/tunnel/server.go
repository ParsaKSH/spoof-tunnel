package tunnel

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ParsaKSH/spooftunnel/internal/config"
	"github.com/ParsaKSH/spooftunnel/internal/crypto"
	"github.com/ParsaKSH/spooftunnel/internal/fec"
	"github.com/ParsaKSH/spooftunnel/internal/protocol"
	"github.com/ParsaKSH/spooftunnel/internal/transport"
)

// Server is the tunnel server
type Server struct {
	config *config.Config
	cipher *crypto.Cipher
	trans  transport.Transport

	// Expected spoof source IP from client (for packet filtering)
	expectedSpoofIP net.IP

	// Real client IP (where to send packets)
	clientRealIP net.IP

	// Session management
	sessions   map[uint32]*ServerSession
	sessionsMu sync.RWMutex

	// FEC
	fecEncoder *fec.Encoder
	fecDecoder *fec.Decoder
	fecMu      sync.Mutex

	// State
	running atomic.Bool
	stopCh  chan struct{}

	// Buffer pool
	bufPool sync.Pool

	// Rate limiter for send pacing (packets per second)
	sendInterval time.Duration // Minimum interval between packets
	lastSendMu   sync.Mutex
	lastSendTime time.Time

	// Stats
	bytesSent     atomic.Uint64
	bytesReceived atomic.Uint64
}

// ServerSession represents a tunnel session on server side
type ServerSession struct {
	ID         uint32
	ClientAddr net.IP
	ClientPort uint16
	Target     string
	TargetConn net.Conn
	Created    time.Time
	LastActive time.Time

	// Reliable delivery - download (server to client)
	sendBuffer *SendBuffer // For tracking sent packets and retransmission

	// Reliable delivery - upload (client to server)
	recvBuffer  *RecvBuffer // For tracking received uploads and generating ACKs
	lastAckTime time.Time   // When we last sent ACK for uploads

	// State
	closed atomic.Bool
	mu     sync.Mutex
}

// NewServer creates a new tunnel server
func NewServer(cfg *config.Config, cipher *crypto.Cipher) (*Server, error) {
	// Create transport
	transportCfg := &transport.Config{
		SourceIP:       net.ParseIP(cfg.Spoof.SourceIP),
		SourceIPv6:     net.ParseIP(cfg.Spoof.SourceIPv6),
		ListenPort:     uint16(cfg.Listen.Port),
		PeerSpoofIP:    net.ParseIP(cfg.Spoof.PeerSpoofIP),
		PeerSpoofIPv6:  net.ParseIP(cfg.Spoof.PeerSpoofIPv6),
		BufferSize:     cfg.Performance.BufferSize,
		MTU:            cfg.Performance.MTU,
		ProtocolNumber: cfg.Transport.ProtocolNumber,
	}

	var trans transport.Transport
	var err error

	switch cfg.Transport.Type {
	case config.TransportICMP:
		var mode transport.ICMPMode
		if cfg.Transport.ICMPMode == config.ICMPModeEcho {
			mode = transport.ICMPModeEcho
		} else {
			mode = transport.ICMPModeReply
		}
		trans, err = transport.NewICMPTransport(transportCfg, mode)
	case config.TransportRAW:
		trans, err = transport.NewRawTransport(transportCfg)
	default:
		trans, err = transport.NewUDPTransport(transportCfg)
	}

	if err != nil {
		return nil, fmt.Errorf("create transport: %w", err)
	}

	// Calculate send interval for rate limiting
	// Default: 1ms per packet = 1000 packets/sec = ~1.3MB/s at 1300 bytes/packet
	sendInterval := time.Millisecond
	if cfg.Performance.SendRateLimit > 0 {
		sendInterval = time.Second / time.Duration(cfg.Performance.SendRateLimit)
	}

	s := &Server{
		config:          cfg,
		cipher:          cipher,
		trans:           trans,
		expectedSpoofIP: net.ParseIP(cfg.Spoof.PeerSpoofIP),
		clientRealIP:    net.ParseIP(cfg.Spoof.ClientRealIP),
		sessions:        make(map[uint32]*ServerSession),
		stopCh:          make(chan struct{}),
		sendInterval:    sendInterval,
		bufPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, cfg.Performance.BufferSize)
				return &buf
			},
		},
	}

	// Initialize FEC if enabled
	if cfg.FEC.Enabled {
		enc, err := fec.NewEncoder(cfg.FEC.DataShards, cfg.FEC.ParityShards)
		if err != nil {
			return nil, fmt.Errorf("create FEC encoder: %w", err)
		}
		s.fecEncoder = enc

		dec, err := fec.NewDecoder(cfg.FEC.DataShards, cfg.FEC.ParityShards)
		if err != nil {
			return nil, fmt.Errorf("create FEC decoder: %w", err)
		}
		s.fecDecoder = dec
	}

	return s, nil
}

// Start starts the server
func (s *Server) Start() error {
	s.running.Store(true)

	log.Printf("Server listening on port %d", s.config.Listen.Port)
	log.Printf("Transport: %s", s.config.Transport.Type)
	log.Printf("Client real IP (destination): %s", s.clientRealIP)
	if s.expectedSpoofIP != nil {
		log.Printf("Expected client spoof IP (source): %s", s.expectedSpoofIP)
	}
	log.Printf("Spoof source IP (our outgoing): %s", s.config.Spoof.SourceIP)

	// Start session cleanup
	go s.cleanupLoop()

	// Main receive loop
	return s.receiveLoop()
}

// Stop stops the server
func (s *Server) Stop() error {
	if !s.running.Swap(false) {
		return nil
	}

	close(s.stopCh)

	// Close all sessions
	s.sessionsMu.Lock()
	for id, sess := range s.sessions {
		sess.Close()
		delete(s.sessions, id)
	}
	s.sessionsMu.Unlock()

	// Close transport
	return s.trans.Close()
}

// receiveLoop receives and processes packets
func (s *Server) receiveLoop() error {
	for s.running.Load() {
		data, srcIP, srcPort, err := s.trans.Receive()
		if err != nil {
			if s.running.Load() {
				log.Printf("receive error: %v", err)
			}
			continue
		}

		// Verify source IP if configured (client sends with spoofed IP)
		if s.expectedSpoofIP != nil && !srcIP.Equal(s.expectedSpoofIP) {
			log.Printf("packet from unexpected IP: %s (expected spoof %s)", srcIP, s.expectedSpoofIP)
			continue
		}

		// Decrypt packet
		plaintext, err := s.cipher.Decrypt(data)
		if err != nil {
			log.Printf("decrypt error: %v", err)
			continue
		}

		// Parse packet
		pkt, err := protocol.Parse(plaintext)
		if err != nil {
			log.Printf("parse error: %v", err)
			continue
		}

		// Handle packet
		s.handlePacket(pkt, srcIP, srcPort)
	}

	return nil
}

// handlePacket processes a received packet
func (s *Server) handlePacket(pkt *protocol.Packet, clientIP net.IP, clientPort uint16) {
	switch pkt.Type {
	case protocol.PacketInit:
		s.handleInit(pkt, clientIP, clientPort)

	case protocol.PacketData:
		s.handleData(pkt)

	case protocol.PacketClose:
		s.handleClose(pkt)

	case protocol.PacketPing:
		s.handlePing(pkt, clientIP, clientPort)

	case protocol.PacketAck:
		s.handleAck(pkt)

	case protocol.PacketFEC:
		s.handleFECPacket(pkt, clientIP, clientPort)

	default:
		log.Printf("unknown packet type: %s", protocol.TypeString(pkt.Type))
	}
}

// handleFECPacket processes an FEC shard and recovers lost packets
func (s *Server) handleFECPacket(pkt *protocol.Packet, clientIP net.IP, clientPort uint16) {
	if s.fecDecoder == nil {
		return
	}

	s.fecMu.Lock()
	original, recovered, err := s.fecDecoder.AddShard(pkt.Payload)
	s.fecMu.Unlock()

	if err != nil {
		log.Printf("[FEC] decode error: %v", err)
		return
	}

	// Process original packet if this was a data shard
	if original != nil {
		s.processRecoveredPacket(original, clientIP, clientPort)
	}

	// Process any recovered packets
	for _, recoveredData := range recovered {
		log.Printf("[FEC] recovered lost packet, %d bytes", len(recoveredData))
		s.processRecoveredPacket(recoveredData, clientIP, clientPort)
	}
}

// processRecoveredPacket handles a packet recovered from FEC
func (s *Server) processRecoveredPacket(ciphertext []byte, clientIP net.IP, clientPort uint16) {
	// Decrypt
	plaintext, err := s.cipher.Decrypt(ciphertext)
	if err != nil {
		log.Printf("[FEC] decrypt recovered packet error: %v", err)
		return
	}

	// Parse and handle
	pkt, err := protocol.Parse(plaintext)
	if err != nil {
		log.Printf("[FEC] parse recovered packet error: %v", err)
		return
	}

	// Handle the recovered packet (but not FEC packets to avoid recursion)
	if pkt.Type != protocol.PacketFEC {
		s.handlePacket(pkt, clientIP, clientPort)
	}
}

// handleInit handles connection init requests
func (s *Server) handleInit(pkt *protocol.Packet, clientSpoofIP net.IP, clientPort uint16) {
	target := string(pkt.Payload)
	log.Printf("INIT session %d: target=%s from spoof=%s port=%d", pkt.SessionID, target, clientSpoofIP, clientPort)

	// Connect to target
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("dial %s: %v", target, err)
		// Send failure response to client's REAL IP
		ackPkt := protocol.NewInitAckPacket(pkt.SessionID, false, err.Error())
		s.sendPacket(ackPkt, s.clientRealIP, clientPort)
		return
	}

	// Enable TCP optimizations
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	// Create session
	sess := &ServerSession{
		ID:         pkt.SessionID,
		ClientAddr: clientSpoofIP,
		ClientPort: clientPort,
		Target:     target,
		TargetConn: conn,
		Created:    time.Now(),
		LastActive: time.Now(),
	}

	// Initialize RecvBuffer for reliable upload if enabled
	if s.config.Reliability.Enabled {
		// RecvBuffer doesn't need deliverCh since we write directly to target
		sess.recvBuffer = NewRecvBuffer(nil, time.Duration(s.config.Reliability.AckIntervalMs)*time.Millisecond)

		// SendBuffer for reliable downloads (server to client)
		retransmitTimeout := time.Duration(s.config.Reliability.RetransmitTimeoutMs) * time.Millisecond
		sess.sendBuffer = NewSendBuffer(
			s.config.Reliability.WindowSize,
			retransmitTimeout,
			func(seqNum uint32, data []byte) error {
				// Retransmit callback - resend packet with same sequence
				pkt := protocol.NewSeqDataPacket(sess.ID, seqNum, data)
				return s.sendPacket(pkt, s.clientRealIP, sess.ClientPort)
			},
		)
	}

	s.sessionsMu.Lock()
	s.sessions[pkt.SessionID] = sess
	s.sessionsMu.Unlock()

	// Send success response to client's REAL IP
	// Send 3x for redundancy (ICMP can drop packets)
	ackPkt := protocol.NewInitAckPacket(pkt.SessionID, true, "connected")
	for i := 0; i < 3; i++ {
		if err := s.sendPacket(ackPkt, s.clientRealIP, clientPort); err != nil {
			log.Printf("send init ack %d: %v", i+1, err)
		} else {
			log.Printf("[DEBUG] session %d: sent INIT_ACK %d/3", pkt.SessionID, i+1)
		}
		if i < 2 {
			time.Sleep(20 * time.Millisecond)
		}
	}

	// Start target reader goroutine
	go s.pumpTargetToClient(sess)
}

// handleData handles data packets (uploads from client)
func (s *Server) handleData(pkt *protocol.Packet) {
	s.sessionsMu.RLock()
	sess, exists := s.sessions[pkt.SessionID]
	s.sessionsMu.RUnlock()

	if !exists {
		log.Printf("[DEBUG] DATA for unknown session %d", pkt.SessionID)
		return
	}

	sess.mu.Lock()
	sess.LastActive = time.Now()
	sess.mu.Unlock()

	var data []byte
	var seqNum uint32

	// Try to parse as sequenced data packet
	if sess.recvBuffer != nil && len(pkt.Payload) >= 4 {
		var err error
		seqNum, data, err = protocol.ParseSeqData(pkt.Payload)
		if err != nil {
			// Fallback to raw payload
			data = pkt.Payload
		} else {
			// Track in RecvBuffer (ignore duplicates)
			if !sess.recvBuffer.Receive(seqNum, data) {
				// Duplicate packet, but still send ACK
				log.Printf("[DEBUG] session %d: duplicate seq %d", pkt.SessionID, seqNum)
			}

			// Send ACK if it's time
			if sess.recvBuffer.ShouldSendAck() {
				ackSeq, bitmap := sess.recvBuffer.GenerateAck()
				ackPkt := protocol.NewAckPacket(pkt.SessionID, ackSeq, bitmap)
				if err := s.sendPacket(ackPkt, s.clientRealIP, sess.ClientPort); err != nil {
					log.Printf("[DEBUG] session %d: failed to send ACK: %v", pkt.SessionID, err)
				}
			}
		}
	} else {
		data = pkt.Payload
	}

	log.Printf("[DEBUG] DATA session %d: seq=%d, %d bytes", pkt.SessionID, seqNum, len(data))

	// Write to target
	if _, err := sess.TargetConn.Write(data); err != nil {
		log.Printf("write to target %s: %v", sess.Target, err)
		s.removeSession(pkt.SessionID)
		return
	}

	s.bytesReceived.Add(uint64(len(data)))
}

// handleClose handles close packets
func (s *Server) handleClose(pkt *protocol.Packet) {
	log.Printf("CLOSE session %d", pkt.SessionID)
	s.removeSession(pkt.SessionID)
}

// handlePing handles ping packets
func (s *Server) handlePing(pkt *protocol.Packet, clientIP net.IP, clientPort uint16) {
	// Extract sequence
	var seq uint32
	if len(pkt.Payload) >= 4 {
		seq = uint32(pkt.Payload[0])<<24 | uint32(pkt.Payload[1])<<16 |
			uint32(pkt.Payload[2])<<8 | uint32(pkt.Payload[3])
	}

	// Send pong
	pongPkt := protocol.NewPongPacket(pkt.SessionID, seq)
	s.sendPacket(pongPkt, clientIP, clientPort)
}

// handleAck handles ACK packets from client for reliable delivery
func (s *Server) handleAck(pkt *protocol.Packet) {
	s.sessionsMu.RLock()
	sess, exists := s.sessions[pkt.SessionID]
	s.sessionsMu.RUnlock()

	if !exists || sess.sendBuffer == nil {
		return
	}

	// Parse ACK
	ackSeqNum, recvBitmap, err := protocol.ParseAck(pkt.Payload)
	if err != nil {
		log.Printf("[DEBUG] invalid ACK from session %d: %v", pkt.SessionID, err)
		return
	}

	// Process ACK - removes acknowledged packets from buffer
	sess.sendBuffer.ProcessAck(ackSeqNum, recvBitmap)

	// Check for packets that need retransmission
	candidates := sess.sendBuffer.GetRetransmitCandidates()
	for _, seqNum := range candidates {
		if err := sess.sendBuffer.Retransmit(seqNum); err != nil {
			log.Printf("[DEBUG] retransmit seq %d failed: %v", seqNum, err)
		}
	}
}

// pumpTargetToClient reads from target and sends to client
func (s *Server) pumpTargetToClient(sess *ServerSession) {
	defer s.removeSession(sess.ID)

	bufPtr := s.bufPool.Get().(*[]byte)
	defer s.bufPool.Put(bufPtr)
	buf := *bufPtr

	// Use longer read timeout for idle connections
	idleTimeout := time.Duration(s.config.Performance.SessionTimeout) * time.Second
	if idleTimeout < 60*time.Second {
		idleTimeout = 60 * time.Second
	}

	doneCh := make(chan struct{})
	defer close(doneCh)

	// Retransmission goroutine for reliable downloads
	if sess.sendBuffer != nil {
		go func() {
			ticker := time.NewTicker(100 * time.Millisecond) // Check every 100ms
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					candidates := sess.sendBuffer.GetRetransmitCandidates()
					for _, seqNum := range candidates {
						if err := sess.sendBuffer.Retransmit(seqNum); err != nil {
							log.Printf("[DEBUG] session %d: retransmit seq %d failed: %v", sess.ID, seqNum, err)
						} else {
							log.Printf("[DEBUG] session %d: retransmit seq %d", sess.ID, seqNum)
						}
					}
				case <-doneCh:
					return
				}
			}
		}()
	}

	for {
		// Set read deadline - but don't close on every timeout
		sess.TargetConn.SetReadDeadline(time.Now().Add(idleTimeout))

		n, err := sess.TargetConn.Read(buf[:s.config.Performance.MTU-100])
		if n > 0 {
			sess.mu.Lock()
			sess.LastActive = time.Now()
			clientPort := sess.ClientPort
			sess.mu.Unlock()

			var pkt *protocol.Packet
			dataCopy := make([]byte, n)
			copy(dataCopy, buf[:n])

			if sess.sendBuffer != nil {
				// Reliable mode: wait for window space, then send with sequence
				for !sess.sendBuffer.CanSend() {
					time.Sleep(10 * time.Millisecond)
				}
				seqNum := sess.sendBuffer.Send(dataCopy)
				pkt = protocol.NewSeqDataPacket(sess.ID, seqNum, dataCopy)
			} else {
				// Non-reliable mode: simple data packet
				pkt = protocol.NewDataPacket(sess.ID, dataCopy)
			}

			if sendErr := s.sendPacket(pkt, s.clientRealIP, clientPort); sendErr != nil {
				log.Printf("send to client: %v", sendErr)
				return
			}

			s.bytesSent.Add(uint64(n))
		}

		if err != nil {
			// Check if it's a timeout - if so, check if session is still active
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				sess.mu.Lock()
				lastActive := sess.LastActive
				sess.mu.Unlock()

				// If we haven't had any activity in a long time, close
				if time.Since(lastActive) > idleTimeout {
					log.Printf("[DEBUG] session %d: idle timeout", sess.ID)
					closePkt := protocol.NewClosePacket(sess.ID)
					s.sendPacket(closePkt, s.clientRealIP, sess.ClientPort)
					return
				}
				// Otherwise continue waiting
				continue
			}

			// Real error or EOF
			if err == io.EOF {
				log.Printf("[DEBUG] session %d: target %s closed connection (EOF)", sess.ID, sess.Target)
			} else {
				log.Printf("[DEBUG] session %d: target error: %v", sess.ID, err)
			}
			// Send close packet to client's REAL IP
			closePkt := protocol.NewClosePacket(sess.ID)
			s.sendPacket(closePkt, s.clientRealIP, sess.ClientPort)
			return
		}
	}
}

// sendPacket encrypts and sends a packet to the client with rate limiting
func (s *Server) sendPacket(pkt *protocol.Packet, clientIP net.IP, clientPort uint16) error {
	// Rate limiting: only apply to DATA packets, not control packets
	// Control packets (INIT_ACK, ACK, CLOSE, etc.) need to be sent immediately
	if s.sendInterval > 0 && pkt.Type == protocol.PacketData {
		s.lastSendMu.Lock()
		sinceLastSend := time.Since(s.lastSendTime)
		if sinceLastSend < s.sendInterval {
			time.Sleep(s.sendInterval - sinceLastSend)
		}
		s.lastSendTime = time.Now()
		s.lastSendMu.Unlock()
	}

	// Marshal packet
	data, err := pkt.Marshal()
	if err != nil {
		return err
	}

	// Encrypt
	ciphertext, err := s.cipher.Encrypt(data)
	if err != nil {
		return err
	}

	// If FEC is enabled and this is a data packet, encode with FEC
	if s.fecEncoder != nil && pkt.Type == protocol.PacketData {
		return s.sendWithFEC(ciphertext, clientIP, clientPort)
	}

	// Send with spoofed source IP
	return s.trans.Send(ciphertext, clientIP, clientPort)
}

// sendWithFEC encodes data with FEC and sends all shards
func (s *Server) sendWithFEC(data []byte, clientIP net.IP, clientPort uint16) error {
	s.fecMu.Lock()
	shards, err := s.fecEncoder.AddPacket(data)
	s.fecMu.Unlock()

	if err != nil {
		return fmt.Errorf("FEC encode: %w", err)
	}

	// If shards is nil, we need more packets to form a group
	if shards == nil {
		return nil
	}

	// Send all shards (data + parity)
	for _, shard := range shards {
		fecPkt := protocol.NewFECPacket(0, shard)
		pktData, err := fecPkt.Marshal()
		if err != nil {
			return err
		}

		ciphertext, err := s.cipher.Encrypt(pktData)
		if err != nil {
			return err
		}

		if err := s.trans.Send(ciphertext, clientIP, clientPort); err != nil {
			return err
		}
	}

	return nil
}

// flushFEC sends any pending FEC packets
func (s *Server) flushFEC(clientIP net.IP, clientPort uint16) error {
	if s.fecEncoder == nil {
		return nil
	}

	s.fecMu.Lock()
	shards, err := s.fecEncoder.Flush()
	s.fecMu.Unlock()

	if err != nil {
		return err
	}

	if shards == nil {
		return nil
	}

	for _, shard := range shards {
		fecPkt := protocol.NewFECPacket(0, shard)
		pktData, err := fecPkt.Marshal()
		if err != nil {
			return err
		}

		ciphertext, err := s.cipher.Encrypt(pktData)
		if err != nil {
			return err
		}

		if err := s.trans.Send(ciphertext, clientIP, clientPort); err != nil {
			return err
		}
	}

	return nil
}

// removeSession removes and closes a session
func (s *Server) removeSession(id uint32) {
	s.sessionsMu.Lock()
	if sess, exists := s.sessions[id]; exists {
		sess.Close()
		delete(s.sessions, id)
		log.Printf("session %d closed", id)
	}
	s.sessionsMu.Unlock()
}

// cleanupLoop periodically cleans up inactive sessions
func (s *Server) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	timeout := time.Duration(s.config.Performance.SessionTimeout) * time.Second

	for {
		select {
		case <-ticker.C:
			s.sessionsMu.Lock()
			now := time.Now()
			for id, sess := range s.sessions {
				sess.mu.Lock()
				if now.Sub(sess.LastActive) > timeout {
					sess.TargetConn.Close()
					delete(s.sessions, id)
					log.Printf("session %d timed out", id)
				}
				sess.mu.Unlock()
			}
			s.sessionsMu.Unlock()

		case <-s.stopCh:
			return
		}
	}
}

// Close closes a session
func (sess *ServerSession) Close() {
	if sess.closed.Swap(true) {
		return
	}
	if sess.TargetConn != nil {
		sess.TargetConn.Close()
	}
}

// Stats returns server statistics
func (s *Server) Stats() (sent, received uint64, sessions int) {
	s.sessionsMu.RLock()
	sessions = len(s.sessions)
	s.sessionsMu.RUnlock()
	return s.bytesSent.Load(), s.bytesReceived.Load(), sessions
}
