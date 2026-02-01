package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ParsaKSH/spooftunnel/internal/config"
	"github.com/ParsaKSH/spooftunnel/internal/crypto"
	"github.com/ParsaKSH/spooftunnel/internal/fec"
	"github.com/ParsaKSH/spooftunnel/internal/protocol"
	"github.com/ParsaKSH/spooftunnel/internal/socks"
	"github.com/ParsaKSH/spooftunnel/internal/transport"
)

// Client is the tunnel client that provides SOCKS5 proxy
type Client struct {
	config *config.Config
	cipher *crypto.Cipher
	trans  transport.Transport

	// Server endpoint
	serverIP   net.IP
	serverPort uint16

	// Session management
	sessions   map[uint32]*ClientSession
	sessionsMu sync.RWMutex

	// SOCKS5 server
	socksServer *socks.Server

	// FEC
	fecEncoder *fec.Encoder
	fecDecoder *fec.Decoder
	fecMu      sync.Mutex

	// State
	running atomic.Bool
	stopCh  chan struct{}

	// Buffer pool
	bufPool sync.Pool

	// Stats
	bytesSent     atomic.Uint64
	bytesReceived atomic.Uint64
}

// ClientSession represents a tunnel session from client side
type ClientSession struct {
	ID         uint32
	Target     string
	LocalConn  net.Conn
	Created    time.Time
	LastActive time.Time
	ClosedAt   time.Time // When this session was closed (for grace period)

	// Data channels
	recvCh chan []byte

	// Reliable delivery - download
	recvBuffer  *RecvBuffer // For tracking received seqs and generating ACKs
	lastAckSeq  uint32      // Last sequence we sent ACK for
	lastAckTime time.Time   // When we last sent an ACK

	// Reliable delivery - upload
	sendBuffer *SendBuffer // For tracking sent packets and retransmission
	uploadSeq  uint32      // Next sequence number for upload

	// State
	closed atomic.Bool
	mu     sync.Mutex
}

// NewClient creates a new tunnel client
func NewClient(cfg *config.Config, cipher *crypto.Cipher) (*Client, error) {
	// Parse server address
	serverIP := net.ParseIP(cfg.Server.Address)
	if serverIP == nil {
		// Try to resolve hostname
		ips, err := net.LookupIP(cfg.Server.Address)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve server address: %w", err)
		}
		serverIP = ips[0]
	}

	// Create transport
	transportCfg := &transport.Config{
		SourceIP:       net.ParseIP(cfg.Spoof.SourceIP),
		SourceIPv6:     net.ParseIP(cfg.Spoof.SourceIPv6),
		ListenPort:     0, // Dynamic port
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

	c := &Client{
		config:     cfg,
		cipher:     cipher,
		trans:      trans,
		serverIP:   serverIP,
		serverPort: uint16(cfg.Server.Port),
		sessions:   make(map[uint32]*ClientSession),
		stopCh:     make(chan struct{}),
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
		c.fecEncoder = enc

		dec, err := fec.NewDecoder(cfg.FEC.DataShards, cfg.FEC.ParityShards)
		if err != nil {
			return nil, fmt.Errorf("create FEC decoder: %w", err)
		}
		c.fecDecoder = dec
	}

	return c, nil
}

// Start starts the client
func (c *Client) Start() error {
	// Create SOCKS5 server with StreamHandler for direct TCP access
	// This allows downloads to bypass channel overhead for maximum throughput
	socksServer, err := socks.NewStreamServer(c.config.GetListenAddr(), c.handleStream)
	if err != nil {
		return fmt.Errorf("create socks server: %w", err)
	}
	c.socksServer = socksServer

	c.running.Store(true)

	// Start receiver goroutine
	go c.receiveLoop()

	// Start session cleanup
	go c.cleanupLoop()

	// Start keepalive
	go c.keepaliveLoop()

	// Start SOCKS5 server
	log.Printf("SOCKS5 proxy listening on %s", c.config.GetListenAddr())
	log.Printf("Tunneling to %s:%d via %s", c.serverIP, c.serverPort, c.config.Transport.Type)

	return c.socksServer.Serve()
}

// Stop stops the client
func (c *Client) Stop() error {
	if !c.running.Swap(false) {
		return nil
	}

	close(c.stopCh)

	// Close all sessions
	c.sessionsMu.Lock()
	for id, sess := range c.sessions {
		sess.Close()
		delete(c.sessions, id)
	}
	c.sessionsMu.Unlock()

	// Close transport
	c.trans.Close()

	// Close SOCKS5 server
	if c.socksServer != nil {
		c.socksServer.Close()
	}

	return nil
}

// handleConnect is called when a SOCKS5 CONNECT request is received
func (c *Client) handleConnect(target string) (net.Conn, error) {
	// Generate session ID
	sessionID := c.generateSessionID()

	// Create session
	sess := &ClientSession{
		ID:         sessionID,
		Target:     target,
		Created:    time.Now(),
		LastActive: time.Now(),
		recvCh:     make(chan []byte, 256),
	}

	c.sessionsMu.Lock()
	c.sessions[sessionID] = sess
	c.sessionsMu.Unlock()

	// Send INIT packet to server
	initPacket := protocol.NewInitPacket(sessionID, target)
	if err := c.sendPacket(initPacket); err != nil {
		c.removeSession(sessionID)
		return nil, fmt.Errorf("send init: %w", err)
	}

	// Wait for INIT_ACK with timeout
	select {
	case data := <-sess.recvCh:
		// Parse the received packet
		pkt, err := protocol.Parse(data)
		if err != nil {
			c.removeSession(sessionID)
			return nil, fmt.Errorf("parse init ack: %w", err)
		}
		if pkt.Type != protocol.PacketInitAck {
			c.removeSession(sessionID)
			return nil, fmt.Errorf("unexpected packet type: %s", protocol.TypeString(pkt.Type))
		}
		success, msg := protocol.ParseInitAck(pkt.Payload)
		if !success {
			c.removeSession(sessionID)
			return nil, fmt.Errorf("server rejected: %s", msg)
		}

	case <-time.After(10 * time.Second):
		c.removeSession(sessionID)
		return nil, fmt.Errorf("init timeout")

	case <-c.stopCh:
		c.removeSession(sessionID)
		return nil, fmt.Errorf("client stopped")
	}

	// Create virtual connection for SOCKS5 using our buffered TunnelConn
	localConn, remoteConn := NewTunnelConnPair(sess.Target)
	sess.LocalConn = localConn

	// Start data forwarding goroutine
	go c.forwardSession(sess, remoteConn)

	return localConn, nil
}

// handleStream is called when a SOCKS5 CONNECT request is received.
// Unlike handleConnect, this receives the actual TCP connection for DIRECT writes.
// This bypasses TunnelConn channel overhead for maximum download throughput.
func (c *Client) handleStream(target string, tcpConn net.Conn) error {
	// Generate session ID
	sessionID := c.generateSessionID()

	// Create session with TCP connection for direct download writes
	sess := &ClientSession{
		ID:         sessionID,
		Target:     target,
		LocalConn:  tcpConn, // Store real TCP conn for direct writes
		Created:    time.Now(),
		LastActive: time.Now(),
		recvCh:     make(chan []byte, 512), // Larger buffer
		uploadSeq:  1,                      // Start sequence at 1
	}

	// Initialize SendBuffer for reliable upload if enabled
	if c.config.Reliability.Enabled {
		retransmitTimeout := time.Duration(c.config.Reliability.RetransmitTimeoutMs) * time.Millisecond
		sess.sendBuffer = NewSendBuffer(
			c.config.Reliability.WindowSize,
			retransmitTimeout,
			func(seqNum uint32, data []byte) error {
				// Retransmit callback - resend packet with same sequence
				pkt := protocol.NewSeqDataPacket(sess.ID, seqNum, data)
				return c.sendPacket(pkt)
			},
		)

		// RecvBuffer for reliable downloads (server to client)
		sess.recvBuffer = NewRecvBuffer(nil, time.Duration(c.config.Reliability.AckIntervalMs)*time.Millisecond)
	}

	c.sessionsMu.Lock()
	c.sessions[sessionID] = sess
	c.sessionsMu.Unlock()

	// Send INIT packet to server
	initPacket := protocol.NewInitPacket(sessionID, target)
	if err := c.sendPacket(initPacket); err != nil {
		c.removeSession(sessionID)
		tcpConn.Close()
		return fmt.Errorf("send init: %w", err)
	}

	// Wait for INIT_ACK with timeout
	select {
	case data := <-sess.recvCh:
		pkt, err := protocol.Parse(data)
		if err != nil {
			c.removeSession(sessionID)
			tcpConn.Close()
			return fmt.Errorf("parse init ack: %w", err)
		}
		if pkt.Type != protocol.PacketInitAck {
			log.Printf("[DEBUG] session %d: expected INIT_ACK but got %s", sessionID, protocol.TypeString(pkt.Type))
			c.removeSession(sessionID)
			tcpConn.Close()
			return fmt.Errorf("unexpected packet type: %s", protocol.TypeString(pkt.Type))
		}
		success, msg := protocol.ParseInitAck(pkt.Payload)
		if !success {
			c.removeSession(sessionID)
			tcpConn.Close()
			return fmt.Errorf("server rejected: %s", msg)
		}
		log.Printf("[DEBUG] session %d: INIT_ACK received, target=%s", sessionID, target)

	case <-time.After(10 * time.Second):
		log.Printf("[DEBUG] session %d: INIT_ACK timeout (10s), target=%s", sessionID, target)
		c.removeSession(sessionID)
		tcpConn.Close()
		return fmt.Errorf("init timeout")

	case <-c.stopCh:
		c.removeSession(sessionID)
		tcpConn.Close()
		return fmt.Errorf("client stopped")
	}

	// Start direct streaming - NO TunnelConn, direct TCP writes for downloads
	c.streamSession(sess)
	return nil
}

// streamSession handles data forwarding with DIRECT TCP writes for downloads.
// This is the high-performance path that bypasses TunnelConn channels.
func (c *Client) streamSession(sess *ClientSession) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[DEBUG] session %d: recovered from panic: %v", sess.ID, r)
		}
	}()
	defer sess.LocalConn.Close()
	defer c.removeSession(sess.ID)

	doneCh := make(chan struct{})
	var closeOnce sync.Once
	closeDone := func() {
		closeOnce.Do(func() {
			close(doneCh)
		})
	}

	// Get idle timeout
	idleTimeout := time.Duration(c.config.Performance.SessionTimeout) * time.Second
	if idleTimeout < 120*time.Second {
		idleTimeout = 120 * time.Second
	}

	// Upload: TCP -> Tunnel (client sending request to server)
	go func() {
		bufPtr := c.bufPool.Get().(*[]byte)
		defer c.bufPool.Put(bufPtr)
		buf := *bufPtr

		for {
			select {
			case <-doneCh:
				return
			default:
			}

			n, err := sess.LocalConn.Read(buf[:c.config.Performance.MTU-100])
			if n > 0 {
				sess.mu.Lock()
				sess.LastActive = time.Now()
				sess.mu.Unlock()

				var pkt *protocol.Packet
				dataCopy := make([]byte, n)
				copy(dataCopy, buf[:n])

				if sess.sendBuffer != nil {
					// Reliable mode: wait for window space, then send with sequence
					for !sess.sendBuffer.CanSend() {
						select {
						case <-doneCh:
							return
						case <-time.After(10 * time.Millisecond):
							// Wait for ACKs to free window space
						}
					}
					seqNum := sess.sendBuffer.Send(dataCopy)
					pkt = protocol.NewSeqDataPacket(sess.ID, seqNum, dataCopy)
				} else {
					// Non-reliable mode: simple data packet
					pkt = protocol.NewDataPacket(sess.ID, dataCopy)
				}

				if sendErr := c.sendPacket(pkt); sendErr != nil {
					log.Printf("[DEBUG] session %d: send error: %v", sess.ID, sendErr)
					closeDone()
					return
				}
				c.bytesSent.Add(uint64(n))
			}
			if err != nil {
				// Client finished sending - don't close session, download may continue
				return
			}
		}
	}()

	// Download: Tunnel -> TCP (server sending response to client)
	// This is the CRITICAL path - DIRECT write to TCP socket, NO channels!
	go func() {
		for {
			select {
			case <-doneCh:
				log.Printf("[DEBUG] session %d: download exiting (doneCh)", sess.ID)
				return

			case data, ok := <-sess.recvCh:
				if !ok {
					log.Printf("[DEBUG] session %d: recvCh closed", sess.ID)
					closeDone()
					return
				}
				pkt, err := protocol.Parse(data)
				if err != nil {
					log.Printf("[DEBUG] session %d: parse error", sess.ID)
					continue
				}

				sess.mu.Lock()
				sess.LastActive = time.Now()
				sess.mu.Unlock()

				switch pkt.Type {
				case protocol.PacketData:
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
								// Duplicate packet, skip write but send ACK
								log.Printf("[DEBUG] session %d: duplicate download seq %d", sess.ID, seqNum)
							}

							// Send ACK if it's time
							if sess.recvBuffer.ShouldSendAck() {
								ackSeq, bitmap := sess.recvBuffer.GenerateAck()
								ackPkt := protocol.NewAckPacket(sess.ID, ackSeq, bitmap)
								if err := c.sendPacket(ackPkt); err != nil {
									log.Printf("[DEBUG] session %d: failed to send ACK: %v", sess.ID, err)
								}
							}
						}
					} else {
						data = pkt.Payload
					}

					// DIRECT WRITE TO TCP
					_, err := sess.LocalConn.Write(data)
					if err != nil {
						log.Printf("[DEBUG] session %d: direct write failed: %v", sess.ID, err)
						closeDone()
						return
					}
					c.bytesReceived.Add(uint64(len(data)))

				case protocol.PacketClose:
					log.Printf("[DEBUG] session %d: server closed", sess.ID)
					closeDone()
					return
				}

			case <-c.stopCh:
				closeDone()
				return
			}
		}
	}()

	// Retransmission goroutine for reliable uploads
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
				case <-c.stopCh:
					return
				}
			}
		}()
	}

	// Idle timeout checker
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sess.mu.Lock()
				lastActive := sess.LastActive
				sess.mu.Unlock()
				if time.Since(lastActive) > idleTimeout {
					log.Printf("[DEBUG] session %d: idle timeout", sess.ID)
					closeDone()
					return
				}
			case <-doneCh:
				return
			case <-c.stopCh:
				return
			}
		}
	}()

	// Wait for session to complete
	<-doneCh

	// Send close packet
	closePkt := protocol.NewClosePacket(sess.ID)
	c.sendPacket(closePkt)
}

// forwardSession handles data forwarding for a session
func (c *Client) forwardSession(sess *ClientSession, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[DEBUG] session %d: recovered from panic: %v", sess.ID, r)
		}
	}()
	defer conn.Close()
	defer c.removeSession(sess.ID)

	doneCh := make(chan struct{})
	var closeOnce sync.Once
	closeDone := func() {
		closeOnce.Do(func() {
			close(doneCh)
		})
	}

	// Track if local->tunnel is done (client finished sending request)
	localDone := make(chan struct{})

	// Get idle timeout
	idleTimeout := time.Duration(c.config.Performance.SessionTimeout) * time.Second
	if idleTimeout < 120*time.Second {
		idleTimeout = 120 * time.Second
	}

	// Local -> Tunnel (from SOCKS5 to server)
	go func() {
		defer close(localDone)
		bufPtr := c.bufPool.Get().(*[]byte)
		defer c.bufPool.Put(bufPtr)
		buf := *bufPtr

		for {
			select {
			case <-doneCh:
				return
			default:
			}

			n, err := conn.Read(buf[:c.config.Performance.MTU-100])
			if n > 0 {
				sess.mu.Lock()
				sess.LastActive = time.Now()
				sess.mu.Unlock()

				pkt := protocol.NewDataPacket(sess.ID, buf[:n])
				if sendErr := c.sendPacket(pkt); sendErr != nil {
					log.Printf("[DEBUG] session %d: send error: %v", sess.ID, sendErr)
					closeDone() // Close on send error
					return
				}
				c.bytesSent.Add(uint64(n))
			}
			if err != nil {
				// Local client finished sending - DON'T close session
				// Just exit this goroutine, let tunnel->local continue
				return
			}
		}
	}()

	// Tunnel -> Local (from server to SOCKS5)
	go func() {
		for {
			select {
			case <-doneCh:
				log.Printf("[DEBUG] session %d: tunnel->local exiting (doneCh)", sess.ID)
				return

			case data, ok := <-sess.recvCh:
				if !ok {
					log.Printf("[DEBUG] session %d: recvCh closed", sess.ID)
					closeDone()
					return
				}
				pkt, err := protocol.Parse(data)
				if err != nil {
					log.Printf("[DEBUG] session %d: parse error in tunnel->local", sess.ID)
					continue
				}

				sess.mu.Lock()
				sess.LastActive = time.Now()
				sess.mu.Unlock()

				switch pkt.Type {
				case protocol.PacketData:
					log.Printf("[DEBUG] session %d: writing %d bytes to local", sess.ID, len(pkt.Payload))
					if _, err := conn.Write(pkt.Payload); err != nil {
						log.Printf("[DEBUG] session %d: write to local failed: %v", sess.ID, err)
						closeDone()
						return
					}
					c.bytesReceived.Add(uint64(len(pkt.Payload)))

				case protocol.PacketClose:
					log.Printf("[DEBUG] session %d: server closed", sess.ID)
					closeDone()
					return

				case protocol.PacketPong:
					// Keepalive response
				}

			case <-c.stopCh:
				closeDone()
				return
			}
		}
	}()

	// Idle timeout checker
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sess.mu.Lock()
				lastActive := sess.LastActive
				sess.mu.Unlock()
				if time.Since(lastActive) > idleTimeout {
					log.Printf("[DEBUG] session %d: idle timeout", sess.ID)
					closeDone()
					return
				}
			case <-doneCh:
				return
			case <-c.stopCh:
				return
			}
		}
	}()

	// Wait for session to complete (server sends CLOSE or timeout)
	<-doneCh

	// Also wait a bit for localDone to complete
	select {
	case <-localDone:
	case <-time.After(100 * time.Millisecond):
	}

	// Send close packet
	closePacket := protocol.NewClosePacket(sess.ID)
	_ = c.sendPacket(closePacket)
}

// receiveLoop receives packets from the transport
func (c *Client) receiveLoop() {
	packetCount := uint64(0)
	for c.running.Load() {
		data, srcIP, _, err := c.trans.Receive()
		if err != nil {
			if c.running.Load() {
				log.Printf("[RECV] error: %v", err)
			}
			continue
		}

		packetCount++
		if packetCount%100 == 1 {
			log.Printf("[RECV] received packet #%d from %v, %d bytes", packetCount, srcIP, len(data))
		}

		// Verify source IP if configured
		if c.config.Spoof.PeerSpoofIP != "" {
			expectedIP := net.ParseIP(c.config.Spoof.PeerSpoofIP)
			if expectedIP != nil && !srcIP.Equal(expectedIP) {
				log.Printf("[RECV] warning: packet from unexpected IP %s (expected %s)", srcIP, expectedIP)
			}
		}

		// Decrypt packet
		plaintext, err := c.cipher.Decrypt(data)
		if err != nil {
			log.Printf("[RECV] decrypt error: %v", err)
			continue
		}

		// Parse header to get session ID
		header, err := protocol.ParseHeader(plaintext)
		if err != nil {
			log.Printf("[RECV] parse header error: %v", err)
			continue
		}

		// Handle FEC packets
		if header.Type == protocol.PacketFEC && c.fecDecoder != nil {
			c.handleFECPacket(plaintext)
			continue
		}

		// Route to session
		c.sessionsMu.RLock()
		sess, exists := c.sessions[header.SessionID]
		c.sessionsMu.RUnlock()

		if !exists {
			// Only log if it's not a keepalive packet (type 5 = PONG)
			if header.Type != 5 {
				log.Printf("[RECV] packet for unknown session %d, type=%d", header.SessionID, header.Type)
			}
			continue
		}

		// Skip if session is already closed (in grace period, but not processing new data)
		if sess.closed.Load() {
			continue
		}

		// Handle ACK packets for upload reliability
		if header.Type == protocol.PacketAck && sess.sendBuffer != nil {
			pkt, err := protocol.Parse(plaintext)
			if err == nil {
				ackSeq, bitmap, err := protocol.ParseAck(pkt.Payload)
				if err == nil {
					acked := sess.sendBuffer.ProcessAck(ackSeq, bitmap)
					if len(acked) > 0 {
						log.Printf("[DEBUG] session %d: ACKed %d packets (up to seq %d)", header.SessionID, len(acked), ackSeq)
					}
				}
			}
			continue // ACK packets don't go to session channel
		}

		// Send to session channel (non-blocking)
		select {
		case sess.recvCh <- plaintext:
		default:
			log.Printf("[RECV] session %d buffer full, dropping packet", header.SessionID)
		}
	}
	log.Printf("[RECV] loop ended, total packets received: %d", packetCount)
}

// handleFECPacket processes an FEC shard and recovers lost packets
func (c *Client) handleFECPacket(data []byte) {
	pkt, err := protocol.Parse(data)
	if err != nil {
		log.Printf("[FEC] parse error: %v", err)
		return
	}

	c.fecMu.Lock()
	original, recovered, err := c.fecDecoder.AddShard(pkt.Payload)
	c.fecMu.Unlock()

	if err != nil {
		log.Printf("[FEC] decode error: %v", err)
		return
	}

	// Process original packet if this was a data shard
	if original != nil {
		c.processRecoveredPacket(original)
	}

	// Process any recovered packets
	for _, recoveredData := range recovered {
		log.Printf("[FEC] recovered lost packet, %d bytes", len(recoveredData))
		c.processRecoveredPacket(recoveredData)
	}
}

// processRecoveredPacket handles a packet recovered from FEC
func (c *Client) processRecoveredPacket(ciphertext []byte) {
	// Decrypt
	plaintext, err := c.cipher.Decrypt(ciphertext)
	if err != nil {
		log.Printf("[FEC] decrypt recovered packet error: %v", err)
		return
	}

	header, err := protocol.ParseHeader(plaintext)
	if err != nil {
		log.Printf("[FEC] parse recovered packet error: %v", err)
		return
	}

	// Route to session
	c.sessionsMu.RLock()
	sess, exists := c.sessions[header.SessionID]
	c.sessionsMu.RUnlock()

	if !exists || sess.closed.Load() {
		return
	}

	// Send to session channel
	select {
	case sess.recvCh <- plaintext:
	default:
		log.Printf("[FEC] session %d buffer full, dropping recovered packet", header.SessionID)
	}
}

// cleanupLoop periodically cleans up inactive sessions
func (c *Client) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	timeout := time.Duration(c.config.Performance.SessionTimeout) * time.Second
	gracePeriod := 5 * time.Second // Keep closed sessions for 5 seconds to receive in-flight packets

	for {
		select {
		case <-ticker.C:
			c.sessionsMu.Lock()
			now := time.Now()
			for id, sess := range c.sessions {
				sess.mu.Lock()
				// Check if session is closed and grace period has passed
				if sess.closed.Load() {
					if !sess.ClosedAt.IsZero() && now.Sub(sess.ClosedAt) > gracePeriod {
						delete(c.sessions, id)
					}
					sess.mu.Unlock()
					continue
				}
				// Check for idle timeout on active sessions
				if now.Sub(sess.LastActive) > timeout {
					sess.closed.Store(true)
					sess.ClosedAt = now
					log.Printf("session %d timed out", id)
				}
				sess.mu.Unlock()
			}
			c.sessionsMu.Unlock()

		case <-c.stopCh:
			return
		}
	}
}

// sendPacket encrypts and sends a packet to the server
func (c *Client) sendPacket(pkt *protocol.Packet) error {
	// Marshal packet
	data, err := pkt.Marshal()
	if err != nil {
		return err
	}

	// Encrypt
	ciphertext, err := c.cipher.Encrypt(data)
	if err != nil {
		return err
	}

	// If FEC is enabled and this is a data packet, encode with FEC
	if c.fecEncoder != nil && pkt.Type == protocol.PacketData {
		return c.sendWithFEC(ciphertext)
	}

	// Send directly
	return c.trans.Send(ciphertext, c.serverIP, c.serverPort)
}

// sendWithFEC encodes data with FEC and sends all shards
func (c *Client) sendWithFEC(data []byte) error {
	c.fecMu.Lock()
	shards, err := c.fecEncoder.AddPacket(data)
	c.fecMu.Unlock()

	if err != nil {
		return fmt.Errorf("FEC encode: %w", err)
	}

	// If shards is nil, we need more packets to form a group
	if shards == nil {
		return nil
	}

	// Send all shards (data + parity)
	for _, shard := range shards {
		// Wrap shard in FEC packet
		fecPkt := protocol.NewFECPacket(0, shard)
		pktData, err := fecPkt.Marshal()
		if err != nil {
			return err
		}

		// Encrypt the FEC packet
		ciphertext, err := c.cipher.Encrypt(pktData)
		if err != nil {
			return err
		}

		if err := c.trans.Send(ciphertext, c.serverIP, c.serverPort); err != nil {
			return err
		}
	}

	return nil
}

// flushFEC sends any pending FEC packets
func (c *Client) flushFEC() error {
	if c.fecEncoder == nil {
		return nil
	}

	c.fecMu.Lock()
	shards, err := c.fecEncoder.Flush()
	c.fecMu.Unlock()

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

		ciphertext, err := c.cipher.Encrypt(pktData)
		if err != nil {
			return err
		}

		if err := c.trans.Send(ciphertext, c.serverIP, c.serverPort); err != nil {
			return err
		}
	}

	return nil
}

// generateSessionID generates a random session ID
func (c *Client) generateSessionID() uint32 {
	var buf [4]byte
	rand.Read(buf[:])
	return binary.BigEndian.Uint32(buf[:])
}

// removeSession marks a session as closed (actual deletion happens in cleanupLoop)
func (c *Client) removeSession(id uint32) {
	c.sessionsMu.Lock()
	if sess, exists := c.sessions[id]; exists {
		sess.Close()
		// Keep in map for grace period - cleanupLoop will delete later
	}
	c.sessionsMu.Unlock()
}

// Close closes a session
func (sess *ClientSession) Close() {
	if sess.closed.Swap(true) {
		return
	}
	sess.mu.Lock()
	sess.ClosedAt = time.Now()
	sess.mu.Unlock()
	if sess.LocalConn != nil {
		sess.LocalConn.Close()
	}
	// Don't close recvCh - might cause panic from writers
	// It will be garbage collected with the session
}

// Stats returns client statistics
func (c *Client) Stats() (sent, received uint64) {
	return c.bytesSent.Load(), c.bytesReceived.Load()
}

// keepaliveLoop sends periodic ping packets to keep the connection alive
func (c *Client) keepaliveLoop() {
	// Send keepalive every 25 seconds (before typical NAT timeout of 30s)
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Only send keepalive if we have active sessions
			c.sessionsMu.RLock()
			hasActiveSessions := len(c.sessions) > 0
			c.sessionsMu.RUnlock()

			if hasActiveSessions {
				// Session ID 0 = global keepalive, not session-specific
				pingPkt := protocol.NewPingPacket(0, 0)
				if err := c.sendPacket(pingPkt); err != nil {
					log.Printf("keepalive ping failed: %v", err)
				}
			}

		case <-c.stopCh:
			return
		}
	}
}
