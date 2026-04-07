package tunnel

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/ParsaKSH/spooftunnel/internal/config"
	"github.com/ParsaKSH/spooftunnel/internal/protocol"
	"github.com/ParsaKSH/spooftunnel/internal/transport"
)

// ═══════════════════════════════════════════════════════════
// Direct Relay Server — zero-overhead bypass
// ═══════════════════════════════════════════════════════════

// startDirectRelayServer runs a dedicated relay on its own port.
// No encryption, no protocol parsing — raw data forwarded to relay_forward.
func (s *Server) startDirectRelayServer() {
	relayPort := s.config.RelayPort
	forwardAddr := s.config.RelayForward
	if relayPort == 0 || forwardAddr == "" {
		return // not configured
	}

	log.Printf("[relay-direct] starting on port %d → %s (zero overhead)", relayPort, forwardAddr)

	// Resolve forward address
	fwdAddr, err := net.ResolveUDPAddr("udp4", forwardAddr)
	if err != nil {
		log.Printf("[relay-direct] resolve forward addr: %v", err)
		return
	}

	// Create transport for receiving client SYN packets
	transportCfg := &transport.Config{
		SourceIP:    net.ParseIP(s.config.Spoof.SourceIP),
		SourceIPv6:  net.ParseIP(s.config.Spoof.SourceIPv6),
		ListenPort:  uint16(relayPort),
		PeerSpoofIP: net.ParseIP(s.config.Spoof.PeerSpoofIP),
		BufferSize:  s.config.Performance.BufferSize,
		MTU:         s.config.Performance.MTU,
	}

	var relayTrans transport.Transport
	switch s.config.Transport.Type {
	case config.TransportSynUDP:
		relayTrans, err = transport.NewSynUDPTransport(transportCfg)
	default:
		relayTrans, err = transport.NewUDPTransport(transportCfg)
	}
	if err != nil {
		log.Printf("[relay-direct] create transport: %v", err)
		return
	}
	defer relayTrans.Close()

	// UDP connection to forward target (persistent, single socket)
	fwdConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		log.Printf("[relay-direct] listen UDP for forward: %v", err)
		return
	}
	defer fwdConn.Close()

	clientRealIP := s.clientRealIP
	var lastClientPort uint16
	var portMu sync.Mutex

	// Downlink: forward target → transport → client
	go func() {
		buf := make([]byte, 65536)
		for s.running.Load() {
			n, _, err := fwdConn.ReadFromUDP(buf)
			if err != nil {
				if s.running.Load() {
					log.Printf("[relay-direct] forward read error: %v", err)
				}
				continue
			}
			if n == 0 {
				continue
			}

			portMu.Lock()
			dstPort := lastClientPort
			portMu.Unlock()

			if dstPort == 0 {
				continue // haven't seen client yet
			}

			// Direct send — no encrypt, no protocol
			if err := relayTrans.Send(buf[:n], clientRealIP, dstPort); err != nil {
				log.Printf("[relay-direct] send to client error: %v", err)
			}
		}
	}()

	// Uplink: transport (client SYN) → forward target
	for s.running.Load() {
		payload, srcIP, srcPort, err := relayTrans.Receive()
		if err != nil {
			if s.running.Load() {
				log.Printf("[relay-direct] recv error: %v", err)
			}
			continue
		}
		if len(payload) == 0 {
			continue
		}

		// Remember client port for responses
		portMu.Lock()
		lastClientPort = srcPort
		portMu.Unlock()

		_ = srcIP // already filtered by PeerSpoofIP in transport

		// Forward to target — no decrypt, no parse
		if _, err := fwdConn.WriteToUDP(payload, fwdAddr); err != nil {
			log.Printf("[relay-direct] forward write error: %v", err)
		}
	}
}

// ═══════════════════════════════════════════════════════════
// Tunnel-based server handlers (relay/forward via encrypted tunnel)
// ═══════════════════════════════════════════════════════════

// relayUDPConns stores the UDP forwarding connections for relay sessions.
var (
	relayConns   = make(map[uint32]*net.UDPConn)
	relayConnsMu sync.RWMutex
)

// handleInitRelay handles a tunnel-based UDP relay init request.
func (s *Server) handleInitRelay(pkt *protocol.Packet, clientSpoofIP net.IP, clientPort uint16) {
	log.Printf("INIT_RELAY session %d from spoof=%s port=%d", pkt.SessionID, clientSpoofIP, clientPort)

	forwardAddr := s.config.RelayForward
	if forwardAddr == "" {
		log.Printf("relay_forward not configured, rejecting session %d", pkt.SessionID)
		ackPkt := protocol.NewInitAckPacket(pkt.SessionID, false, "relay_forward not configured")
		s.sendPacket(ackPkt, s.clientRealIP, clientPort)
		return
	}

	fwdAddr, err := net.ResolveUDPAddr("udp4", forwardAddr)
	if err != nil {
		log.Printf("resolve relay forward %s: %v", forwardAddr, err)
		ackPkt := protocol.NewInitAckPacket(pkt.SessionID, false, err.Error())
		s.sendPacket(ackPkt, s.clientRealIP, clientPort)
		return
	}

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		log.Printf("relay udp listen: %v", err)
		ackPkt := protocol.NewInitAckPacket(pkt.SessionID, false, err.Error())
		s.sendPacket(ackPkt, s.clientRealIP, clientPort)
		return
	}

	relayConnsMu.Lock()
	relayConns[pkt.SessionID] = udpConn
	relayConnsMu.Unlock()

	sess := &ServerSession{
		ID:         pkt.SessionID,
		ClientAddr: clientSpoofIP,
		ClientPort: clientPort,
		Target:     "relay:" + forwardAddr,
		Created:    time.Now(),
		LastActive: time.Now(),
	}

	s.sessionsMu.Lock()
	s.sessions[pkt.SessionID] = sess
	s.sessionsMu.Unlock()

	ackPkt := protocol.NewInitAckPacket(pkt.SessionID, true, "relay connected")
	for i := 0; i < 3; i++ {
		s.sendPacket(ackPkt, s.clientRealIP, clientPort)
		if i < 2 {
			time.Sleep(20 * time.Millisecond)
		}
	}

	go s.pumpRelayToClient(sess, udpConn, fwdAddr)
}

func (s *Server) pumpRelayToClient(sess *ServerSession, udpConn *net.UDPConn, fwdAddr *net.UDPAddr) {
	defer func() {
		udpConn.Close()
		relayConnsMu.Lock()
		delete(relayConns, sess.ID)
		relayConnsMu.Unlock()
		s.removeSession(sess.ID)
	}()

	buf := make([]byte, 65536)
	idleTimeout := time.Duration(s.config.Performance.SessionTimeout) * time.Second
	if idleTimeout < 60*time.Second {
		idleTimeout = 60 * time.Second
	}

	for {
		udpConn.SetReadDeadline(time.Now().Add(idleTimeout))
		n, _, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				sess.mu.Lock()
				lastActive := sess.LastActive
				sess.mu.Unlock()
				if time.Since(lastActive) > idleTimeout {
					return
				}
				continue
			}
			return
		}

		sess.mu.Lock()
		sess.LastActive = time.Now()
		clientPort := sess.ClientPort
		sess.mu.Unlock()

		pkt := protocol.NewDataUDPPacket(sess.ID, buf[:n])
		if err := s.sendPacket(pkt, s.clientRealIP, clientPort); err != nil {
			return
		}
		s.bytesSent.Add(uint64(n))
	}
}

func (s *Server) handleDataUDP(pkt *protocol.Packet) {
	s.sessionsMu.RLock()
	sess, exists := s.sessions[pkt.SessionID]
	s.sessionsMu.RUnlock()
	if !exists {
		return
	}

	sess.mu.Lock()
	sess.LastActive = time.Now()
	sess.mu.Unlock()

	forwardAddr := s.config.RelayForward
	if forwardAddr == "" {
		return
	}
	fwdAddr, err := net.ResolveUDPAddr("udp4", forwardAddr)
	if err != nil {
		return
	}

	relayConnsMu.RLock()
	conn, ok := relayConns[pkt.SessionID]
	relayConnsMu.RUnlock()
	if !ok {
		return
	}

	if _, err := conn.WriteToUDP(pkt.Payload, fwdAddr); err != nil {
		log.Printf("[relay] forward write: %v", err)
	}
	s.bytesReceived.Add(uint64(len(pkt.Payload)))
}

// handleInitForward handles a TCP port-forward init request.
func (s *Server) handleInitForward(pkt *protocol.Packet, clientSpoofIP net.IP, clientPort uint16) {
	target := string(pkt.Payload)
	log.Printf("INIT_FORWARD session %d: target=%s from spoof=%s port=%d",
		pkt.SessionID, target, clientSpoofIP, clientPort)

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("[forward] dial %s: %v", target, err)
		ackPkt := protocol.NewInitAckPacket(pkt.SessionID, false, err.Error())
		s.sendPacket(ackPkt, s.clientRealIP, clientPort)
		return
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	sess := &ServerSession{
		ID:         pkt.SessionID,
		ClientAddr: clientSpoofIP,
		ClientPort: clientPort,
		Target:     target,
		TargetConn: conn,
		Created:    time.Now(),
		LastActive: time.Now(),
	}

	if s.config.Reliability.Enabled {
		sess.recvBuffer = NewRecvBuffer(nil, time.Duration(s.config.Reliability.AckIntervalMs)*time.Millisecond)
		retransmitTimeout := time.Duration(s.config.Reliability.RetransmitTimeoutMs) * time.Millisecond
		sess.sendBuffer = NewSendBuffer(
			s.config.Reliability.WindowSize,
			retransmitTimeout,
			func(seqNum uint32, data []byte) error {
				pkt := protocol.NewSeqDataPacket(sess.ID, seqNum, data)
				return s.sendPacket(pkt, s.clientRealIP, sess.ClientPort)
			},
		)
	}

	s.sessionsMu.Lock()
	s.sessions[pkt.SessionID] = sess
	s.sessionsMu.Unlock()

	ackPkt := protocol.NewInitAckPacket(pkt.SessionID, true, "connected")
	for i := 0; i < 3; i++ {
		s.sendPacket(ackPkt, s.clientRealIP, clientPort)
		if i < 2 {
			time.Sleep(20 * time.Millisecond)
		}
	}

	go s.pumpTargetToClient(sess)
}
