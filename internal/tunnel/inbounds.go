package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/ParsaKSH/spooftunnel/internal/config"
	"github.com/ParsaKSH/spooftunnel/internal/protocol"
	"github.com/ParsaKSH/spooftunnel/internal/transport"
)

// ═══════════════════════════════════════════════════════════
// Direct Relay — zero-overhead bypass (no encrypt/decrypt/session)
// ═══════════════════════════════════════════════════════════

// startDirectRelay starts a direct relay that bypasses the tunnel stack entirely.
// App traffic is read from a local UDP port and sent raw via a dedicated
// SynUDP transport to the server's relay port. No encryption, no protocol framing.
func (c *Client) startDirectRelay(listenAddr string, remotePort int) error {
	// Listen for app traffic (e.g. WireGuard)
	addr, err := net.ResolveUDPAddr("udp4", listenAddr)
	if err != nil {
		return fmt.Errorf("resolve relay addr: %w", err)
	}
	appConn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("listen relay: %w", err)
	}
	defer appConn.Close()

	// Create dedicated transport for relay (separate from tunnel transport)
	transportCfg := &transport.Config{
		SourceIP:    net.ParseIP(c.config.Spoof.SourceIP),
		SourceIPv6:  net.ParseIP(c.config.Spoof.SourceIPv6),
		ListenPort:  0, // dynamic
		PeerSpoofIP: net.ParseIP(c.config.Spoof.PeerSpoofIP),
		BufferSize:  c.config.Performance.BufferSize,
		MTU:         c.config.Performance.MTU,
	}

	var relayTrans transport.Transport
	switch c.config.Transport.Type {
	case config.TransportSynUDP:
		relayTrans, err = transport.NewSynUDPTransport(transportCfg)
	default:
		relayTrans, err = transport.NewUDPTransport(transportCfg)
	}
	if err != nil {
		return fmt.Errorf("create relay transport: %w", err)
	}
	defer relayTrans.Close()

	serverIP := c.serverIP
	serverPort := uint16(remotePort)

	log.Printf("[relay-direct] bypass active: %s → %s:%d (zero overhead)", listenAddr, serverIP, serverPort)

	// Track last app address for responses
	var lastAppAddr *net.UDPAddr
	var addrMu sync.Mutex

	stopCh := c.stopCh

	// Uplink: app → transport (raw, no encrypt)
	go func() {
		buf := make([]byte, 65536)
		for {
			select {
			case <-stopCh:
				return
			default:
			}

			n, appAddr, err := appConn.ReadFromUDP(buf)
			if err != nil {
				if c.running.Load() {
					log.Printf("[relay-direct] app read error: %v", err)
				}
				continue
			}
			if n == 0 {
				continue
			}

			addrMu.Lock()
			lastAppAddr = appAddr
			addrMu.Unlock()

			// Direct send — no encrypt, no protocol
			if err := relayTrans.Send(buf[:n], serverIP, serverPort); err != nil {
				log.Printf("[relay-direct] send error: %v", err)
			}
		}
	}()

	// Downlink: transport → app (raw, no decrypt)
	buf := make([]byte, 65536)
	for {
		select {
		case <-stopCh:
			return nil
		default:
		}

		payload, _, _, err := relayTrans.Receive()
		if err != nil {
			if c.running.Load() {
				log.Printf("[relay-direct] recv error: %v", err)
			}
			continue
		}
		if len(payload) == 0 {
			continue
		}
		_ = buf // suppress

		addrMu.Lock()
		addr := lastAppAddr
		addrMu.Unlock()

		if addr == nil {
			continue
		}

		if _, err := appConn.WriteToUDP(payload, addr); err != nil {
			log.Printf("[relay-direct] app write error: %v", err)
		}
	}
}

// ═══════════════════════════════════════════════════════════
// Tunnel-based Relay — goes through encrypt/decrypt/session stack
// (kept for non-direct relay, e.g. when remote_port is not set)
// ═══════════════════════════════════════════════════════════

// startRelayInbound starts a tunnel-based UDP relay inbound.
func (c *Client) startRelayInbound(listenAddr string) error {
	addr, err := net.ResolveUDPAddr("udp4", listenAddr)
	if err != nil {
		return fmt.Errorf("resolve relay addr: %w", err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("listen relay UDP: %w", err)
	}
	defer conn.Close()

	sessionID := c.generateSessionID()

	sess := &ClientSession{
		ID:         sessionID,
		Target:     "relay:" + listenAddr,
		Created:    time.Now(),
		LastActive: time.Now(),
		recvCh:     make(chan []byte, 512),
		uploadSeq:  1,
	}

	c.sessionsMu.Lock()
	c.sessions[sessionID] = sess
	c.sessionsMu.Unlock()

	initPkt := protocol.NewInitRelayPacket(sessionID)
	if err := c.sendPacket(initPkt); err != nil {
		c.removeSession(sessionID)
		return fmt.Errorf("send relay init: %w", err)
	}

	select {
	case data := <-sess.recvCh:
		pkt, err := protocol.Parse(data)
		if err != nil {
			c.removeSession(sessionID)
			return fmt.Errorf("parse relay init ack: %w", err)
		}
		if pkt.Type != protocol.PacketInitAck {
			c.removeSession(sessionID)
			return fmt.Errorf("expected INIT_ACK, got %s", protocol.TypeString(pkt.Type))
		}
		ok, msg := protocol.ParseInitAck(pkt.Payload)
		if !ok {
			c.removeSession(sessionID)
			return fmt.Errorf("relay init rejected: %s", msg)
		}
		log.Printf("[relay] session %d established", sessionID)

	case <-time.After(10 * time.Second):
		c.removeSession(sessionID)
		return fmt.Errorf("relay init timeout")

	case <-c.stopCh:
		c.removeSession(sessionID)
		return fmt.Errorf("client stopped")
	}

	var lastAppAddr *net.UDPAddr
	var addrMu sync.Mutex

	go func() {
		buf := make([]byte, 65536)
		for c.running.Load() {
			n, appAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if c.running.Load() {
					log.Printf("[relay] UDP read error: %v", err)
				}
				continue
			}
			if n == 0 {
				continue
			}

			addrMu.Lock()
			lastAppAddr = appAddr
			addrMu.Unlock()

			sess.mu.Lock()
			sess.LastActive = time.Now()
			sess.mu.Unlock()

			pkt := protocol.NewDataUDPPacket(sessionID, buf[:n])
			if err := c.sendPacket(pkt); err != nil {
				log.Printf("[relay] send error: %v", err)
			}
			c.bytesSent.Add(uint64(n))
		}
	}()

	for {
		select {
		case data, ok := <-sess.recvCh:
			if !ok {
				return nil
			}
			pkt, err := protocol.Parse(data)
			if err != nil {
				continue
			}

			sess.mu.Lock()
			sess.LastActive = time.Now()
			sess.mu.Unlock()

			switch pkt.Type {
			case protocol.PacketDataUDP:
				addrMu.Lock()
				addr := lastAppAddr
				addrMu.Unlock()
				if addr == nil {
					continue
				}
				if _, err := conn.WriteToUDP(pkt.Payload, addr); err != nil {
					log.Printf("[relay] UDP write error: %v", err)
				}
				c.bytesReceived.Add(uint64(len(pkt.Payload)))

			case protocol.PacketClose:
				return nil
			}

		case <-c.stopCh:
			return nil
		}
	}
}

// ═══════════════════════════════════════════════════════════
// TCP Port Forward inbound
// ═══════════════════════════════════════════════════════════

func (c *Client) startForwardInbound(listenAddr, target string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen forward TCP: %w", err)
	}
	defer ln.Close()

	for c.running.Load() {
		conn, err := ln.Accept()
		if err != nil {
			if c.running.Load() {
				log.Printf("[forward] accept error: %v", err)
			}
			continue
		}
		go c.handleForwardConn(conn, target)
	}
	return nil
}

func (c *Client) handleForwardConn(conn net.Conn, target string) {
	defer conn.Close()

	var buf [4]byte
	rand.Read(buf[:])
	sessionID := binary.BigEndian.Uint32(buf[:])

	sess := &ClientSession{
		ID:         sessionID,
		Target:     target,
		LocalConn:  conn,
		Created:    time.Now(),
		LastActive: time.Now(),
		recvCh:     make(chan []byte, 512),
		uploadSeq:  1,
	}

	c.sessionsMu.Lock()
	c.sessions[sessionID] = sess
	c.sessionsMu.Unlock()

	initPkt := protocol.NewInitForwardPacket(sessionID, target)
	if err := c.sendPacket(initPkt); err != nil {
		c.removeSession(sessionID)
		log.Printf("[forward] session %d init error: %v", sessionID, err)
		return
	}

	select {
	case data := <-sess.recvCh:
		pkt, err := protocol.Parse(data)
		if err != nil {
			c.removeSession(sessionID)
			return
		}
		if pkt.Type != protocol.PacketInitAck {
			c.removeSession(sessionID)
			return
		}
		ok, msg := protocol.ParseInitAck(pkt.Payload)
		if !ok {
			c.removeSession(sessionID)
			log.Printf("[forward] session %d rejected: %s", sessionID, msg)
			return
		}
		log.Printf("[forward] session %d connected to %s", sessionID, target)

	case <-time.After(10 * time.Second):
		c.removeSession(sessionID)
		log.Printf("[forward] session %d init timeout", sessionID)
		return

	case <-c.stopCh:
		c.removeSession(sessionID)
		return
	}

	c.streamSession(sess)
}
