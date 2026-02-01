package socks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// SOCKS5 constants
const (
	Version5 = 0x05

	// Auth methods
	AuthNone     = 0x00
	AuthPassword = 0x02
	AuthNoAccept = 0xFF

	// Commands
	CmdConnect = 0x01
	CmdBind    = 0x02
	CmdUDP     = 0x03

	// Address types
	AddrIPv4   = 0x01
	AddrDomain = 0x03
	AddrIPv6   = 0x04

	// Reply codes
	ReplySuccess          = 0x00
	ReplyGeneralFailure   = 0x01
	ReplyNotAllowed       = 0x02
	ReplyNetUnreachable   = 0x03
	ReplyHostUnreachable  = 0x04
	ReplyConnRefused      = 0x05
	ReplyTTLExpired       = 0x06
	ReplyCmdNotSupported  = 0x07
	ReplyAddrNotSupported = 0x08
)

var (
	ErrUnsupportedVersion = errors.New("unsupported SOCKS version")
	ErrNoAcceptableAuth   = errors.New("no acceptable auth method")
	ErrUnsupportedCommand = errors.New("unsupported command")
	ErrInvalidAddress     = errors.New("invalid address")
)

// ConnectHandler is called when a CONNECT request is received
// It should return a connection to forward data or an error
type ConnectHandler func(target string) (net.Conn, error)

// StreamHandler is called when a CONNECT request is received.
// It receives the actual TCP connection and handles all forwarding internally.
// This allows for direct writes to the TCP socket for maximum throughput.
// Returns an error if the connection fails, or nil when the session ends.
type StreamHandler func(target string, tcpConn net.Conn) error

// Server is a SOCKS5 proxy server
type Server struct {
	listener      net.Listener
	handler       ConnectHandler
	streamHandler StreamHandler // New: for direct TCP access

	// Configuration
	timeout     time.Duration
	readTimeout time.Duration

	// State
	closed bool
	mu     sync.Mutex
	wg     sync.WaitGroup

	// Buffer pool
	bufPool sync.Pool
}

// NewServer creates a new SOCKS5 server
func NewServer(listenAddr string, handler ConnectHandler) (*Server, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	return &Server{
		listener:    ln,
		handler:     handler,
		timeout:     30 * time.Second,
		readTimeout: 10 * time.Second,
		bufPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 32*1024)
				return &buf
			},
		},
	}, nil
}

// NewStreamServer creates a new SOCKS5 server with a StreamHandler.
// StreamHandler receives the actual TCP connection for direct writes,
// bypassing channel overhead for maximum download throughput.
func NewStreamServer(listenAddr string, streamHandler StreamHandler) (*Server, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	return &Server{
		listener:      ln,
		streamHandler: streamHandler,
		timeout:       30 * time.Second,
		readTimeout:   10 * time.Second,
		bufPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 32*1024)
				return &buf
			},
		},
	}, nil
}

// SetTimeout sets the connection timeout
func (s *Server) SetTimeout(d time.Duration) {
	s.timeout = d
}

// Addr returns the server's listen address
func (s *Server) Addr() net.Addr {
	return s.listener.Addr()
}

// Serve starts accepting connections
func (s *Server) Serve() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn)
		}()
	}
}

// Close closes the server
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	err := s.listener.Close()
	s.wg.Wait()
	return err
}

func (s *Server) handleConnection(conn net.Conn) {
	// Set initial timeout for handshake
	_ = conn.SetDeadline(time.Now().Add(s.readTimeout))

	// Handle auth negotiation
	if err := s.handleAuth(conn); err != nil {
		conn.Close()
		return
	}

	// Handle request
	target, err := s.handleRequest(conn)
	if err != nil {
		conn.Close()
		return
	}

	// Clear deadline for data forwarding
	_ = conn.SetDeadline(time.Time{})

	// Use streamHandler if available (new high-performance path)
	if s.streamHandler != nil {
		// StreamHandler takes full ownership of the connection
		// It handles both sending success reply and all forwarding
		s.sendReply(conn, ReplySuccess, nil)
		if err := s.streamHandler(target, conn); err != nil {
			// StreamHandler is responsible for closing conn
		}
		return
	}

	// Legacy path: use ConnectHandler and io.CopyBuffer
	remote, err := s.handler(target)
	if err != nil {
		s.sendReply(conn, ReplyHostUnreachable, nil)
		conn.Close()
		return
	}
	defer remote.Close()
	defer conn.Close()

	// Send success reply
	s.sendReply(conn, ReplySuccess, remote.LocalAddr())

	// Forward data bidirectionally
	s.forward(conn, remote)
}

func (s *Server) handleAuth(conn net.Conn) error {
	// Read version + num methods
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	if buf[0] != Version5 {
		return ErrUnsupportedVersion
	}

	// Read methods
	numMethods := int(buf[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// Check for no-auth method
	hasNoAuth := false
	for _, m := range methods {
		if m == AuthNone {
			hasNoAuth = true
			break
		}
	}

	if !hasNoAuth {
		conn.Write([]byte{Version5, AuthNoAccept})
		return ErrNoAcceptableAuth
	}

	// Accept no-auth
	_, err := conn.Write([]byte{Version5, AuthNone})
	return err
}

func (s *Server) handleRequest(conn net.Conn) (string, error) {
	// Read request header: VER, CMD, RSV, ATYP
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", err
	}

	if buf[0] != Version5 {
		return "", ErrUnsupportedVersion
	}

	cmd := buf[1]
	atyp := buf[3]

	if cmd != CmdConnect {
		s.sendReply(conn, ReplyCmdNotSupported, nil)
		return "", ErrUnsupportedCommand
	}

	// Parse address
	var host string
	switch atyp {
	case AddrIPv4:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", err
		}
		host = net.IP(ipBuf).String()

	case AddrIPv6:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", err
		}
		host = net.IP(ipBuf).String()

	case AddrDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}
		domainLen := int(lenBuf[0])
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return "", err
		}
		host = string(domainBuf)

	default:
		s.sendReply(conn, ReplyAddrNotSupported, nil)
		return "", ErrInvalidAddress
	}

	// Read port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func (s *Server) sendReply(conn net.Conn, code byte, bindAddr net.Addr) {
	// Build reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
	reply := make([]byte, 10)
	reply[0] = Version5
	reply[1] = code
	reply[2] = 0x00 // Reserved
	reply[3] = AddrIPv4

	if bindAddr != nil {
		if tcpAddr, ok := bindAddr.(*net.TCPAddr); ok {
			ip := tcpAddr.IP.To4()
			if ip != nil {
				copy(reply[4:8], ip)
				binary.BigEndian.PutUint16(reply[8:10], uint16(tcpAddr.Port))
			}
		}
	}

	conn.Write(reply)
}

func (s *Server) forward(client, remote net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Remote (upload)
	go func() {
		defer wg.Done()
		bufPtr := s.bufPool.Get().(*[]byte)
		defer s.bufPool.Put(bufPtr)
		io.CopyBuffer(remote, client, *bufPtr)
		// Don't close anything when upload finishes - download may still be in progress
	}()

	// Remote -> Client (download)
	go func() {
		defer wg.Done()
		bufPtr := s.bufPool.Get().(*[]byte)
		defer s.bufPool.Put(bufPtr)
		io.CopyBuffer(client, remote, *bufPtr)
		// When download finishes, we can close client write side
	}()

	// Wait for BOTH directions to complete
	wg.Wait()

	// Now close both connections
	client.Close()
	remote.Close()
}

// ParseAddress parses a SOCKS5 address from bytes
func ParseAddress(data []byte) (host string, port uint16, bytesRead int, err error) {
	if len(data) < 2 {
		return "", 0, 0, ErrInvalidAddress
	}

	atyp := data[0]
	switch atyp {
	case AddrIPv4:
		if len(data) < 7 {
			return "", 0, 0, ErrInvalidAddress
		}
		host = net.IP(data[1:5]).String()
		port = binary.BigEndian.Uint16(data[5:7])
		bytesRead = 7

	case AddrIPv6:
		if len(data) < 19 {
			return "", 0, 0, ErrInvalidAddress
		}
		host = net.IP(data[1:17]).String()
		port = binary.BigEndian.Uint16(data[17:19])
		bytesRead = 19

	case AddrDomain:
		if len(data) < 2 {
			return "", 0, 0, ErrInvalidAddress
		}
		domainLen := int(data[1])
		if len(data) < 2+domainLen+2 {
			return "", 0, 0, ErrInvalidAddress
		}
		host = string(data[2 : 2+domainLen])
		port = binary.BigEndian.Uint16(data[2+domainLen : 2+domainLen+2])
		bytesRead = 2 + domainLen + 2

	default:
		return "", 0, 0, ErrInvalidAddress
	}

	return host, port, bytesRead, nil
}

// BuildAddress builds a SOCKS5 address from host and port
func BuildAddress(host string, port uint16) []byte {
	ip := net.ParseIP(host)

	var data []byte
	if ip != nil {
		ip4 := ip.To4()
		if ip4 != nil {
			// IPv4
			data = make([]byte, 7)
			data[0] = AddrIPv4
			copy(data[1:5], ip4)
			binary.BigEndian.PutUint16(data[5:7], port)
		} else {
			// IPv6
			data = make([]byte, 19)
			data[0] = AddrIPv6
			copy(data[1:17], ip.To16())
			binary.BigEndian.PutUint16(data[17:19], port)
		}
	} else {
		// Domain
		data = make([]byte, 2+len(host)+2)
		data[0] = AddrDomain
		data[1] = byte(len(host))
		copy(data[2:], host)
		binary.BigEndian.PutUint16(data[2+len(host):], port)
	}

	return data
}
