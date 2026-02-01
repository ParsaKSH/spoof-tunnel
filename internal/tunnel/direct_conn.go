package tunnel

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DirectConn provides a high-performance connection for tunnel sessions.
// Unlike TunnelConn which uses channels, DirectConn allows direct writes
// to the underlying TCP socket for maximum download throughput.
type DirectConn struct {
	// Real TCP connection to SOCKS5 client (for download writes)
	tcpConn net.Conn

	// Upload data channel (client app -> tunnel -> server)
	uploadCh chan []byte

	// State
	closed    atomic.Bool
	closeOnce sync.Once
	closeCh   chan struct{}

	// Buffered reader for uploads
	readBuf []byte
	readMu  sync.Mutex

	// For net.Conn interface
	target string
}

// NewDirectConn creates a new DirectConn wrapping a real TCP connection
func NewDirectConn(tcpConn net.Conn, target string) *DirectConn {
	return &DirectConn{
		tcpConn:  tcpConn,
		uploadCh: make(chan []byte, 512), // Larger buffer for uploads
		closeCh:  make(chan struct{}),
		target:   target,
	}
}

// WriteDownload writes download data DIRECTLY to the TCP socket
// This bypasses all channels for maximum throughput
func (c *DirectConn) WriteDownload(data []byte) (int, error) {
	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	return c.tcpConn.Write(data)
}

// Read reads upload data from the TCP socket.
// This is called by the tunnel to get data to send to the server.
func (c *DirectConn) Read(b []byte) (int, error) {
	// First drain any buffered data
	c.readMu.Lock()
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		c.readMu.Unlock()
		return n, nil
	}
	c.readMu.Unlock()

	if c.closed.Load() {
		return 0, io.EOF
	}

	// Read directly from TCP socket
	return c.tcpConn.Read(b)
}

// Write is for compatibility - it should not be used for downloads
// Downloads should use WriteDownload for direct writes
func (c *DirectConn) Write(b []byte) (int, error) {
	// This is the upload path - write to upload channel
	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	data := make([]byte, len(b))
	copy(data, b)

	select {
	case c.uploadCh <- data:
		return len(b), nil
	case <-c.closeCh:
		return 0, io.ErrClosedPipe
	}
}

// GetUploadCh returns the upload channel for the tunnel to read from
func (c *DirectConn) GetUploadCh() <-chan []byte {
	return c.uploadCh
}

// Close closes the connection
func (c *DirectConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.closeCh)
		c.tcpConn.Close()
	})
	return nil
}

// IsClosed returns whether the connection is closed
func (c *DirectConn) IsClosed() bool {
	return c.closed.Load()
}

// TCP returns the underlying TCP connection
func (c *DirectConn) TCP() net.Conn {
	return c.tcpConn
}

// LocalAddr returns the local address
func (c *DirectConn) LocalAddr() net.Addr {
	return c.tcpConn.LocalAddr()
}

// RemoteAddr returns the remote address
func (c *DirectConn) RemoteAddr() net.Addr {
	return c.tcpConn.RemoteAddr()
}

// SetDeadline sets the deadline
func (c *DirectConn) SetDeadline(t time.Time) error {
	return c.tcpConn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline
func (c *DirectConn) SetReadDeadline(t time.Time) error {
	return c.tcpConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline
func (c *DirectConn) SetWriteDeadline(t time.Time) error {
	return c.tcpConn.SetWriteDeadline(t)
}
