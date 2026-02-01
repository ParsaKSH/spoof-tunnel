package tunnel

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// TunnelConnPair manages the shared state between two connected TunnelConns
type TunnelConnPair struct {
	ch1       chan []byte
	ch2       chan []byte
	closed    atomic.Bool
	closeOnce sync.Once
	closeCh   chan struct{}
}

// TunnelConn implements net.Conn for tunnel sessions
type TunnelConn struct {
	pair    *TunnelConnPair
	readCh  chan []byte
	writeCh chan []byte
	readBuf []byte
	readMu  sync.Mutex

	// For net.Conn interface
	localAddr  net.Addr
	remoteAddr net.Addr
}

// TunnelAddr implements net.Addr
type TunnelAddr struct {
	network string
	address string
}

func (a TunnelAddr) Network() string { return a.network }
func (a TunnelAddr) String() string  { return a.address }

// NewTunnelConnPair creates a pair of connected TunnelConns
func NewTunnelConnPair(target string) (*TunnelConn, *TunnelConn) {
	// Create shared pair state
	pair := &TunnelConnPair{
		ch1:     make(chan []byte, 256),
		ch2:     make(chan []byte, 256),
		closeCh: make(chan struct{}),
	}

	local := &TunnelConn{
		pair:       pair,
		readCh:     pair.ch1,
		writeCh:    pair.ch2,
		localAddr:  TunnelAddr{"tunnel", "local"},
		remoteAddr: TunnelAddr{"tunnel", target},
	}

	remote := &TunnelConn{
		pair:       pair,
		readCh:     pair.ch2,
		writeCh:    pair.ch1,
		localAddr:  TunnelAddr{"tunnel", target},
		remoteAddr: TunnelAddr{"tunnel", "local"},
	}

	return local, remote
}

// Read reads data from the connection
func (c *TunnelConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	// First, drain any buffered data
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		c.readMu.Unlock()
		return n, nil
	}
	c.readMu.Unlock()

	// Check if closed - if so, try to drain channel first
	if c.pair.closed.Load() {
		// Non-blocking read to drain any remaining data
		select {
		case data, ok := <-c.readCh:
			if ok && len(data) > 0 {
				n := copy(b, data)
				if n < len(data) {
					c.readMu.Lock()
					c.readBuf = append(c.readBuf, data[n:]...)
					c.readMu.Unlock()
				}
				return n, nil
			}
		default:
			// Channel empty, return EOF
		}
		return 0, io.EOF
	}

	// Wait for new data - prioritize data over close signal
	select {
	case data, ok := <-c.readCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, data)
		if n < len(data) {
			c.readMu.Lock()
			c.readBuf = append(c.readBuf, data[n:]...)
			c.readMu.Unlock()
		}
		return n, nil

	case <-c.pair.closeCh:
		// Connection closing - but first drain any remaining data
		select {
		case data, ok := <-c.readCh:
			if ok && len(data) > 0 {
				n := copy(b, data)
				if n < len(data) {
					c.readMu.Lock()
					c.readBuf = append(c.readBuf, data[n:]...)
					c.readMu.Unlock()
				}
				return n, nil
			}
		default:
		}
		return 0, io.EOF
	}
}

// Write writes data to the connection
func (c *TunnelConn) Write(b []byte) (int, error) {
	if c.pair.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	// Make a copy to avoid data races
	data := make([]byte, len(b))
	copy(data, b)

	select {
	case c.writeCh <- data:
		return len(b), nil
	case <-c.pair.closeCh:
		return 0, io.ErrClosedPipe
	}
}

// Close closes the connection (and its pair)
func (c *TunnelConn) Close() error {
	c.pair.closeOnce.Do(func() {
		c.pair.closed.Store(true)
		close(c.pair.closeCh)
		// Don't close ch1/ch2 here - goroutines might still be writing
		// They'll be garbage collected when no longer referenced
	})
	return nil
}

// LocalAddr returns the local address
func (c *TunnelConn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr returns the remote address
func (c *TunnelConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// SetDeadline sets the deadline
func (c *TunnelConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets the read deadline
func (c *TunnelConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets the write deadline
func (c *TunnelConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// IsClosed returns whether the connection is closed
func (c *TunnelConn) IsClosed() bool {
	return c.pair.closed.Load()
}
