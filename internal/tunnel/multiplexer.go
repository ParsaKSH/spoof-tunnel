package tunnel

import (
	"encoding/binary"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ParsaKSH/spooftunnel/internal/protocol"
)

// Multiplexer handles multiple streams over a single tunnel connection
// This eliminates per-TCP-connection INIT/INIT_ACK overhead
type Multiplexer struct {
	// Stream management
	streams   map[uint32]*Stream
	streamsMu sync.RWMutex

	// Sequence tracking
	nextStreamID uint32

	// Callback for sending data through tunnel
	sendFn func(pkt *protocol.Packet) error

	// Session ID for the master tunnel
	sessionID uint32

	// Stats
	activeStreams atomic.Int32
}

// Stream represents a single multiplexed connection
type Stream struct {
	ID         uint32
	Target     string
	LocalConn  net.Conn
	Created    time.Time
	LastActive time.Time

	// Data channel for received data
	recvCh chan []byte

	// State
	closed atomic.Bool
	mu     sync.Mutex
}

// Multiplexed packet types (inside tunnel DATA packet payload)
const (
	MuxStreamOpen  byte = 0x01 // Open new stream: [StreamID:4][TargetLen:2][Target:...]
	MuxStreamData  byte = 0x02 // Stream data: [StreamID:4][Data:...]
	MuxStreamClose byte = 0x03 // Close stream: [StreamID:4]
	MuxStreamAck   byte = 0x04 // Stream opened ack: [StreamID:4][Success:1][MsgLen:2][Msg:...]
)

// NewMultiplexer creates a new stream multiplexer
func NewMultiplexer(sessionID uint32, sendFn func(pkt *protocol.Packet) error) *Multiplexer {
	return &Multiplexer{
		streams:      make(map[uint32]*Stream),
		nextStreamID: 1,
		sendFn:       sendFn,
		sessionID:    sessionID,
	}
}

// OpenStream opens a new stream to the target
func (m *Multiplexer) OpenStream(target string, localConn net.Conn) (*Stream, error) {
	streamID := atomic.AddUint32(&m.nextStreamID, 1)

	stream := &Stream{
		ID:         streamID,
		Target:     target,
		LocalConn:  localConn,
		Created:    time.Now(),
		LastActive: time.Now(),
		recvCh:     make(chan []byte, 256),
	}

	m.streamsMu.Lock()
	m.streams[streamID] = stream
	m.streamsMu.Unlock()
	m.activeStreams.Add(1)

	// Send stream open packet
	payload := m.encodeStreamOpen(streamID, target)
	pkt := protocol.NewDataPacket(m.sessionID, payload)
	if err := m.sendFn(pkt); err != nil {
		m.removeStream(streamID)
		return nil, err
	}

	log.Printf("[MUX] opened stream %d to %s", streamID, target)
	return stream, nil
}

// SendData sends data on a stream
func (m *Multiplexer) SendData(streamID uint32, data []byte) error {
	payload := m.encodeStreamData(streamID, data)
	pkt := protocol.NewDataPacket(m.sessionID, payload)
	return m.sendFn(pkt)
}

// CloseStream closes a stream
func (m *Multiplexer) CloseStream(streamID uint32) {
	m.streamsMu.Lock()
	stream, exists := m.streams[streamID]
	m.streamsMu.Unlock()

	if !exists {
		return
	}

	if stream.closed.Swap(true) {
		return // Already closed
	}

	// Send close packet
	payload := m.encodeStreamClose(streamID)
	pkt := protocol.NewDataPacket(m.sessionID, payload)
	m.sendFn(pkt)

	m.removeStream(streamID)
	log.Printf("[MUX] closed stream %d", streamID)
}

// HandleData processes incoming multiplexed data
func (m *Multiplexer) HandleData(payload []byte) {
	if len(payload) < 5 {
		return
	}

	muxType := payload[0]
	streamID := binary.BigEndian.Uint32(payload[1:5])
	data := payload[5:]

	switch muxType {
	case MuxStreamData:
		m.streamsMu.RLock()
		stream, exists := m.streams[streamID]
		m.streamsMu.RUnlock()

		if !exists || stream.closed.Load() {
			return
		}

		stream.mu.Lock()
		stream.LastActive = time.Now()
		stream.mu.Unlock()

		// Deliver to stream
		select {
		case stream.recvCh <- data:
		default:
			log.Printf("[MUX] stream %d buffer full, dropping", streamID)
		}

	case MuxStreamClose:
		m.removeStream(streamID)

	case MuxStreamAck:
		// Stream open acknowledgment
		if len(data) < 1 {
			return
		}
		success := data[0] == 1
		var msg string
		if len(data) >= 3 {
			msgLen := binary.BigEndian.Uint16(data[1:3])
			if len(data) >= 3+int(msgLen) {
				msg = string(data[3 : 3+msgLen])
			}
		}
		log.Printf("[MUX] stream %d ack: success=%v msg=%s", streamID, success, msg)
	}
}

// removeStream removes a stream from the map
func (m *Multiplexer) removeStream(streamID uint32) {
	m.streamsMu.Lock()
	stream, exists := m.streams[streamID]
	if exists {
		delete(m.streams, streamID)
		m.activeStreams.Add(-1)
		if stream.LocalConn != nil {
			stream.LocalConn.Close()
		}
		close(stream.recvCh)
	}
	m.streamsMu.Unlock()
}

// GetStream returns a stream by ID
func (m *Multiplexer) GetStream(streamID uint32) *Stream {
	m.streamsMu.RLock()
	defer m.streamsMu.RUnlock()
	return m.streams[streamID]
}

// ActiveStreams returns number of active streams
func (m *Multiplexer) ActiveStreams() int {
	return int(m.activeStreams.Load())
}

// Close closes all streams
func (m *Multiplexer) Close() {
	m.streamsMu.Lock()
	streams := make([]*Stream, 0, len(m.streams))
	for _, s := range m.streams {
		streams = append(streams, s)
	}
	m.streamsMu.Unlock()

	for _, s := range streams {
		m.CloseStream(s.ID)
	}
}

// Encoding helpers

func (m *Multiplexer) encodeStreamOpen(streamID uint32, target string) []byte {
	payload := make([]byte, 1+4+2+len(target))
	payload[0] = MuxStreamOpen
	binary.BigEndian.PutUint32(payload[1:5], streamID)
	binary.BigEndian.PutUint16(payload[5:7], uint16(len(target)))
	copy(payload[7:], target)
	return payload
}

func (m *Multiplexer) encodeStreamData(streamID uint32, data []byte) []byte {
	payload := make([]byte, 1+4+len(data))
	payload[0] = MuxStreamData
	binary.BigEndian.PutUint32(payload[1:5], streamID)
	copy(payload[5:], data)
	return payload
}

func (m *Multiplexer) encodeStreamClose(streamID uint32) []byte {
	payload := make([]byte, 1+4)
	payload[0] = MuxStreamClose
	binary.BigEndian.PutUint32(payload[1:5], streamID)
	return payload
}

// Server-side multiplexer

// ServerMultiplexer handles multiplexed streams on server side
type ServerMultiplexer struct {
	// Stream management
	streams   map[uint32]*ServerStream
	streamsMu sync.RWMutex

	// Callback for sending data through tunnel
	sendFn func(pkt *protocol.Packet, clientIP net.IP, clientPort uint16) error

	// Session info
	sessionID  uint32
	clientIP   net.IP
	clientPort uint16

	// Stats
	activeStreams atomic.Int32
}

// ServerStream represents a server-side multiplexed stream
type ServerStream struct {
	ID         uint32
	Target     string
	TargetConn net.Conn
	Created    time.Time
	LastActive time.Time

	// State
	closed atomic.Bool
	mu     sync.Mutex
}

// NewServerMultiplexer creates a server-side multiplexer
func NewServerMultiplexer(sessionID uint32, clientIP net.IP, clientPort uint16,
	sendFn func(pkt *protocol.Packet, clientIP net.IP, clientPort uint16) error) *ServerMultiplexer {
	return &ServerMultiplexer{
		streams:    make(map[uint32]*ServerStream),
		sendFn:     sendFn,
		sessionID:  sessionID,
		clientIP:   clientIP,
		clientPort: clientPort,
	}
}

// HandleData processes incoming multiplexed data from client
func (sm *ServerMultiplexer) HandleData(payload []byte) {
	if len(payload) < 5 {
		return
	}

	muxType := payload[0]
	streamID := binary.BigEndian.Uint32(payload[1:5])
	data := payload[5:]

	switch muxType {
	case MuxStreamOpen:
		sm.handleStreamOpen(streamID, data)

	case MuxStreamData:
		sm.handleStreamData(streamID, data)

	case MuxStreamClose:
		sm.removeStream(streamID)
	}
}

func (sm *ServerMultiplexer) handleStreamOpen(streamID uint32, data []byte) {
	if len(data) < 2 {
		return
	}
	targetLen := binary.BigEndian.Uint16(data[0:2])
	if len(data) < 2+int(targetLen) {
		return
	}
	target := string(data[2 : 2+targetLen])

	// Connect to target
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("[MUX] stream %d: dial %s failed: %v", streamID, target, err)
		sm.sendStreamAck(streamID, false, err.Error())
		return
	}

	// Create stream
	stream := &ServerStream{
		ID:         streamID,
		Target:     target,
		TargetConn: conn,
		Created:    time.Now(),
		LastActive: time.Now(),
	}

	sm.streamsMu.Lock()
	sm.streams[streamID] = stream
	sm.streamsMu.Unlock()
	sm.activeStreams.Add(1)

	// Send ack
	sm.sendStreamAck(streamID, true, "connected")

	// Start reading from target
	go sm.pumpTargetToClient(stream)

	log.Printf("[MUX] stream %d: connected to %s", streamID, target)
}

func (sm *ServerMultiplexer) handleStreamData(streamID uint32, data []byte) {
	sm.streamsMu.RLock()
	stream, exists := sm.streams[streamID]
	sm.streamsMu.RUnlock()

	if !exists || stream.closed.Load() {
		return
	}

	stream.mu.Lock()
	stream.LastActive = time.Now()
	stream.mu.Unlock()

	// Write to target
	if _, err := stream.TargetConn.Write(data); err != nil {
		log.Printf("[MUX] stream %d: write error: %v", streamID, err)
		sm.removeStream(streamID)
	}
}

func (sm *ServerMultiplexer) pumpTargetToClient(stream *ServerStream) {
	defer sm.removeStream(stream.ID)

	buf := make([]byte, 4096)
	for {
		n, err := stream.TargetConn.Read(buf)
		if n > 0 {
			stream.mu.Lock()
			stream.LastActive = time.Now()
			stream.mu.Unlock()

			// Send data back through mux
			payload := make([]byte, 1+4+n)
			payload[0] = MuxStreamData
			binary.BigEndian.PutUint32(payload[1:5], stream.ID)
			copy(payload[5:], buf[:n])

			pkt := protocol.NewDataPacket(sm.sessionID, payload)
			if err := sm.sendFn(pkt, sm.clientIP, sm.clientPort); err != nil {
				log.Printf("[MUX] stream %d: send error: %v", stream.ID, err)
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (sm *ServerMultiplexer) sendStreamAck(streamID uint32, success bool, msg string) {
	payload := make([]byte, 1+4+1+2+len(msg))
	payload[0] = MuxStreamAck
	binary.BigEndian.PutUint32(payload[1:5], streamID)
	if success {
		payload[5] = 1
	}
	binary.BigEndian.PutUint16(payload[6:8], uint16(len(msg)))
	copy(payload[8:], msg)

	pkt := protocol.NewDataPacket(sm.sessionID, payload)
	sm.sendFn(pkt, sm.clientIP, sm.clientPort)
}

func (sm *ServerMultiplexer) removeStream(streamID uint32) {
	sm.streamsMu.Lock()
	stream, exists := sm.streams[streamID]
	if exists {
		delete(sm.streams, streamID)
		sm.activeStreams.Add(-1)
		if stream.TargetConn != nil {
			stream.TargetConn.Close()
		}
	}
	sm.streamsMu.Unlock()

	// Send close to client
	payload := make([]byte, 1+4)
	payload[0] = MuxStreamClose
	binary.BigEndian.PutUint32(payload[1:5], streamID)
	pkt := protocol.NewDataPacket(sm.sessionID, payload)
	sm.sendFn(pkt, sm.clientIP, sm.clientPort)
}

// ActiveStreams returns number of active streams
func (sm *ServerMultiplexer) ActiveStreams() int {
	return int(sm.activeStreams.Load())
}

// Close closes all streams
func (sm *ServerMultiplexer) Close() {
	sm.streamsMu.Lock()
	streams := make([]*ServerStream, 0, len(sm.streams))
	for _, s := range sm.streams {
		streams = append(streams, s)
	}
	sm.streamsMu.Unlock()

	for _, s := range streams {
		sm.removeStream(s.ID)
	}
}
