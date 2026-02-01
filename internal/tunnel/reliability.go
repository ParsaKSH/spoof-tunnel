package tunnel

import (
	"sync"
	"time"
)

// SendBuffer manages packets waiting for acknowledgment (server-side)
// It implements sliding window and retransmission for reliable delivery
type SendBuffer struct {
	mu sync.Mutex

	// Packets waiting for ACK: seqNum -> (data, sendTime)
	pending map[uint32]*pendingPacket

	// Sequence tracking
	nextSeq   uint32 // Next sequence to use for new packets
	lastAcked uint32 // Last continuously ACKed sequence

	// Flow control
	windowSize    int           // Max in-flight packets
	retransmitAge time.Duration // How old a packet must be to retransmit

	// Callback for retransmitting packets
	retransmitFn func(seqNum uint32, data []byte) error
}

type pendingPacket struct {
	data     []byte
	sendTime time.Time
}

// NewSendBuffer creates a new send buffer
func NewSendBuffer(windowSize int, retransmitAge time.Duration, retransmitFn func(uint32, []byte) error) *SendBuffer {
	return &SendBuffer{
		pending:       make(map[uint32]*pendingPacket),
		nextSeq:       1, // Start from 1
		lastAcked:     0,
		windowSize:    windowSize,
		retransmitAge: retransmitAge,
		retransmitFn:  retransmitFn,
	}
}

// CanSend returns true if we can send more packets (window not full)
func (sb *SendBuffer) CanSend() bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return len(sb.pending) < sb.windowSize
}

// Send records a packet as sent and returns its sequence number
func (sb *SendBuffer) Send(data []byte) uint32 {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	seqNum := sb.nextSeq
	sb.nextSeq++

	// Store copy of data for potential retransmit
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	sb.pending[seqNum] = &pendingPacket{
		data:     dataCopy,
		sendTime: time.Now(),
	}

	return seqNum
}

// ProcessAck handles an ACK from client
// Returns list of seqNums that were acknowledged
func (sb *SendBuffer) ProcessAck(ackSeqNum uint32, recvBitmap uint64) []uint32 {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	var acked []uint32

	// Remove all packets up to ackSeqNum (contiguous ack)
	for seq := sb.lastAcked + 1; seq <= ackSeqNum; seq++ {
		if _, exists := sb.pending[seq]; exists {
			delete(sb.pending, seq)
			acked = append(acked, seq)
		}
	}
	sb.lastAcked = ackSeqNum

	// Process selective ACK bitmap (next 64 packets after ackSeqNum)
	for i := uint64(0); i < 64; i++ {
		if recvBitmap&(1<<i) != 0 {
			seq := ackSeqNum + 1 + uint32(i)
			if _, exists := sb.pending[seq]; exists {
				delete(sb.pending, seq)
				acked = append(acked, seq)
			}
		}
	}

	return acked
}

// GetRetransmitCandidates returns packets that need retransmission
func (sb *SendBuffer) GetRetransmitCandidates() []uint32 {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	now := time.Now()
	var candidates []uint32

	for seqNum, pkt := range sb.pending {
		if now.Sub(pkt.sendTime) >= sb.retransmitAge {
			candidates = append(candidates, seqNum)
		}
	}

	return candidates
}

// Retransmit sends a packet again and updates its send time
func (sb *SendBuffer) Retransmit(seqNum uint32) error {
	sb.mu.Lock()
	pkt, exists := sb.pending[seqNum]
	if !exists {
		sb.mu.Unlock()
		return nil // Already ACKed
	}
	data := pkt.data
	pkt.sendTime = time.Now() // Reset timer
	sb.mu.Unlock()

	return sb.retransmitFn(seqNum, data)
}

// Pending returns number of unacked packets
func (sb *SendBuffer) Pending() int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return len(sb.pending)
}

// RecvBuffer manages received packets and generates ACKs (client-side)
type RecvBuffer struct {
	mu sync.Mutex

	// Track received sequences
	received      map[uint32]bool // seqNum -> received?
	lastDelivered uint32          // Last contiguously delivered sequence

	// Output channel for ordered delivery
	deliverCh chan []byte

	// For generating ACKs
	ackInterval time.Duration
	lastAckTime time.Time
}

// NewRecvBuffer creates a new receive buffer
func NewRecvBuffer(deliverCh chan []byte, ackInterval time.Duration) *RecvBuffer {
	return &RecvBuffer{
		received:      make(map[uint32]bool),
		lastDelivered: 0,
		deliverCh:     deliverCh,
		ackInterval:   ackInterval,
	}
}

// Receive processes an incoming sequenced packet
// Returns true if this is a new packet (not duplicate)
func (rb *RecvBuffer) Receive(seqNum uint32, data []byte) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Check for duplicate
	if rb.received[seqNum] {
		return false
	}

	rb.received[seqNum] = true

	// Try to deliver in order
	// For simplicity, we deliver immediately if it's the next expected
	// In a more complex impl, we'd buffer out-of-order packets
	if seqNum == rb.lastDelivered+1 {
		rb.lastDelivered = seqNum

		// Try to deliver
		select {
		case rb.deliverCh <- data:
		default:
			// Channel full, might want to handle this
		}

		// Check if we can deliver more buffered packets
		// (simplified - real impl would buffer out-of-order packets)
	}

	return true
}

// ShouldSendAck returns true if it's time to send an ACK
func (rb *RecvBuffer) ShouldSendAck() bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return time.Since(rb.lastAckTime) >= rb.ackInterval
}

// GenerateAck creates ACK data
func (rb *RecvBuffer) GenerateAck() (ackSeqNum uint32, recvBitmap uint64) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.lastAckTime = time.Now()
	ackSeqNum = rb.lastDelivered

	// Build bitmap for next 64 sequences
	for i := uint32(1); i <= 64; i++ {
		seq := ackSeqNum + i
		if rb.received[seq] {
			recvBitmap |= (1 << (i - 1))
		}
	}

	return ackSeqNum, recvBitmap
}

// LastDelivered returns the last contiguously delivered sequence
func (rb *RecvBuffer) LastDelivered() uint32 {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.lastDelivered
}
