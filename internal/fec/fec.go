package fec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/klauspost/reedsolomon"
)

var (
	ErrInvalidConfig    = errors.New("invalid FEC configuration")
	ErrGroupNotComplete = errors.New("FEC group not complete")
	ErrTooManyLost      = errors.New("too many packets lost for recovery")
	ErrInvalidShardIdx  = errors.New("invalid shard index")
)

// Shard header format:
// [GroupID:4][ShardIdx:1][TotalShards:1][DataShards:1][OrigLensSize:1][OrigLens:2*DataShards][Payload:...]
// OrigLens contains the original length of each data shard so recovery knows the true sizes
const ShardHeaderBaseSize = 8 // Without OrigLens array

// Encoder handles FEC encoding of packets
type Encoder struct {
	mu           sync.Mutex
	dataShards   int
	parityShards int
	totalShards  int
	encoder      reedsolomon.Encoder

	// Current group being built
	groupID     uint32
	shardBuf    [][]byte // Accumulates data shards
	shardLens   []int    // Original lengths of each shard
	maxShardLen int      // Max shard length in current group
}

// NewEncoder creates a new FEC encoder
func NewEncoder(dataShards, parityShards int) (*Encoder, error) {
	if dataShards < 1 || parityShards < 1 {
		return nil, ErrInvalidConfig
	}

	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("create reed-solomon encoder: %w", err)
	}

	totalShards := dataShards + parityShards

	return &Encoder{
		dataShards:   dataShards,
		parityShards: parityShards,
		totalShards:  totalShards,
		encoder:      enc,
		groupID:      0,
		shardBuf:     make([][]byte, 0, dataShards),
		shardLens:    make([]int, 0, dataShards),
	}, nil
}

// AddPacket adds a packet to the current FEC group
// Returns encoded shards when the group is complete (data + parity shards)
// Returns nil if more packets are needed to complete the group
func (e *Encoder) AddPacket(data []byte) ([][]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Track original length
	e.shardLens = append(e.shardLens, len(data))
	if len(data) > e.maxShardLen {
		e.maxShardLen = len(data)
	}

	// Store data
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	e.shardBuf = append(e.shardBuf, dataCopy)

	// Check if we have enough data shards
	if len(e.shardBuf) < e.dataShards {
		return nil, nil // Need more packets
	}

	// We have enough data shards, generate parity
	return e.encodeGroup()
}

// Flush forces encoding of remaining packets even if group is not full
// Pads with empty shards if necessary
func (e *Encoder) Flush() ([][]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.shardBuf) == 0 {
		return nil, nil
	}

	// Pad with empty shards
	for len(e.shardBuf) < e.dataShards {
		e.shardLens = append(e.shardLens, 0)
		e.shardBuf = append(e.shardBuf, []byte{})
	}

	return e.encodeGroup()
}

// encodeGroup generates parity shards and returns all shards with headers
// Must be called with lock held
func (e *Encoder) encodeGroup() ([][]byte, error) {
	// Pad all shards to same length
	shards := make([][]byte, e.totalShards)
	for i := 0; i < e.dataShards; i++ {
		shards[i] = make([]byte, e.maxShardLen)
		copy(shards[i], e.shardBuf[i])
	}

	// Allocate parity shards
	for i := e.dataShards; i < e.totalShards; i++ {
		shards[i] = make([]byte, e.maxShardLen)
	}

	// Generate parity
	if err := e.encoder.Encode(shards); err != nil {
		return nil, fmt.Errorf("encode parity: %w", err)
	}

	// Create output with headers
	result := make([][]byte, e.totalShards)
	for i := 0; i < e.totalShards; i++ {
		result[i] = e.makeShardPacket(e.groupID, byte(i), shards[i])
	}

	// Reset for next group
	e.groupID++
	e.shardBuf = e.shardBuf[:0]
	e.shardLens = e.shardLens[:0]
	e.maxShardLen = 0

	return result, nil
}

// makeShardPacket creates a shard packet with header including all origLens
func (e *Encoder) makeShardPacket(groupID uint32, shardIdx byte, payload []byte) []byte {
	origLensSize := e.dataShards * 2
	headerSize := ShardHeaderBaseSize + origLensSize
	pkt := make([]byte, headerSize+len(payload))

	binary.BigEndian.PutUint32(pkt[0:4], groupID)
	pkt[4] = shardIdx
	pkt[5] = byte(e.totalShards)
	pkt[6] = byte(e.dataShards)
	pkt[7] = byte(origLensSize)

	// Write all original lengths
	for i := 0; i < e.dataShards; i++ {
		binary.BigEndian.PutUint16(pkt[ShardHeaderBaseSize+i*2:], uint16(e.shardLens[i]))
	}

	copy(pkt[headerSize:], payload)
	return pkt
}

// PendingCount returns the number of packets waiting to form a complete group
func (e *Encoder) PendingCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.shardBuf)
}

// Decoder handles FEC decoding and packet recovery
type Decoder struct {
	mu           sync.Mutex
	dataShards   int
	parityShards int
	decoder      reedsolomon.Encoder

	// Groups being assembled: groupID -> group
	groups map[uint32]*decoderGroup

	// Cleanup old groups
	maxGroups int
}

type decoderGroup struct {
	shards      [][]byte // All shards (data + parity), nil if not received
	origLens    []uint16 // Original lengths for data shards
	received    int      // Count of received shards
	totalShards int
	dataShards  int
	maxLen      int // Max shard payload length
}

// NewDecoder creates a new FEC decoder
func NewDecoder(dataShards, parityShards int) (*Decoder, error) {
	if dataShards < 1 || parityShards < 1 {
		return nil, ErrInvalidConfig
	}

	dec, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("create reed-solomon decoder: %w", err)
	}

	return &Decoder{
		dataShards:   dataShards,
		parityShards: parityShards,
		decoder:      dec,
		groups:       make(map[uint32]*decoderGroup),
		maxGroups:    1000, // Keep at most 1000 incomplete groups
	}, nil
}

// AddShard adds a received shard to the decoder
// Returns recovered data packets if group can be reconstructed
// The first return value is the original packet data (if this is a data shard)
// The second return value is recovered packets from reconstruction (if any)
func (d *Decoder) AddShard(shardData []byte) (original []byte, recovered [][]byte, err error) {
	if len(shardData) < ShardHeaderBaseSize {
		return nil, nil, errors.New("shard too small")
	}

	// Parse header
	groupID := binary.BigEndian.Uint32(shardData[0:4])
	shardIdx := int(shardData[4])
	totalShards := int(shardData[5])
	dataShards := int(shardData[6])
	origLensSize := int(shardData[7])

	headerSize := ShardHeaderBaseSize + origLensSize
	if len(shardData) < headerSize {
		return nil, nil, errors.New("shard too small for header")
	}

	// Parse all original lengths
	origLens := make([]uint16, dataShards)
	for i := 0; i < dataShards; i++ {
		origLens[i] = binary.BigEndian.Uint16(shardData[ShardHeaderBaseSize+i*2:])
	}

	payload := shardData[headerSize:]

	d.mu.Lock()
	defer d.mu.Unlock()

	// Get or create group
	group, exists := d.groups[groupID]
	if !exists {
		group = &decoderGroup{
			shards:      make([][]byte, totalShards),
			origLens:    origLens, // Use origLens from first shard received
			totalShards: totalShards,
			dataShards:  dataShards,
		}
		d.groups[groupID] = group

		// Cleanup old groups if too many
		if len(d.groups) > d.maxGroups {
			d.cleanupOldGroups(groupID)
		}
	}

	// Validate shard index
	if shardIdx >= totalShards {
		return nil, nil, ErrInvalidShardIdx
	}

	// Check for duplicate
	if group.shards[shardIdx] != nil {
		// Duplicate shard, return original if it's a data shard
		if shardIdx < dataShards && group.origLens[shardIdx] > 0 {
			origLen := group.origLens[shardIdx]
			orig := make([]byte, origLen)
			copy(orig, payload[:origLen])
			return orig, nil, nil
		}
		return nil, nil, nil
	}

	// Store shard
	shardCopy := make([]byte, len(payload))
	copy(shardCopy, payload)
	group.shards[shardIdx] = shardCopy
	group.received++

	if len(payload) > group.maxLen {
		group.maxLen = len(payload)
	}

	// Return original data immediately if this is a data shard with content
	if shardIdx < dataShards && group.origLens[shardIdx] > 0 {
		origLen := group.origLens[shardIdx]
		original = make([]byte, origLen)
		copy(original, payload[:origLen])
	}

	// Check if we need and can reconstruct
	if group.received >= dataShards {
		// Count missing data shards
		missingData := 0
		for i := 0; i < dataShards; i++ {
			if group.shards[i] == nil {
				missingData++
			}
		}

		// If we have all data shards, no need to reconstruct
		if missingData == 0 {
			// Cleanup complete group
			delete(d.groups, groupID)
			return original, nil, nil
		}

		// Try to reconstruct
		recovered, err = d.reconstruct(group)
		if err == nil {
			delete(d.groups, groupID)
		}
	}

	return original, recovered, nil
}

// reconstruct attempts to recover missing data shards
// Must be called with lock held
func (d *Decoder) reconstruct(group *decoderGroup) ([][]byte, error) {
	// Pad shards to same length
	shards := make([][]byte, group.totalShards)
	for i := 0; i < group.totalShards; i++ {
		if group.shards[i] != nil {
			// Pad to maxLen
			shards[i] = make([]byte, group.maxLen)
			copy(shards[i], group.shards[i])
		}
		// nil shards remain nil for reconstruction
	}

	// Reconstruct
	if err := d.decoder.Reconstruct(shards); err != nil {
		return nil, fmt.Errorf("reconstruct: %w", err)
	}

	// Extract recovered data shards
	var recovered [][]byte
	for i := 0; i < group.dataShards; i++ {
		if group.shards[i] == nil && shards[i] != nil {
			// This was a missing shard that got reconstructed
			origLen := group.origLens[i]
			if origLen > 0 && int(origLen) <= len(shards[i]) {
				data := make([]byte, origLen)
				copy(data, shards[i][:origLen])
				recovered = append(recovered, data)
			}
		}
	}

	return recovered, nil
}

// cleanupOldGroups removes oldest groups when too many are pending
// Must be called with lock held
func (d *Decoder) cleanupOldGroups(currentGroupID uint32) {
	// Remove groups that are too old (more than maxGroups behind current)
	threshold := currentGroupID - uint32(d.maxGroups)
	for gid := range d.groups {
		// Handle wrap-around
		if gid < threshold && (currentGroupID-gid) < uint32(d.maxGroups*2) {
			delete(d.groups, gid)
		}
	}
}

// PendingGroups returns the number of incomplete groups
func (d *Decoder) PendingGroups() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.groups)
}
