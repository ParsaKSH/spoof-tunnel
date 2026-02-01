package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Packet types
const (
	PacketData      byte = 0x01 // Data packet
	PacketInit      byte = 0x02 // Connection init (handshake)
	PacketInitAck   byte = 0x03 // Init acknowledgment
	PacketPing      byte = 0x04 // Keepalive ping
	PacketPong      byte = 0x05 // Keepalive pong
	PacketClose     byte = 0x06 // Connection close
	PacketHandshake byte = 0x07 // Key exchange handshake
	PacketAck       byte = 0x08 // Data acknowledgment (for reliable delivery)
	PacketFEC       byte = 0x09 // FEC shard packet
)

// Header sizes
const (
	// BaseHeaderSize is the minimum header size
	// [SessionID:4][Type:1][Length:2] = 7 bytes
	BaseHeaderSize = 7

	// MaxSessionID is the maximum session ID value
	MaxSessionID = 0xFFFFFFFF

	// MaxPacketSize is the maximum packet size
	MaxPacketSize = 65535
)

var (
	ErrPacketTooSmall  = errors.New("packet too small")
	ErrPacketTooLarge  = errors.New("packet too large")
	ErrInvalidType     = errors.New("invalid packet type")
	ErrInvalidLength   = errors.New("invalid packet length")
	ErrInvalidChecksum = errors.New("invalid checksum")
)

// Packet represents a tunnel packet
type Packet struct {
	SessionID uint32
	Type      byte
	Payload   []byte
}

// Header represents just the packet header for quick parsing
type Header struct {
	SessionID uint32
	Type      byte
	Length    uint16
}

// ParseHeader parses just the header from raw bytes
func ParseHeader(data []byte) (*Header, error) {
	if len(data) < BaseHeaderSize {
		return nil, ErrPacketTooSmall
	}

	return &Header{
		SessionID: binary.BigEndian.Uint32(data[0:4]),
		Type:      data[4],
		Length:    binary.BigEndian.Uint16(data[5:7]),
	}, nil
}

// Parse parses a packet from raw bytes (after decryption)
func Parse(data []byte) (*Packet, error) {
	if len(data) < BaseHeaderSize {
		return nil, ErrPacketTooSmall
	}

	sessionID := binary.BigEndian.Uint32(data[0:4])
	pType := data[4]
	length := binary.BigEndian.Uint16(data[5:7])

	expectedLen := BaseHeaderSize + int(length)
	if len(data) < expectedLen {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidLength, expectedLen, len(data))
	}

	return &Packet{
		SessionID: sessionID,
		Type:      pType,
		Payload:   data[BaseHeaderSize:expectedLen],
	}, nil
}

// Marshal serializes a packet to bytes
func (p *Packet) Marshal() ([]byte, error) {
	if len(p.Payload) > MaxPacketSize-BaseHeaderSize {
		return nil, ErrPacketTooLarge
	}

	buf := make([]byte, BaseHeaderSize+len(p.Payload))
	p.MarshalTo(buf)
	return buf, nil
}

// MarshalTo serializes a packet into the provided buffer
// Returns the number of bytes written
func (p *Packet) MarshalTo(buf []byte) int {
	binary.BigEndian.PutUint32(buf[0:4], p.SessionID)
	buf[4] = p.Type
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(p.Payload)))
	copy(buf[BaseHeaderSize:], p.Payload)
	return BaseHeaderSize + len(p.Payload)
}

// Size returns the total serialized size of the packet
func (p *Packet) Size() int {
	return BaseHeaderSize + len(p.Payload)
}

// NewDataPacket creates a new data packet (for backward compatibility)
func NewDataPacket(sessionID uint32, data []byte) *Packet {
	return &Packet{
		SessionID: sessionID,
		Type:      PacketData,
		Payload:   data,
	}
}

// NewSeqDataPacket creates a new data packet with sequence number for reliable delivery
// Payload format: [SeqNum:4][Data:...]
func NewSeqDataPacket(sessionID uint32, seqNum uint32, data []byte) *Packet {
	payload := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(payload[0:4], seqNum)
	copy(payload[4:], data)
	return &Packet{
		SessionID: sessionID,
		Type:      PacketData,
		Payload:   payload,
	}
}

// ParseSeqData parses a sequenced data packet payload
// Returns seqNum and actual data
func ParseSeqData(payload []byte) (seqNum uint32, data []byte, err error) {
	if len(payload) < 4 {
		return 0, nil, errors.New("payload too small for sequence number")
	}
	seqNum = binary.BigEndian.Uint32(payload[0:4])
	data = payload[4:]
	return seqNum, data, nil
}

// NewAckPacket creates an ACK packet for reliable delivery
// Payload format: [AckSeqNum:4][RecvBitmap:8]
// AckSeqNum: highest contiguous sequence received
// RecvBitmap: bitmap of next 64 packets received (for selective ACK)
func NewAckPacket(sessionID uint32, ackSeqNum uint32, recvBitmap uint64) *Packet {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint32(payload[0:4], ackSeqNum)
	binary.BigEndian.PutUint64(payload[4:12], recvBitmap)
	return &Packet{
		SessionID: sessionID,
		Type:      PacketAck,
		Payload:   payload,
	}
}

// ParseAck parses an ACK packet payload
func ParseAck(payload []byte) (ackSeqNum uint32, recvBitmap uint64, err error) {
	if len(payload) < 12 {
		return 0, 0, errors.New("ACK payload too small")
	}
	ackSeqNum = binary.BigEndian.Uint32(payload[0:4])
	recvBitmap = binary.BigEndian.Uint64(payload[4:12])
	return ackSeqNum, recvBitmap, nil
}

// NewInitPacket creates a new init packet with target address
func NewInitPacket(sessionID uint32, target string) *Packet {
	return &Packet{
		SessionID: sessionID,
		Type:      PacketInit,
		Payload:   []byte(target),
	}
}

// NewInitAckPacket creates an init acknowledgment packet
func NewInitAckPacket(sessionID uint32, success bool, message string) *Packet {
	payload := make([]byte, 1+len(message))
	if success {
		payload[0] = 1
	} else {
		payload[0] = 0
	}
	copy(payload[1:], message)

	return &Packet{
		SessionID: sessionID,
		Type:      PacketInitAck,
		Payload:   payload,
	}
}

// ParseInitAck parses an init ack packet payload
func ParseInitAck(payload []byte) (success bool, message string) {
	if len(payload) < 1 {
		return false, ""
	}
	success = payload[0] == 1
	if len(payload) > 1 {
		message = string(payload[1:])
	}
	return
}

// NewPingPacket creates a ping packet
func NewPingPacket(sessionID uint32, seq uint32) *Packet {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, seq)
	return &Packet{
		SessionID: sessionID,
		Type:      PacketPing,
		Payload:   payload,
	}
}

// NewPongPacket creates a pong packet
func NewPongPacket(sessionID uint32, seq uint32) *Packet {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, seq)
	return &Packet{
		SessionID: sessionID,
		Type:      PacketPong,
		Payload:   payload,
	}
}

// NewClosePacket creates a close packet
func NewClosePacket(sessionID uint32) *Packet {
	return &Packet{
		SessionID: sessionID,
		Type:      PacketClose,
		Payload:   nil,
	}
}

// HandshakePayload contains the handshake data
type HandshakePayload struct {
	PublicKey [32]byte
	Timestamp uint64
}

// NewHandshakePacket creates a handshake packet with public key
func NewHandshakePacket(sessionID uint32, publicKey [32]byte, timestamp uint64) *Packet {
	payload := make([]byte, 40) // 32 bytes key + 8 bytes timestamp
	copy(payload[:32], publicKey[:])
	binary.BigEndian.PutUint64(payload[32:40], timestamp)

	return &Packet{
		SessionID: sessionID,
		Type:      PacketHandshake,
		Payload:   payload,
	}
}

// ParseHandshake parses handshake packet payload
func ParseHandshake(payload []byte) (*HandshakePayload, error) {
	if len(payload) < 40 {
		return nil, fmt.Errorf("handshake payload too small: %d", len(payload))
	}

	hs := &HandshakePayload{
		Timestamp: binary.BigEndian.Uint64(payload[32:40]),
	}
	copy(hs.PublicKey[:], payload[:32])

	return hs, nil
}

// TypeString returns a human-readable type name
func TypeString(t byte) string {
	switch t {
	case PacketData:
		return "DATA"
	case PacketInit:
		return "INIT"
	case PacketInitAck:
		return "INIT_ACK"
	case PacketPing:
		return "PING"
	case PacketPong:
		return "PONG"
	case PacketClose:
		return "CLOSE"
	case PacketHandshake:
		return "HANDSHAKE"
	case PacketAck:
		return "ACK"
	case PacketFEC:
		return "FEC"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

// NewFECPacket creates a new FEC shard packet
func NewFECPacket(sessionID uint32, shardData []byte) *Packet {
	return &Packet{
		SessionID: sessionID,
		Type:      PacketFEC,
		Payload:   shardData,
	}
}
