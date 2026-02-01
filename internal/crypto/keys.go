package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const (
	// KeySize is the size of X25519 keys in bytes
	KeySize = 32
)

// KeyPair holds a private and public key pair
type KeyPair struct {
	PrivateKey [KeySize]byte
	PublicKey  [KeySize]byte
}

// GenerateKeyPair generates a new X25519 key pair
func GenerateKeyPair() (*KeyPair, error) {
	var privateKey [KeySize]byte
	var publicKey [KeySize]byte

	// Generate random private key
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}

	// Clamp private key (X25519 requirement)
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Derive public key
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// PrivateKeyBase64 returns the private key as base64
func (kp *KeyPair) PrivateKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.PrivateKey[:])
}

// PublicKeyBase64 returns the public key as base64
func (kp *KeyPair) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.PublicKey[:])
}

// ParsePrivateKey parses a base64 encoded private key and derives the public key
func ParsePrivateKey(b64 string) (*KeyPair, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}

	if len(data) != KeySize {
		return nil, fmt.Errorf("invalid private key length: %d (expected %d)", len(data), KeySize)
	}

	var privateKey [KeySize]byte
	var publicKey [KeySize]byte
	copy(privateKey[:], data)

	// Derive public key from private key
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// ParsePublicKey parses a base64 encoded public key
func ParsePublicKey(b64 string) ([KeySize]byte, error) {
	var publicKey [KeySize]byte

	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return publicKey, fmt.Errorf("decode public key: %w", err)
	}

	if len(data) != KeySize {
		return publicKey, fmt.Errorf("invalid public key length: %d (expected %d)", len(data), KeySize)
	}

	copy(publicKey[:], data)
	return publicKey, nil
}

// ComputeSharedSecret computes the shared secret using X25519 ECDH
func ComputeSharedSecret(privateKey [KeySize]byte, peerPublicKey [KeySize]byte) ([KeySize]byte, error) {
	var sharedSecret [KeySize]byte

	result, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return sharedSecret, fmt.Errorf("compute shared secret: %w", err)
	}

	copy(sharedSecret[:], result)
	return sharedSecret, nil
}

// DeriveSessionKeys derives encryption keys from the shared secret
// Returns: (sendKey, receiveKey, error)
// Keys are derived using HKDF-like construction
func DeriveSessionKeys(sharedSecret [KeySize]byte, isInitiator bool) ([KeySize]byte, [KeySize]byte, error) {
	var sendKey, recvKey [KeySize]byte

	// Simple key derivation: XOR with constants for send/receive differentiation
	// In production, use proper HKDF
	sendSalt := [KeySize]byte{
		0x53, 0x50, 0x4f, 0x4f, 0x46, 0x5f, 0x53, 0x45,
		0x4e, 0x44, 0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x56,
		0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	recvSalt := [KeySize]byte{
		0x53, 0x50, 0x4f, 0x4f, 0x46, 0x5f, 0x52, 0x45,
		0x43, 0x56, 0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x56,
		0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}

	for i := 0; i < KeySize; i++ {
		sendKey[i] = sharedSecret[i] ^ sendSalt[i]
		recvKey[i] = sharedSecret[i] ^ recvSalt[i]
	}

	// Swap keys based on role (initiator sends, responder receives with same key)
	if !isInitiator {
		sendKey, recvKey = recvKey, sendKey
	}

	return sendKey, recvKey, nil
}
