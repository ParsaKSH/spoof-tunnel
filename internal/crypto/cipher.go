package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// NonceSize is the size of the nonce for ChaCha20-Poly1305
	NonceSize = chacha20poly1305.NonceSize // 12 bytes
	// TagSize is the authentication tag size
	TagSize = chacha20poly1305.Overhead // 16 bytes
	// MaxPayloadSize is the maximum size of encrypted payload
	MaxPayloadSize = 65535 - NonceSize - TagSize
)

var (
	ErrPayloadTooLarge = errors.New("payload too large")
	ErrDecryptFailed   = errors.New("decryption failed: authentication error")
	ErrInvalidNonce    = errors.New("invalid nonce")
)

// Cipher handles ChaCha20-Poly1305 encryption/decryption
type Cipher struct {
	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD

	// Nonce counters for anti-replay
	sendNonce uint64
	recvNonce uint64

	// Buffer pool for efficiency
	bufPool sync.Pool
}

// NewCipher creates a new cipher with send and receive keys
func NewCipher(sendKey, recvKey [KeySize]byte) (*Cipher, error) {
	sendAEAD, err := chacha20poly1305.New(sendKey[:])
	if err != nil {
		return nil, fmt.Errorf("create send cipher: %w", err)
	}

	recvAEAD, err := chacha20poly1305.New(recvKey[:])
	if err != nil {
		return nil, fmt.Errorf("create recv cipher: %w", err)
	}

	return &Cipher{
		sendAEAD: sendAEAD,
		recvAEAD: recvAEAD,
		bufPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 65535)
				return &buf
			},
		},
	}, nil
}

// Encrypt encrypts plaintext and returns ciphertext with nonce prepended
// Format: [nonce:12][ciphertext+tag:variable]
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxPayloadSize {
		return nil, ErrPayloadTooLarge
	}

	// Generate nonce from counter (prevents replay, ensures uniqueness)
	nonce := make([]byte, NonceSize)
	counter := atomic.AddUint64(&c.sendNonce, 1)
	binary.BigEndian.PutUint64(nonce[4:], counter)

	// Allocate output buffer: nonce + ciphertext + tag
	out := make([]byte, NonceSize+len(plaintext)+TagSize)
	copy(out[:NonceSize], nonce)

	// Encrypt in place
	c.sendAEAD.Seal(out[NonceSize:NonceSize], nonce, plaintext, nil)

	return out, nil
}

// EncryptTo encrypts plaintext into the provided buffer
// Returns the number of bytes written
func (c *Cipher) EncryptTo(dst, plaintext []byte) (int, error) {
	if len(plaintext) > MaxPayloadSize {
		return 0, ErrPayloadTooLarge
	}

	needed := NonceSize + len(plaintext) + TagSize
	if len(dst) < needed {
		return 0, fmt.Errorf("buffer too small: need %d, have %d", needed, len(dst))
	}

	// Generate nonce from counter
	counter := atomic.AddUint64(&c.sendNonce, 1)
	binary.BigEndian.PutUint64(dst[4:NonceSize], counter)

	// First 4 bytes of nonce are random for additional entropy
	if _, err := rand.Read(dst[:4]); err != nil {
		return 0, fmt.Errorf("generate nonce: %w", err)
	}

	// Encrypt
	c.sendAEAD.Seal(dst[NonceSize:NonceSize], dst[:NonceSize], plaintext, nil)

	return needed, nil
}

// Decrypt decrypts ciphertext with prepended nonce
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize+TagSize {
		return nil, ErrInvalidNonce
	}

	nonce := ciphertext[:NonceSize]
	encrypted := ciphertext[NonceSize:]

	// Extract counter from nonce for replay protection
	counter := binary.BigEndian.Uint64(nonce[4:])
	
	// Simple replay check: nonce should be greater than last seen
	// In production, use a sliding window for out-of-order packets
	lastNonce := atomic.LoadUint64(&c.recvNonce)
	if counter <= lastNonce && lastNonce > 0 {
		// Allow some window for out-of-order packets
		if lastNonce-counter > 1000 {
			return nil, fmt.Errorf("replay detected: counter %d, last %d", counter, lastNonce)
		}
	}
	
	// Update last seen nonce
	if counter > lastNonce {
		atomic.StoreUint64(&c.recvNonce, counter)
	}

	// Decrypt
	plaintext, err := c.recvAEAD.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	return plaintext, nil
}

// DecryptTo decrypts ciphertext into the provided buffer
func (c *Cipher) DecryptTo(dst, ciphertext []byte) (int, error) {
	if len(ciphertext) < NonceSize+TagSize {
		return 0, ErrInvalidNonce
	}

	nonce := ciphertext[:NonceSize]
	encrypted := ciphertext[NonceSize:]
	plaintextLen := len(encrypted) - TagSize

	if len(dst) < plaintextLen {
		return 0, fmt.Errorf("buffer too small: need %d, have %d", plaintextLen, len(dst))
	}

	// Extract and check counter
	counter := binary.BigEndian.Uint64(nonce[4:])
	lastNonce := atomic.LoadUint64(&c.recvNonce)
	if counter <= lastNonce && lastNonce > 0 {
		if lastNonce-counter > 1000 {
			return 0, fmt.Errorf("replay detected")
		}
	}
	if counter > lastNonce {
		atomic.StoreUint64(&c.recvNonce, counter)
	}

	// Decrypt
	_, err := c.recvAEAD.Open(dst[:0], nonce, encrypted, nil)
	if err != nil {
		return 0, ErrDecryptFailed
	}

	return plaintextLen, nil
}

// GetBuffer gets a buffer from the pool
func (c *Cipher) GetBuffer() *[]byte {
	return c.bufPool.Get().(*[]byte)
}

// PutBuffer returns a buffer to the pool
func (c *Cipher) PutBuffer(buf *[]byte) {
	c.bufPool.Put(buf)
}

// EncryptedSize returns the size of ciphertext for given plaintext size
func EncryptedSize(plaintextSize int) int {
	return NonceSize + plaintextSize + TagSize
}

// PlaintextSize returns the size of plaintext for given ciphertext size
func PlaintextSize(ciphertextSize int) int {
	return ciphertextSize - NonceSize - TagSize
}
