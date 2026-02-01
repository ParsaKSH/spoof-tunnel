package crypto

import (
	"bytes"
	"testing"
)

func TestKeyPairGeneration(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Keys should be different
	if bytes.Equal(kp1.PrivateKey[:], kp2.PrivateKey[:]) {
		t.Error("Generated keys should be unique")
	}
}

func TestKeyPairParsing(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Parse the base64 private key
	kp2, err := ParsePrivateKey(kp1.PrivateKeyBase64())
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	// Public keys should match
	if !bytes.Equal(kp1.PublicKey[:], kp2.PublicKey[:]) {
		t.Error("Public key mismatch after parsing")
	}
}

func TestSharedSecret(t *testing.T) {
	// Generate two key pairs
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	// Compute shared secrets
	aliceSecret, err := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret (alice): %v", err)
	}

	bobSecret, err := ComputeSharedSecret(bob.PrivateKey, alice.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret (bob): %v", err)
	}

	// Shared secrets should be identical
	if !bytes.Equal(aliceSecret[:], bobSecret[:]) {
		t.Error("Shared secrets should be equal")
	}
}

func TestCipherEncryptDecrypt(t *testing.T) {
	// Generate keys
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	// Compute shared secret
	sharedSecret, _ := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)

	// Derive session keys
	aliceSend, aliceRecv, _ := DeriveSessionKeys(sharedSecret, true)
	bobSend, bobRecv, _ := DeriveSessionKeys(sharedSecret, false)

	// Create ciphers
	aliceCipher, err := NewCipher(aliceSend, aliceRecv)
	if err != nil {
		t.Fatalf("NewCipher (alice): %v", err)
	}

	bobCipher, err := NewCipher(bobSend, bobRecv)
	if err != nil {
		t.Fatalf("NewCipher (bob): %v", err)
	}

	// Test encryption/decryption
	plaintext := []byte("Hello, this is a secret message!")

	// Alice encrypts, Bob decrypts
	ciphertext, err := aliceCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decrypted, err := bobCipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text mismatch: got %q, want %q", decrypted, plaintext)
	}

	// Bob encrypts, Alice decrypts
	ciphertext2, _ := bobCipher.Encrypt(plaintext)
	decrypted2, err := aliceCipher.Decrypt(ciphertext2)
	if err != nil {
		t.Fatalf("Decrypt (bob->alice): %v", err)
	}

	if !bytes.Equal(plaintext, decrypted2) {
		t.Errorf("Decrypted text mismatch (bob->alice)")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)
	sendKey, recvKey, _ := DeriveSessionKeys(sharedSecret, true)
	cipher, _ := NewCipher(sendKey, recvKey)

	data := make([]byte, 1400) // MTU size
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = cipher.Encrypt(data)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)
	aliceSend, aliceRecv, _ := DeriveSessionKeys(sharedSecret, true)
	bobSend, bobRecv, _ := DeriveSessionKeys(sharedSecret, false)
	
	aliceCipher, _ := NewCipher(aliceSend, aliceRecv)
	bobCipher, _ := NewCipher(bobSend, bobRecv)

	data := make([]byte, 1400)
	ciphertext, _ := aliceCipher.Encrypt(data)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = bobCipher.Decrypt(ciphertext)
	}
}
