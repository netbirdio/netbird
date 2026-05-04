package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// FieldEncrypt provides AES-GCM encryption for sensitive fields.
type FieldEncrypt struct {
	block cipher.Block
}

// NewFieldEncrypt creates a new FieldEncrypt with the given base64-encoded key.
// The key must be 32 bytes when decoded (for AES-256).
func NewFieldEncrypt(base64Key string) (*FieldEncrypt, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("decode encryption key: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	return &FieldEncrypt{block: block}, nil
}

// Encrypt encrypts the given plaintext and returns base64-encoded ciphertext.
// Returns empty string for empty input.
func (f *FieldEncrypt) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	gcm, err := cipher.NewGCM(f.block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given base64-encoded ciphertext and returns the plaintext.
// Returns empty string for empty input.
// If the input is not a valid base64 string or decryption fails (e.g. wrong key or unencrypted data),
// it returns the original string to allow graceful fallback/migration.
func (f *FieldEncrypt) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		// Not base64, likely plain text
		return ciphertext, nil
	}

	gcm, err := cipher.NewGCM(f.block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		// Too short to be AES-GCM ciphertext, likely plain text
		return ciphertext, nil
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		// Decryption failed, likely plain text or wrong key.
		// We return the original string to avoid breaking systems when encryption is newly enabled.
		return ciphertext, nil
	}

	return string(plaintext), nil
}

// GenerateKey generates a new random 32-byte encryption key and returns it as base64.
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
