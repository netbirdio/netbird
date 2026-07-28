package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)
	assert.NotEmpty(t, key)

	_, err = NewFieldEncrypt(key)
	assert.NoError(t, err)
}

func TestNewFieldEncrypt_InvalidKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{name: "invalid base64", key: "not-valid-base64!!!"},
		{name: "too short", key: "c2hvcnQ="},
		{name: "empty", key: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewFieldEncrypt(tt.key)
			assert.Error(t, err)
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	ec, err := NewFieldEncrypt(key)
	require.NoError(t, err)

	testCases := []struct {
		name  string
		input string
	}{
		{name: "Empty String", input: ""},
		{name: "Short String", input: "Hello"},
		{name: "String with Spaces", input: "Hello, World!"},
		{name: "Long String", input: "The quick brown fox jumps over the lazy dog."},
		{name: "Unicode Characters", input: "こんにちは世界"},
		{name: "Special Characters", input: "!@#$%^&*()_+-=[]{}|;':\",./<>?"},
		{name: "Numeric String", input: "1234567890"},
		{name: "Email Address", input: "user@example.com"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := ec.Encrypt(tc.input)
			require.NoError(t, err)

			decrypted, err := ec.Decrypt(encrypted)
			require.NoError(t, err)

			assert.Equal(t, tc.input, decrypted)
		})
	}
}

func TestEncrypt_DifferentCiphertexts(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	ec, err := NewFieldEncrypt(key)
	require.NoError(t, err)

	plaintext := "same plaintext"

	// Encrypt the same plaintext multiple times
	encrypted1, err := ec.Encrypt(plaintext)
	require.NoError(t, err)

	encrypted2, err := ec.Encrypt(plaintext)
	require.NoError(t, err)

	assert.NotEqual(t, encrypted1, encrypted2, "expected different ciphertexts for same plaintext (random nonce)")

	// Both should decrypt to the same plaintext
	decrypted1, err := ec.Decrypt(encrypted1)
	require.NoError(t, err)

	decrypted2, err := ec.Decrypt(encrypted2)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted1)
	assert.Equal(t, plaintext, decrypted2)
}

func TestDecrypt_InvalidCiphertext(t *testing.T) {
	key, err := GenerateKey()
	assert.NoError(t, err)

	ec, err := NewFieldEncrypt(key)
	assert.NoError(t, err)

	tests := []struct {
		name       string
		ciphertext string
	}{
		{name: "invalid base64", ciphertext: "not-valid!!!"},
		{name: "too short", ciphertext: "c2hvcnQ="},
		{name: "corrupted", ciphertext: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := ec.Decrypt(tt.ciphertext)
			assert.Error(t, err)
			assert.Empty(t, payload)
		})
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()

	ec1, _ := NewFieldEncrypt(key1)
	ec2, _ := NewFieldEncrypt(key2)

	plaintext := "secret data"
	encrypted, _ := ec1.Encrypt(plaintext)

	// Try to decrypt with wrong key
	payload, err := ec2.Decrypt(encrypted)
	assert.Error(t, err)
	assert.Empty(t, payload)
}
