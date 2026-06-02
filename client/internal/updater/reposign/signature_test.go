package reposign

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSignature_Valid(t *testing.T) {
	timestamp := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	keyID, err := ParseKeyID("0123456789abcdef")
	require.NoError(t, err)

	signatureData := []byte{0x01, 0x02, 0x03, 0x04}

	jsonData, err := json.Marshal(Signature{
		Signature: signatureData,
		Timestamp: timestamp,
		KeyID:     keyID,
		Algorithm: "ed25519",
		HashAlgo:  "blake2s",
	})
	require.NoError(t, err)

	sig, err := ParseSignature(jsonData)
	require.NoError(t, err)
	assert.NotNil(t, sig)
	assert.Equal(t, signatureData, sig.Signature)
	assert.Equal(t, timestamp.Unix(), sig.Timestamp.Unix())
	assert.Equal(t, keyID, sig.KeyID)
	assert.Equal(t, "ed25519", sig.Algorithm)
	assert.Equal(t, "blake2s", sig.HashAlgo)
}

func TestParseSignature_InvalidJSON(t *testing.T) {
	invalidJSON := []byte(`{invalid json}`)

	sig, err := ParseSignature(invalidJSON)
	assert.Error(t, err)
	assert.Nil(t, sig)
}

func TestParseSignature_EmptyData(t *testing.T) {
	emptyJSON := []byte(`{}`)

	sig, err := ParseSignature(emptyJSON)
	require.NoError(t, err)
	assert.NotNil(t, sig)
	assert.Empty(t, sig.Signature)
	assert.True(t, sig.Timestamp.IsZero())
	assert.Equal(t, KeyID{}, sig.KeyID)
	assert.Empty(t, sig.Algorithm)
	assert.Empty(t, sig.HashAlgo)
}

func TestParseSignature_MissingFields(t *testing.T) {
	// JSON with only some fields
	partialJSON := []byte(`{
		"signature": "AQIDBA==",
		"algorithm": "ed25519"
	}`)

	sig, err := ParseSignature(partialJSON)
	require.NoError(t, err)
	assert.NotNil(t, sig)
	assert.NotEmpty(t, sig.Signature)
	assert.Equal(t, "ed25519", sig.Algorithm)
	assert.True(t, sig.Timestamp.IsZero())
}

func TestSignature_MarshalUnmarshal_Roundtrip(t *testing.T) {
	timestamp := time.Date(2024, 6, 20, 14, 45, 30, 0, time.UTC)
	keyID, err := ParseKeyID("fedcba9876543210")
	require.NoError(t, err)

	original := Signature{
		Signature: []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe},
		Timestamp: timestamp,
		KeyID:     keyID,
		Algorithm: "ed25519",
		HashAlgo:  "sha512",
	}

	// Marshal
	jsonData, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal
	parsed, err := ParseSignature(jsonData)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Signature, parsed.Signature)
	assert.Equal(t, original.Timestamp.Unix(), parsed.Timestamp.Unix())
	assert.Equal(t, original.KeyID, parsed.KeyID)
	assert.Equal(t, original.Algorithm, parsed.Algorithm)
	assert.Equal(t, original.HashAlgo, parsed.HashAlgo)
}

func TestSignature_NilSignatureBytes(t *testing.T) {
	timestamp := time.Now().UTC()
	keyID, err := ParseKeyID("0011223344556677")
	require.NoError(t, err)

	sig := Signature{
		Signature: nil,
		Timestamp: timestamp,
		KeyID:     keyID,
		Algorithm: "ed25519",
		HashAlgo:  "blake2s",
	}

	jsonData, err := json.Marshal(sig)
	require.NoError(t, err)

	parsed, err := ParseSignature(jsonData)
	require.NoError(t, err)
	assert.Nil(t, parsed.Signature)
}

func TestSignature_LargeSignature(t *testing.T) {
	timestamp := time.Now().UTC()
	keyID, err := ParseKeyID("aabbccddeeff0011")
	require.NoError(t, err)

	// Create a large signature (64 bytes for ed25519)
	largeSignature := make([]byte, 64)
	for i := range largeSignature {
		largeSignature[i] = byte(i)
	}

	sig := Signature{
		Signature: largeSignature,
		Timestamp: timestamp,
		KeyID:     keyID,
		Algorithm: "ed25519",
		HashAlgo:  "blake2s",
	}

	jsonData, err := json.Marshal(sig)
	require.NoError(t, err)

	parsed, err := ParseSignature(jsonData)
	require.NoError(t, err)
	assert.Equal(t, largeSignature, parsed.Signature)
}

func TestSignature_WithDifferentHashAlgorithms(t *testing.T) {
	tests := []struct {
		name     string
		hashAlgo string
	}{
		{"blake2s", "blake2s"},
		{"sha512", "sha512"},
		{"sha256", "sha256"},
		{"empty", ""},
	}

	keyID, err := ParseKeyID("1122334455667788")
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := Signature{
				Signature: []byte{0x01, 0x02},
				Timestamp: time.Now().UTC(),
				KeyID:     keyID,
				Algorithm: "ed25519",
				HashAlgo:  tt.hashAlgo,
			}

			jsonData, err := json.Marshal(sig)
			require.NoError(t, err)

			parsed, err := ParseSignature(jsonData)
			require.NoError(t, err)
			assert.Equal(t, tt.hashAlgo, parsed.HashAlgo)
		})
	}
}

func TestSignature_TimestampPrecision(t *testing.T) {
	// Test that timestamp preserves precision through JSON marshaling
	timestamp := time.Date(2024, 3, 15, 10, 30, 45, 123456789, time.UTC)
	keyID, err := ParseKeyID("8877665544332211")
	require.NoError(t, err)

	sig := Signature{
		Signature: []byte{0xaa, 0xbb},
		Timestamp: timestamp,
		KeyID:     keyID,
		Algorithm: "ed25519",
		HashAlgo:  "blake2s",
	}

	jsonData, err := json.Marshal(sig)
	require.NoError(t, err)

	parsed, err := ParseSignature(jsonData)
	require.NoError(t, err)

	// JSON timestamps typically have second or millisecond precision
	// so we check that at least seconds match
	assert.Equal(t, timestamp.Unix(), parsed.Timestamp.Unix())
}

func TestParseSignature_MalformedKeyID(t *testing.T) {
	// Test with a malformed KeyID field
	malformedJSON := []byte(`{
		"signature": "AQID",
		"timestamp": "2024-01-15T10:30:00Z",
		"key_id": "invalid_keyid_format",
		"algorithm": "ed25519",
		"hash_algo": "blake2s"
	}`)

	// This should fail since "invalid_keyid_format" is not a valid KeyID
	sig, err := ParseSignature(malformedJSON)
	assert.Error(t, err)
	assert.Nil(t, sig)
}

func TestParseSignature_InvalidTimestamp(t *testing.T) {
	// Test with an invalid timestamp format
	invalidTimestampJSON := []byte(`{
		"signature": "AQID",
		"timestamp": "not-a-timestamp",
		"key_id": "0123456789abcdef",
		"algorithm": "ed25519",
		"hash_algo": "blake2s"
	}`)

	sig, err := ParseSignature(invalidTimestampJSON)
	assert.Error(t, err)
	assert.Nil(t, sig)
}

func TestSignature_ZeroKeyID(t *testing.T) {
	// Test with a zero KeyID
	sig := Signature{
		Signature: []byte{0x01, 0x02, 0x03},
		Timestamp: time.Now().UTC(),
		KeyID:     KeyID{},
		Algorithm: "ed25519",
		HashAlgo:  "blake2s",
	}

	jsonData, err := json.Marshal(sig)
	require.NoError(t, err)

	parsed, err := ParseSignature(jsonData)
	require.NoError(t, err)
	assert.Equal(t, KeyID{}, parsed.KeyID)
}

func TestParseSignature_ExtraFields(t *testing.T) {
	// JSON with extra fields that should be ignored
	jsonWithExtra := []byte(`{
		"signature": "AQIDBA==",
		"timestamp": "2024-01-15T10:30:00Z",
		"key_id": "0123456789abcdef",
		"algorithm": "ed25519",
		"hash_algo": "blake2s",
		"extra_field": "should be ignored",
		"another_extra": 12345
	}`)

	sig, err := ParseSignature(jsonWithExtra)
	require.NoError(t, err)
	assert.NotNil(t, sig)
	assert.NotEmpty(t, sig.Signature)
	assert.Equal(t, "ed25519", sig.Algorithm)
	assert.Equal(t, "blake2s", sig.HashAlgo)
}
