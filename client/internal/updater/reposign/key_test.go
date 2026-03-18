package reposign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test KeyID functions

func TestComputeKeyID(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyID := computeKeyID(pub)

	// Verify it's the first 8 bytes of SHA-256
	h := sha256.Sum256(pub)
	expectedID := KeyID{}
	copy(expectedID[:], h[:8])

	assert.Equal(t, expectedID, keyID)
}

func TestComputeKeyID_Deterministic(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Computing KeyID multiple times should give the same result
	keyID1 := computeKeyID(pub)
	keyID2 := computeKeyID(pub)

	assert.Equal(t, keyID1, keyID2)
}

func TestComputeKeyID_DifferentKeys(t *testing.T) {
	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyID1 := computeKeyID(pub1)
	keyID2 := computeKeyID(pub2)

	// Different keys should produce different IDs
	assert.NotEqual(t, keyID1, keyID2)
}

func TestParseKeyID_Valid(t *testing.T) {
	hexStr := "0123456789abcdef"

	keyID, err := ParseKeyID(hexStr)
	require.NoError(t, err)

	expected := KeyID{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	assert.Equal(t, expected, keyID)
}

func TestParseKeyID_InvalidLength(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"too short", "01234567"},
		{"too long", "0123456789abcdef00"},
		{"empty", ""},
		{"odd length", "0123456789abcde"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseKeyID(tt.input)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid KeyID length")
		})
	}
}

func TestParseKeyID_InvalidHex(t *testing.T) {
	invalidHex := "0123456789abcxyz" // 'xyz' are not valid hex

	_, err := ParseKeyID(invalidHex)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode KeyID")
}

func TestKeyID_String(t *testing.T) {
	keyID := KeyID{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}

	str := keyID.String()
	assert.Equal(t, "0123456789abcdef", str)
}

func TestKeyID_RoundTrip(t *testing.T) {
	original := "fedcba9876543210"

	keyID, err := ParseKeyID(original)
	require.NoError(t, err)

	result := keyID.String()
	assert.Equal(t, original, result)
}

func TestKeyID_ZeroValue(t *testing.T) {
	keyID := KeyID{}
	str := keyID.String()
	assert.Equal(t, "0000000000000000", str)
}

// Test KeyMetadata

func TestKeyMetadata_JSONMarshaling(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	metadata := KeyMetadata{
		ID:        computeKeyID(pub),
		CreatedAt: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		ExpiresAt: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
	}

	jsonData, err := json.Marshal(metadata)
	require.NoError(t, err)

	var decoded KeyMetadata
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)

	assert.Equal(t, metadata.ID, decoded.ID)
	assert.Equal(t, metadata.CreatedAt.Unix(), decoded.CreatedAt.Unix())
	assert.Equal(t, metadata.ExpiresAt.Unix(), decoded.ExpiresAt.Unix())
}

func TestKeyMetadata_NoExpiration(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	metadata := KeyMetadata{
		ID:        computeKeyID(pub),
		CreatedAt: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		ExpiresAt: time.Time{}, // Zero value = no expiration
	}

	jsonData, err := json.Marshal(metadata)
	require.NoError(t, err)

	var decoded KeyMetadata
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)

	assert.True(t, decoded.ExpiresAt.IsZero())
}

// Test PublicKey

func TestPublicKey_JSONMarshaling(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubKey := PublicKey{
		Key: pub,
		Metadata: KeyMetadata{
			ID:        computeKeyID(pub),
			CreatedAt: time.Now().UTC(),
			ExpiresAt: time.Now().Add(365 * 24 * time.Hour).UTC(),
		},
	}

	jsonData, err := json.Marshal(pubKey)
	require.NoError(t, err)

	var decoded PublicKey
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)

	assert.Equal(t, pubKey.Key, decoded.Key)
	assert.Equal(t, pubKey.Metadata.ID, decoded.Metadata.ID)
}

// Test parsePublicKey

func TestParsePublicKey_Valid(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	metadata := KeyMetadata{
		ID:        computeKeyID(pub),
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).UTC(),
	}

	pubKey := PublicKey{
		Key:      pub,
		Metadata: metadata,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(pubKey)
	require.NoError(t, err)

	// Encode to PEM
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  tagRootPublic,
		Bytes: jsonData,
	})

	// Parse it back
	parsed, rest, err := parsePublicKey(pemData, tagRootPublic)
	require.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, pub, parsed.Key)
	assert.Equal(t, metadata.ID, parsed.Metadata.ID)
}

func TestParsePublicKey_InvalidPEM(t *testing.T) {
	invalidPEM := []byte("not a PEM")

	_, _, err := parsePublicKey(invalidPEM, tagRootPublic)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM")
}

func TestParsePublicKey_WrongType(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubKey := PublicKey{
		Key: pub,
		Metadata: KeyMetadata{
			ID:        computeKeyID(pub),
			CreatedAt: time.Now().UTC(),
		},
	}

	jsonData, err := json.Marshal(pubKey)
	require.NoError(t, err)

	// Encode with wrong type
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "WRONG TYPE",
		Bytes: jsonData,
	})

	_, _, err = parsePublicKey(pemData, tagRootPublic)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PEM type")
}

func TestParsePublicKey_InvalidJSON(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  tagRootPublic,
		Bytes: []byte("invalid json"),
	})

	_, _, err := parsePublicKey(pemData, tagRootPublic)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal")
}

func TestParsePublicKey_InvalidKeySize(t *testing.T) {
	// Create a public key with wrong size
	pubKey := PublicKey{
		Key: []byte{0x01, 0x02, 0x03}, // Too short
		Metadata: KeyMetadata{
			ID:        KeyID{},
			CreatedAt: time.Now().UTC(),
		},
	}

	jsonData, err := json.Marshal(pubKey)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  tagRootPublic,
		Bytes: jsonData,
	})

	_, _, err = parsePublicKey(pemData, tagRootPublic)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "incorrect Ed25519 public key size")
}

func TestParsePublicKey_IDRecomputation(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create a public key with WRONG ID
	wrongID := KeyID{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	pubKey := PublicKey{
		Key: pub,
		Metadata: KeyMetadata{
			ID:        wrongID,
			CreatedAt: time.Now().UTC(),
		},
	}

	jsonData, err := json.Marshal(pubKey)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  tagRootPublic,
		Bytes: jsonData,
	})

	// Parse should recompute the correct ID
	parsed, _, err := parsePublicKey(pemData, tagRootPublic)
	require.NoError(t, err)

	correctID := computeKeyID(pub)
	assert.Equal(t, correctID, parsed.Metadata.ID)
	assert.NotEqual(t, wrongID, parsed.Metadata.ID)
}

// Test parsePublicKeyBundle

func TestParsePublicKeyBundle_Single(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubKey := PublicKey{
		Key: pub,
		Metadata: KeyMetadata{
			ID:        computeKeyID(pub),
			CreatedAt: time.Now().UTC(),
		},
	}

	jsonData, err := json.Marshal(pubKey)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  tagRootPublic,
		Bytes: jsonData,
	})

	keys, err := parsePublicKeyBundle(pemData, tagRootPublic)
	require.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Equal(t, pub, keys[0].Key)
}

func TestParsePublicKeyBundle_Multiple(t *testing.T) {
	var bundle []byte

	// Create 3 keys
	for i := 0; i < 3; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		pubKey := PublicKey{
			Key: pub,
			Metadata: KeyMetadata{
				ID:        computeKeyID(pub),
				CreatedAt: time.Now().UTC(),
			},
		}

		jsonData, err := json.Marshal(pubKey)
		require.NoError(t, err)

		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  tagRootPublic,
			Bytes: jsonData,
		})

		bundle = append(bundle, pemData...)
	}

	keys, err := parsePublicKeyBundle(bundle, tagRootPublic)
	require.NoError(t, err)
	assert.Len(t, keys, 3)
}

func TestParsePublicKeyBundle_Empty(t *testing.T) {
	_, err := parsePublicKeyBundle([]byte{}, tagRootPublic)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no keys found")
}

func TestParsePublicKeyBundle_Invalid(t *testing.T) {
	_, err := parsePublicKeyBundle([]byte("invalid data"), tagRootPublic)
	assert.Error(t, err)
}

// Test PrivateKey

func TestPrivateKey_JSONMarshaling(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	privKey := PrivateKey{
		Key: priv,
		Metadata: KeyMetadata{
			ID:        computeKeyID(pub),
			CreatedAt: time.Now().UTC(),
		},
	}

	jsonData, err := json.Marshal(privKey)
	require.NoError(t, err)

	var decoded PrivateKey
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)

	assert.Equal(t, privKey.Key, decoded.Key)
	assert.Equal(t, privKey.Metadata.ID, decoded.Metadata.ID)
}

// Test parsePrivateKey

func TestParsePrivateKey_Valid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	privKey := PrivateKey{
		Key: priv,
		Metadata: KeyMetadata{
			ID:        computeKeyID(pub),
			CreatedAt: time.Now().UTC(),
		},
	}

	jsonData, err := json.Marshal(privKey)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  tagRootPrivate,
		Bytes: jsonData,
	})

	parsed, err := parsePrivateKey(pemData, tagRootPrivate)
	require.NoError(t, err)
	assert.Equal(t, priv, parsed.Key)
}

func TestParsePrivateKey_InvalidPEM(t *testing.T) {
	_, err := parsePrivateKey([]byte("not a PEM"), tagRootPrivate)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM")
}

func TestParsePrivateKey_TrailingData(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	privKey := PrivateKey{
		Key: priv,
		Metadata: KeyMetadata{
			ID:        computeKeyID(pub),
			CreatedAt: time.Now().UTC(),
		},
	}

	jsonData, err := json.Marshal(privKey)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  tagRootPrivate,
		Bytes: jsonData,
	})

	// Add trailing data
	pemData = append(pemData, []byte("extra data")...)

	_, err = parsePrivateKey(pemData, tagRootPrivate)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "trailing PEM data")
}

func TestParsePrivateKey_WrongType(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	privKey := PrivateKey{
		Key: priv,
		Metadata: KeyMetadata{
			ID:        computeKeyID(pub),
			CreatedAt: time.Now().UTC(),
		},
	}

	jsonData, err := json.Marshal(privKey)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "WRONG TYPE",
		Bytes: jsonData,
	})

	_, err = parsePrivateKey(pemData, tagRootPrivate)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PEM type")
}

func TestParsePrivateKey_InvalidKeySize(t *testing.T) {
	privKey := PrivateKey{
		Key: []byte{0x01, 0x02, 0x03}, // Too short
		Metadata: KeyMetadata{
			ID:        KeyID{},
			CreatedAt: time.Now().UTC(),
		},
	}

	jsonData, err := json.Marshal(privKey)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  tagRootPrivate,
		Bytes: jsonData,
	})

	_, err = parsePrivateKey(pemData, tagRootPrivate)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "incorrect Ed25519 private key size")
}

// Test verifyAny

func TestVerifyAny_ValidSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	message := []byte("test message")
	signature := ed25519.Sign(priv, message)

	rootKeys := []PublicKey{
		{
			Key: pub,
			Metadata: KeyMetadata{
				ID:        computeKeyID(pub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	result := verifyAny(rootKeys, message, signature)
	assert.True(t, result)
}

func TestVerifyAny_InvalidSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	message := []byte("test message")
	invalidSignature := make([]byte, ed25519.SignatureSize)

	rootKeys := []PublicKey{
		{
			Key: pub,
			Metadata: KeyMetadata{
				ID:        computeKeyID(pub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	result := verifyAny(rootKeys, message, invalidSignature)
	assert.False(t, result)
}

func TestVerifyAny_MultipleKeys(t *testing.T) {
	// Create 3 key pairs
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pub3, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	message := []byte("test message")
	signature := ed25519.Sign(priv1, message)

	rootKeys := []PublicKey{
		{Key: pub2, Metadata: KeyMetadata{ID: computeKeyID(pub2)}},
		{Key: pub1, Metadata: KeyMetadata{ID: computeKeyID(pub1)}}, // Correct key in middle
		{Key: pub3, Metadata: KeyMetadata{ID: computeKeyID(pub3)}},
	}

	result := verifyAny(rootKeys, message, signature)
	assert.True(t, result)
}

func TestVerifyAny_NoMatchingKey(t *testing.T) {
	_, priv1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	message := []byte("test message")
	signature := ed25519.Sign(priv1, message)

	// Only include pub2, not pub1
	rootKeys := []PublicKey{
		{Key: pub2, Metadata: KeyMetadata{ID: computeKeyID(pub2)}},
	}

	result := verifyAny(rootKeys, message, signature)
	assert.False(t, result)
}

func TestVerifyAny_EmptyKeys(t *testing.T) {
	message := []byte("test message")
	signature := make([]byte, ed25519.SignatureSize)

	result := verifyAny([]PublicKey{}, message, signature)
	assert.False(t, result)
}

func TestVerifyAny_TamperedMessage(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	message := []byte("test message")
	signature := ed25519.Sign(priv, message)

	rootKeys := []PublicKey{
		{Key: pub, Metadata: KeyMetadata{ID: computeKeyID(pub)}},
	}

	// Verify with different message
	tamperedMessage := []byte("different message")
	result := verifyAny(rootKeys, tamperedMessage, signature)
	assert.False(t, result)
}
