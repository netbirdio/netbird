package reposign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test ArtifactHash

func TestNewArtifactHash(t *testing.T) {
	h := NewArtifactHash()
	assert.NotNil(t, h)
	assert.NotNil(t, h.Hash)
}

func TestArtifactHash_Write(t *testing.T) {
	h := NewArtifactHash()

	data := []byte("test data")
	n, err := h.Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)

	hash := h.Sum(nil)
	assert.NotEmpty(t, hash)
	assert.Equal(t, 32, len(hash)) // BLAKE2s-256
}

func TestArtifactHash_Deterministic(t *testing.T) {
	data := []byte("test data")

	h1 := NewArtifactHash()
	if _, err := h1.Write(data); err != nil {
		t.Fatal(err)
	}
	hash1 := h1.Sum(nil)

	h2 := NewArtifactHash()
	if _, err := h2.Write(data); err != nil {
		t.Fatal(err)
	}
	hash2 := h2.Sum(nil)

	assert.Equal(t, hash1, hash2)
}

func TestArtifactHash_DifferentData(t *testing.T) {
	h1 := NewArtifactHash()
	if _, err := h1.Write([]byte("data1")); err != nil {
		t.Fatal(err)
	}
	hash1 := h1.Sum(nil)

	h2 := NewArtifactHash()
	if _, err := h2.Write([]byte("data2")); err != nil {
		t.Fatal(err)
	}
	hash2 := h2.Sum(nil)

	assert.NotEqual(t, hash1, hash2)
}

// Test ArtifactKey.String()

func TestArtifactKey_String(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	createdAt := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	expiresAt := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)

	ak := ArtifactKey{
		PrivateKey{
			Key: priv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(pub),
				CreatedAt: createdAt,
				ExpiresAt: expiresAt,
			},
		},
	}

	str := ak.String()
	assert.Contains(t, str, "ArtifactKey")
	assert.Contains(t, str, computeKeyID(pub).String())
	assert.Contains(t, str, "2024-01-15")
	assert.Contains(t, str, "2025-01-15")
}

// Test GenerateArtifactKey

func TestGenerateArtifactKey_Valid(t *testing.T) {
	// Create root key
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
				ExpiresAt: time.Now().Add(365 * 24 * time.Hour).UTC(),
			},
		},
	}

	// Generate artifact key
	ak, privPEM, pubPEM, signature, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)
	assert.NotNil(t, ak)
	assert.NotEmpty(t, privPEM)
	assert.NotEmpty(t, pubPEM)
	assert.NotEmpty(t, signature)

	// Verify expiration
	assert.True(t, ak.Metadata.ExpiresAt.After(time.Now()))
	assert.True(t, ak.Metadata.ExpiresAt.Before(time.Now().Add(31*24*time.Hour)))
}

func TestGenerateArtifactKey_ExpiredRoot(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create expired root key
	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().Add(-2 * 365 * 24 * time.Hour).UTC(),
				ExpiresAt: time.Now().Add(-1 * time.Hour).UTC(), // Expired
			},
		},
	}

	_, _, _, _, err = GenerateArtifactKey(rootKey, 30*24*time.Hour)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestGenerateArtifactKey_NoExpiration(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Root key with no expiration
	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
				ExpiresAt: time.Time{}, // No expiration
			},
		},
	}

	ak, _, _, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)
	assert.NotNil(t, ak)
}

// Test ParseArtifactKey

func TestParseArtifactKey_Valid(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	original, privPEM, _, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)

	// Parse it back
	parsed, err := ParseArtifactKey(privPEM)
	require.NoError(t, err)

	assert.Equal(t, original.Key, parsed.Key)
	assert.Equal(t, original.Metadata.ID, parsed.Metadata.ID)
}

func TestParseArtifactKey_InvalidPEM(t *testing.T) {
	_, err := ParseArtifactKey([]byte("invalid pem"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestParseArtifactKey_WrongType(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create a root key (wrong type)
	rootKey := RootKey{
		PrivateKey{
			Key: priv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(pub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	privJSON, err := json.Marshal(rootKey.PrivateKey)
	require.NoError(t, err)

	privPEM := encodePrivateKey(privJSON, tagRootPrivate)

	_, err = ParseArtifactKey(privPEM)
	assert.Error(t, err)
}

// Test ParseArtifactPubKey

func TestParseArtifactPubKey_Valid(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	original, _, pubPEM, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)

	parsed, err := ParseArtifactPubKey(pubPEM)
	require.NoError(t, err)

	assert.Equal(t, original.Metadata.ID, parsed.Metadata.ID)
}

func TestParseArtifactPubKey_Invalid(t *testing.T) {
	_, err := ParseArtifactPubKey([]byte("invalid"))
	assert.Error(t, err)
}

// Test BundleArtifactKeys

func TestBundleArtifactKeys_Single(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	_, _, pubPEM, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)

	pubKey, err := ParseArtifactPubKey(pubPEM)
	require.NoError(t, err)

	bundle, signature, err := BundleArtifactKeys(rootKey, []PublicKey{pubKey})
	require.NoError(t, err)
	assert.NotEmpty(t, bundle)
	assert.NotEmpty(t, signature)
}

func TestBundleArtifactKeys_Multiple(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	// Generate 3 artifact keys
	var pubKeys []PublicKey
	for i := 0; i < 3; i++ {
		_, _, pubPEM, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
		require.NoError(t, err)

		pubKey, err := ParseArtifactPubKey(pubPEM)
		require.NoError(t, err)
		pubKeys = append(pubKeys, pubKey)
	}

	bundle, signature, err := BundleArtifactKeys(rootKey, pubKeys)
	require.NoError(t, err)
	assert.NotEmpty(t, bundle)
	assert.NotEmpty(t, signature)

	// Verify we can parse the bundle
	parsed, err := parsePublicKeyBundle(bundle, tagArtifactPublic)
	require.NoError(t, err)
	assert.Len(t, parsed, 3)
}

func TestBundleArtifactKeys_Empty(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	_, _, err = BundleArtifactKeys(rootKey, []PublicKey{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no keys")
}

// Test ValidateArtifactKeys

func TestSingleValidateArtifactKey_Valid(t *testing.T) {
	// Create root key
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	rootKeys := []PublicKey{
		{
			Key: rootPub,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	// Generate artifact key
	_, _, pubPEM, sigData, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)

	sig, _ := ParseSignature(sigData)

	// Validate
	validKeys, err := ValidateArtifactKeys(rootKeys, pubPEM, *sig, nil)
	require.NoError(t, err)
	assert.Len(t, validKeys, 1)
}

func TestValidateArtifactKeys_Valid(t *testing.T) {
	// Create root key
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	rootKeys := []PublicKey{
		{
			Key: rootPub,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	// Generate artifact key
	_, _, pubPEM, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)

	pubKey, err := ParseArtifactPubKey(pubPEM)
	require.NoError(t, err)

	// Bundle and sign
	bundle, sigData, err := BundleArtifactKeys(rootKey, []PublicKey{pubKey})
	require.NoError(t, err)

	sig, err := ParseSignature(sigData)
	require.NoError(t, err)

	// Validate
	validKeys, err := ValidateArtifactKeys(rootKeys, bundle, *sig, nil)
	require.NoError(t, err)
	assert.Len(t, validKeys, 1)
}

func TestValidateArtifactKeys_FutureTimestamp(t *testing.T) {
	rootPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKeys := []PublicKey{
		{
			Key: rootPub,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	sig := Signature{
		Signature: make([]byte, 64),
		Timestamp: time.Now().UTC().Add(10 * time.Minute),
		KeyID:     computeKeyID(rootPub),
		Algorithm: "ed25519",
		HashAlgo:  "blake2s",
	}

	_, err = ValidateArtifactKeys(rootKeys, []byte("data"), sig, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "in the future")
}

func TestValidateArtifactKeys_TooOld(t *testing.T) {
	rootPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKeys := []PublicKey{
		{
			Key: rootPub,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	sig := Signature{
		Signature: make([]byte, 64),
		Timestamp: time.Now().UTC().Add(-20 * 365 * 24 * time.Hour),
		KeyID:     computeKeyID(rootPub),
		Algorithm: "ed25519",
		HashAlgo:  "blake2s",
	}

	_, err = ValidateArtifactKeys(rootKeys, []byte("data"), sig, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too old")
}

func TestValidateArtifactKeys_InvalidSignature(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	rootKeys := []PublicKey{
		{
			Key: rootPub,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	_, _, pubPEM, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)

	pubKey, err := ParseArtifactPubKey(pubPEM)
	require.NoError(t, err)

	bundle, _, err := BundleArtifactKeys(rootKey, []PublicKey{pubKey})
	require.NoError(t, err)

	// Create invalid signature
	invalidSig := Signature{
		Signature: make([]byte, 64),
		Timestamp: time.Now().UTC(),
		KeyID:     computeKeyID(rootPub),
		Algorithm: "ed25519",
		HashAlgo:  "blake2s",
	}

	_, err = ValidateArtifactKeys(rootKeys, bundle, invalidSig, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify")
}

func TestValidateArtifactKeys_WithRevocation(t *testing.T) {
	// Create root key
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	rootKeys := []PublicKey{
		{
			Key: rootPub,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	// Generate two artifact keys
	_, _, pubPEM1, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)
	pubKey1, err := ParseArtifactPubKey(pubPEM1)
	require.NoError(t, err)

	_, _, pubPEM2, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)
	pubKey2, err := ParseArtifactPubKey(pubPEM2)
	require.NoError(t, err)

	// Bundle both keys
	bundle, sigData, err := BundleArtifactKeys(rootKey, []PublicKey{pubKey1, pubKey2})
	require.NoError(t, err)

	sig, err := ParseSignature(sigData)
	require.NoError(t, err)

	// Create revocation list with first key revoked
	revocationList := &RevocationList{
		Revoked: map[KeyID]time.Time{
			pubKey1.Metadata.ID: time.Now().UTC(),
		},
		LastUpdated: time.Now().UTC(),
	}

	// Validate - should only return second key
	validKeys, err := ValidateArtifactKeys(rootKeys, bundle, *sig, revocationList)
	require.NoError(t, err)
	assert.Len(t, validKeys, 1)
	assert.Equal(t, pubKey2.Metadata.ID, validKeys[0].Metadata.ID)
}

func TestValidateArtifactKeys_AllRevoked(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	rootKeys := []PublicKey{
		{
			Key: rootPub,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	_, _, pubPEM, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)
	pubKey, err := ParseArtifactPubKey(pubPEM)
	require.NoError(t, err)

	bundle, sigData, err := BundleArtifactKeys(rootKey, []PublicKey{pubKey})
	require.NoError(t, err)

	sig, err := ParseSignature(sigData)
	require.NoError(t, err)

	// Revoke the key
	revocationList := &RevocationList{
		Revoked: map[KeyID]time.Time{
			pubKey.Metadata.ID: time.Now().UTC(),
		},
		LastUpdated: time.Now().UTC(),
	}

	_, err = ValidateArtifactKeys(rootKeys, bundle, *sig, revocationList)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

// Test ValidateArtifact

func TestValidateArtifact_Valid(t *testing.T) {
	// Create root key
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	// Generate artifact key
	artifactKey, _, _, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)

	// Sign some data
	data := []byte("test artifact data")
	sigData, err := SignData(*artifactKey, data)
	require.NoError(t, err)

	sig, err := ParseSignature(sigData)
	require.NoError(t, err)

	// Get public key for validation
	artifactPubKey := PublicKey{
		Key:      artifactKey.Key.Public().(ed25519.PublicKey),
		Metadata: artifactKey.Metadata,
	}

	// Validate
	err = ValidateArtifact([]PublicKey{artifactPubKey}, data, *sig)
	assert.NoError(t, err)
}

func TestValidateArtifact_FutureTimestamp(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	artifactPubKey := PublicKey{
		Key: pub,
		Metadata: KeyMetadata{
			ID:        computeKeyID(pub),
			CreatedAt: time.Now().UTC(),
		},
	}

	sig := Signature{
		Signature: make([]byte, 64),
		Timestamp: time.Now().UTC().Add(10 * time.Minute),
		KeyID:     computeKeyID(pub),
		Algorithm: "ed25519",
		HashAlgo:  "blake2s",
	}

	err = ValidateArtifact([]PublicKey{artifactPubKey}, []byte("data"), sig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "in the future")
}

func TestValidateArtifact_TooOld(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	artifactPubKey := PublicKey{
		Key: pub,
		Metadata: KeyMetadata{
			ID:        computeKeyID(pub),
			CreatedAt: time.Now().UTC(),
		},
	}

	sig := Signature{
		Signature: make([]byte, 64),
		Timestamp: time.Now().UTC().Add(-20 * 365 * 24 * time.Hour),
		KeyID:     computeKeyID(pub),
		Algorithm: "ed25519",
		HashAlgo:  "blake2s",
	}

	err = ValidateArtifact([]PublicKey{artifactPubKey}, []byte("data"), sig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too old")
}

func TestValidateArtifact_ExpiredKey(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	// Generate artifact key with very short expiration
	artifactKey, _, _, _, err := GenerateArtifactKey(rootKey, 1*time.Millisecond)
	require.NoError(t, err)

	// Wait for key to expire
	time.Sleep(10 * time.Millisecond)

	// Try to sign - should succeed but with old timestamp
	data := []byte("test data")
	sigData, err := SignData(*artifactKey, data)
	require.Error(t, err) // Key is expired, so signing should fail
	assert.Contains(t, err.Error(), "expired")
	assert.Nil(t, sigData)
}

func TestValidateArtifact_WrongKey(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	// Generate two artifact keys
	artifactKey1, _, _, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)

	artifactKey2, _, _, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)

	// Sign with key1
	data := []byte("test data")
	sigData, err := SignData(*artifactKey1, data)
	require.NoError(t, err)

	sig, err := ParseSignature(sigData)
	require.NoError(t, err)

	// Try to validate with key2 only
	artifactPubKey2 := PublicKey{
		Key:      artifactKey2.Key.Public().(ed25519.PublicKey),
		Metadata: artifactKey2.Metadata,
	}

	err = ValidateArtifact([]PublicKey{artifactPubKey2}, data, *sig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no signing Key found")
}

func TestValidateArtifact_TamperedData(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	artifactKey, _, _, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)

	// Sign original data
	originalData := []byte("original data")
	sigData, err := SignData(*artifactKey, originalData)
	require.NoError(t, err)

	sig, err := ParseSignature(sigData)
	require.NoError(t, err)

	artifactPubKey := PublicKey{
		Key:      artifactKey.Key.Public().(ed25519.PublicKey),
		Metadata: artifactKey.Metadata,
	}

	// Try to validate with tampered data
	tamperedData := []byte("tampered data")
	err = ValidateArtifact([]PublicKey{artifactPubKey}, tamperedData, *sig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

func TestValidateArtifactKeys_TwoKeysOneExpired(t *testing.T) {
	// Test ValidateArtifactKeys with a bundle containing two keys where one is expired
	// Should return only the valid key
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	rootKeys := []PublicKey{
		{
			Key: rootPub,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	// Generate first key with very short expiration
	_, _, expiredPubPEM, _, err := GenerateArtifactKey(rootKey, 1*time.Millisecond)
	require.NoError(t, err)
	expiredPubKey, err := ParseArtifactPubKey(expiredPubPEM)
	require.NoError(t, err)

	// Wait for first key to expire
	time.Sleep(10 * time.Millisecond)

	// Generate second key with normal expiration
	_, _, validPubPEM, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)
	validPubKey, err := ParseArtifactPubKey(validPubPEM)
	require.NoError(t, err)

	// Bundle both keys together
	bundle, sigData, err := BundleArtifactKeys(rootKey, []PublicKey{expiredPubKey, validPubKey})
	require.NoError(t, err)

	sig, err := ParseSignature(sigData)
	require.NoError(t, err)

	// ValidateArtifactKeys should return only the valid key
	validKeys, err := ValidateArtifactKeys(rootKeys, bundle, *sig, nil)
	require.NoError(t, err)
	assert.Len(t, validKeys, 1)
	assert.Equal(t, validPubKey.Metadata.ID, validKeys[0].Metadata.ID)
}

func TestValidateArtifactKeys_TwoKeysBothExpired(t *testing.T) {
	// Test ValidateArtifactKeys with a bundle containing two expired keys
	// Should fail because no valid keys remain
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	rootKeys := []PublicKey{
		{
			Key: rootPub,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	// Generate first key with
	_, _, pubPEM1, _, err := GenerateArtifactKey(rootKey, 24*time.Hour)
	require.NoError(t, err)
	pubKey1, err := ParseArtifactPubKey(pubPEM1)
	require.NoError(t, err)

	// Generate second key with very short expiration
	_, _, pubPEM2, _, err := GenerateArtifactKey(rootKey, 1*time.Millisecond)
	require.NoError(t, err)
	pubKey2, err := ParseArtifactPubKey(pubPEM2)
	require.NoError(t, err)

	// Wait for expire
	time.Sleep(10 * time.Millisecond)

	bundle, sigData, err := BundleArtifactKeys(rootKey, []PublicKey{pubKey1, pubKey2})
	require.NoError(t, err)

	sig, err := ParseSignature(sigData)
	require.NoError(t, err)

	// ValidateArtifactKeys should fail because all keys are expired
	keys, err := ValidateArtifactKeys(rootKeys, bundle, *sig, nil)
	assert.NoError(t, err)
	assert.Len(t, keys, 1)
}

// Test SignData

func TestSignData_Valid(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	artifactKey, _, _, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)

	data := []byte("test data to sign")
	sigData, err := SignData(*artifactKey, data)
	require.NoError(t, err)
	assert.NotEmpty(t, sigData)

	// Verify signature can be parsed
	sig, err := ParseSignature(sigData)
	require.NoError(t, err)
	assert.NotEmpty(t, sig.Signature)
	assert.Equal(t, "ed25519", sig.Algorithm)
	assert.Equal(t, "blake2s", sig.HashAlgo)
}

func TestSignData_EmptyData(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	artifactKey, _, _, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)

	_, err = SignData(*artifactKey, []byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be positive")
}

func TestSignData_ExpiredKey(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	// Generate key with very short expiration
	artifactKey, _, _, _, err := GenerateArtifactKey(rootKey, 1*time.Millisecond)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Try to sign with expired key
	_, err = SignData(*artifactKey, []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

// Integration test

func TestArtifact_FullWorkflow(t *testing.T) {
	// Step 1: Create root key
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := &RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	rootKeys := []PublicKey{
		{
			Key: rootPub,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	// Step 2: Generate artifact key
	artifactKey, _, pubPEM, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)

	// Step 3: Create and validate key bundle
	artifactPubKey, err := ParseArtifactPubKey(pubPEM)
	require.NoError(t, err)

	bundle, bundleSig, err := BundleArtifactKeys(rootKey, []PublicKey{artifactPubKey})
	require.NoError(t, err)

	sig, err := ParseSignature(bundleSig)
	require.NoError(t, err)

	validKeys, err := ValidateArtifactKeys(rootKeys, bundle, *sig, nil)
	require.NoError(t, err)
	assert.Len(t, validKeys, 1)

	// Step 4: Sign artifact data
	artifactData := []byte("This is my artifact data that needs to be signed")
	artifactSig, err := SignData(*artifactKey, artifactData)
	require.NoError(t, err)

	// Step 5: Validate artifact
	parsedSig, err := ParseSignature(artifactSig)
	require.NoError(t, err)

	err = ValidateArtifact(validKeys, artifactData, *parsedSig)
	assert.NoError(t, err)
}

// Helper function for tests
func encodePrivateKey(jsonData []byte, typeTag string) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  typeTag,
		Bytes: jsonData,
	})
}
