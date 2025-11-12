package reposign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test RevocationList marshaling/unmarshaling

func TestRevocationList_MarshalJSON(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyID := computeKeyID(pub)
	revokedTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	lastUpdated := time.Date(2024, 1, 15, 11, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2024, 4, 15, 11, 0, 0, 0, time.UTC)

	rl := &RevocationList{
		Revoked: map[KeyID]time.Time{
			keyID: revokedTime,
		},
		LastUpdated: lastUpdated,
		ExpiresAt:   expiresAt,
	}

	jsonData, err := json.Marshal(rl)
	require.NoError(t, err)

	// Verify it can be unmarshaled back
	var decoded map[string]interface{}
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)

	assert.Contains(t, decoded, "revoked")
	assert.Contains(t, decoded, "last_updated")
	assert.Contains(t, decoded, "expires_at")
}

func TestRevocationList_UnmarshalJSON(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyID := computeKeyID(pub)
	revokedTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	lastUpdated := time.Date(2024, 1, 15, 11, 0, 0, 0, time.UTC)

	jsonData := map[string]interface{}{
		"revoked": map[string]string{
			keyID.String(): revokedTime.Format(time.RFC3339),
		},
		"last_updated": lastUpdated.Format(time.RFC3339),
	}

	jsonBytes, err := json.Marshal(jsonData)
	require.NoError(t, err)

	var rl RevocationList
	err = json.Unmarshal(jsonBytes, &rl)
	require.NoError(t, err)

	assert.Len(t, rl.Revoked, 1)
	assert.Contains(t, rl.Revoked, keyID)
	assert.Equal(t, lastUpdated.Unix(), rl.LastUpdated.Unix())
}

func TestRevocationList_MarshalUnmarshal_Roundtrip(t *testing.T) {
	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyID1 := computeKeyID(pub1)
	keyID2 := computeKeyID(pub2)

	original := &RevocationList{
		Revoked: map[KeyID]time.Time{
			keyID1: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			keyID2: time.Date(2024, 2, 20, 14, 45, 0, 0, time.UTC),
		},
		LastUpdated: time.Date(2024, 2, 20, 15, 0, 0, 0, time.UTC),
	}

	// Marshal
	jsonData, err := original.MarshalJSON()
	require.NoError(t, err)

	// Unmarshal
	var decoded RevocationList
	err = decoded.UnmarshalJSON(jsonData)
	require.NoError(t, err)

	// Verify
	assert.Len(t, decoded.Revoked, 2)
	assert.Equal(t, original.Revoked[keyID1].Unix(), decoded.Revoked[keyID1].Unix())
	assert.Equal(t, original.Revoked[keyID2].Unix(), decoded.Revoked[keyID2].Unix())
	assert.Equal(t, original.LastUpdated.Unix(), decoded.LastUpdated.Unix())
}

func TestRevocationList_UnmarshalJSON_InvalidKeyID(t *testing.T) {
	jsonData := []byte(`{
		"revoked": {
			"invalid_key_id": "2024-01-15T10:30:00Z"
		},
		"last_updated": "2024-01-15T11:00:00Z"
	}`)

	var rl RevocationList
	err := json.Unmarshal(jsonData, &rl)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse KeyID")
}

func TestRevocationList_EmptyRevoked(t *testing.T) {
	rl := &RevocationList{
		Revoked:     make(map[KeyID]time.Time),
		LastUpdated: time.Now().UTC(),
	}

	jsonData, err := rl.MarshalJSON()
	require.NoError(t, err)

	var decoded RevocationList
	err = decoded.UnmarshalJSON(jsonData)
	require.NoError(t, err)

	assert.Empty(t, decoded.Revoked)
	assert.NotNil(t, decoded.Revoked)
}

// Test ParseRevocationList

func TestParseRevocationList_Valid(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyID := computeKeyID(pub)
	revokedTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	lastUpdated := time.Date(2024, 1, 15, 11, 0, 0, 0, time.UTC)

	rl := RevocationList{
		Revoked: map[KeyID]time.Time{
			keyID: revokedTime,
		},
		LastUpdated: lastUpdated,
		ExpiresAt:   time.Date(2025, 2, 20, 14, 45, 0, 0, time.UTC),
	}

	jsonData, err := rl.MarshalJSON()
	require.NoError(t, err)

	parsed, err := ParseRevocationList(jsonData)
	require.NoError(t, err)
	assert.NotNil(t, parsed)
	assert.Len(t, parsed.Revoked, 1)
	assert.Equal(t, lastUpdated.Unix(), parsed.LastUpdated.Unix())
}

func TestParseRevocationList_InvalidJSON(t *testing.T) {
	invalidJSON := []byte("not valid json")

	_, err := ParseRevocationList(invalidJSON)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal")
}

func TestParseRevocationList_MissingLastUpdated(t *testing.T) {
	jsonData := []byte(`{
		"revoked": {}
	}`)

	_, err := ParseRevocationList(jsonData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing last_updated")
}

func TestParseRevocationList_EmptyObject(t *testing.T) {
	jsonData := []byte(`{}`)

	_, err := ParseRevocationList(jsonData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing last_updated")
}

func TestParseRevocationList_NilRevoked(t *testing.T) {
	lastUpdated := time.Now().UTC()
	expiresAt := lastUpdated.Add(90 * 24 * time.Hour)
	jsonData := []byte(`{
		"last_updated": "` + lastUpdated.Format(time.RFC3339) + `",
		"expires_at": "` + expiresAt.Format(time.RFC3339) + `"
	}`)

	parsed, err := ParseRevocationList(jsonData)
	require.NoError(t, err)
	assert.NotNil(t, parsed.Revoked)
	assert.Empty(t, parsed.Revoked)
}

func TestParseRevocationList_MissingExpiresAt(t *testing.T) {
	lastUpdated := time.Now().UTC()
	jsonData := []byte(`{
		"revoked": {},
		"last_updated": "` + lastUpdated.Format(time.RFC3339) + `"
	}`)

	_, err := ParseRevocationList(jsonData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing expires_at")
}

// Test ValidateRevocationList

func TestValidateRevocationList_Valid(t *testing.T) {
	// Generate root key
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := RootKey{
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

	// Create revocation list
	rlData, sigData, err := CreateRevocationList(rootKey, defaultRevocationListExpiration)
	require.NoError(t, err)

	signature, err := ParseSignature(sigData)
	require.NoError(t, err)

	// Validate
	rl, err := ValidateRevocationList(rootKeys, rlData, *signature)
	require.NoError(t, err)
	assert.NotNil(t, rl)
	assert.Empty(t, rl.Revoked)
}

func TestValidateRevocationList_InvalidSignature(t *testing.T) {
	// Generate root key
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := RootKey{
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

	// Create revocation list
	rlData, _, err := CreateRevocationList(rootKey, defaultRevocationListExpiration)
	require.NoError(t, err)

	// Create invalid signature
	invalidSig := Signature{
		Signature: make([]byte, 64),
		Timestamp: time.Now().UTC(),
		KeyID:     computeKeyID(rootPub),
		Algorithm: "ed25519",
		HashAlgo:  "sha512",
	}

	// Validate should fail
	_, err = ValidateRevocationList(rootKeys, rlData, invalidSig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

func TestValidateRevocationList_FutureTimestamp(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := RootKey{
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

	rlData, sigData, err := CreateRevocationList(rootKey, defaultRevocationListExpiration)
	require.NoError(t, err)

	signature, err := ParseSignature(sigData)
	require.NoError(t, err)

	// Modify timestamp to be in the future
	signature.Timestamp = time.Now().UTC().Add(10 * time.Minute)

	_, err = ValidateRevocationList(rootKeys, rlData, *signature)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "in the future")
}

func TestValidateRevocationList_TooOld(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := RootKey{
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

	rlData, sigData, err := CreateRevocationList(rootKey, defaultRevocationListExpiration)
	require.NoError(t, err)

	signature, err := ParseSignature(sigData)
	require.NoError(t, err)

	// Modify timestamp to be too old
	signature.Timestamp = time.Now().UTC().Add(-20 * 365 * 24 * time.Hour)

	_, err = ValidateRevocationList(rootKeys, rlData, *signature)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too old")
}

func TestValidateRevocationList_InvalidJSON(t *testing.T) {
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

	signature := Signature{
		Signature: make([]byte, 64),
		Timestamp: time.Now().UTC(),
		KeyID:     computeKeyID(rootPub),
		Algorithm: "ed25519",
		HashAlgo:  "sha512",
	}

	_, err = ValidateRevocationList(rootKeys, []byte("invalid json"), signature)
	assert.Error(t, err)
}

func TestValidateRevocationList_FutureLastUpdated(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := RootKey{
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

	// Create revocation list with future LastUpdated
	rl := RevocationList{
		Revoked:     make(map[KeyID]time.Time),
		LastUpdated: time.Now().UTC().Add(10 * time.Minute),
		ExpiresAt:   time.Now().UTC().Add(365 * 24 * time.Hour),
	}

	rlData, err := json.Marshal(rl)
	require.NoError(t, err)

	// Sign it
	sig, err := signRevocationList(rootKey, rl)
	require.NoError(t, err)

	_, err = ValidateRevocationList(rootKeys, rlData, *sig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "LastUpdated is in the future")
}

func TestValidateRevocationList_TimestampMismatch(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := RootKey{
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

	// Create revocation list with LastUpdated far in the past
	rl := RevocationList{
		Revoked:     make(map[KeyID]time.Time),
		LastUpdated: time.Now().UTC().Add(-1 * time.Hour),
		ExpiresAt:   time.Now().UTC().Add(365 * 24 * time.Hour),
	}

	rlData, err := json.Marshal(rl)
	require.NoError(t, err)

	// Sign it with current timestamp
	sig, err := signRevocationList(rootKey, rl)
	require.NoError(t, err)

	// Modify signature timestamp to differ too much from LastUpdated
	sig.Timestamp = time.Now().UTC()

	_, err = ValidateRevocationList(rootKeys, rlData, *sig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "differs too much")
}

func TestValidateRevocationList_Expired(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := RootKey{
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

	// Create revocation list that expired in the past
	now := time.Now().UTC()
	rl := RevocationList{
		Revoked:     make(map[KeyID]time.Time),
		LastUpdated: now.Add(-100 * 24 * time.Hour),
		ExpiresAt:   now.Add(-10 * 24 * time.Hour), // Expired 10 days ago
	}

	rlData, err := json.Marshal(rl)
	require.NoError(t, err)

	// Sign it
	sig, err := signRevocationList(rootKey, rl)
	require.NoError(t, err)
	// Adjust signature timestamp to match LastUpdated
	sig.Timestamp = rl.LastUpdated

	_, err = ValidateRevocationList(rootKeys, rlData, *sig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestValidateRevocationList_ExpiresAtTooFarInFuture(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := RootKey{
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

	// Create revocation list with ExpiresAt too far in the future (beyond maxRevocationSignatureAge)
	now := time.Now().UTC()
	rl := RevocationList{
		Revoked:     make(map[KeyID]time.Time),
		LastUpdated: now,
		ExpiresAt:   now.Add(15 * 365 * 24 * time.Hour), // 15 years in the future
	}

	rlData, err := json.Marshal(rl)
	require.NoError(t, err)

	// Sign it
	sig, err := signRevocationList(rootKey, rl)
	require.NoError(t, err)

	_, err = ValidateRevocationList(rootKeys, rlData, *sig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too far in the future")
}

// Test CreateRevocationList

func TestCreateRevocationList_Valid(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	rlData, sigData, err := CreateRevocationList(rootKey, defaultRevocationListExpiration)
	require.NoError(t, err)
	assert.NotEmpty(t, rlData)
	assert.NotEmpty(t, sigData)

	// Verify it can be parsed
	rl, err := ParseRevocationList(rlData)
	require.NoError(t, err)
	assert.Empty(t, rl.Revoked)
	assert.False(t, rl.LastUpdated.IsZero())

	// Verify signature can be parsed
	sig, err := ParseSignature(sigData)
	require.NoError(t, err)
	assert.NotEmpty(t, sig.Signature)
}

// Test ExtendRevocationList

func TestExtendRevocationList_AddKey(t *testing.T) {
	// Generate root key
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	// Create empty revocation list
	rlData, _, err := CreateRevocationList(rootKey, defaultRevocationListExpiration)
	require.NoError(t, err)

	rl, err := ParseRevocationList(rlData)
	require.NoError(t, err)
	assert.Empty(t, rl.Revoked)

	// Generate a key to revoke
	revokedPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	revokedKeyID := computeKeyID(revokedPub)

	// Extend the revocation list
	newRLData, newSigData, err := ExtendRevocationList(rootKey, *rl, revokedKeyID, defaultRevocationListExpiration)
	require.NoError(t, err)

	// Verify the new list
	newRL, err := ParseRevocationList(newRLData)
	require.NoError(t, err)
	assert.Len(t, newRL.Revoked, 1)
	assert.Contains(t, newRL.Revoked, revokedKeyID)

	// Verify signature
	sig, err := ParseSignature(newSigData)
	require.NoError(t, err)
	assert.NotEmpty(t, sig.Signature)
}

func TestExtendRevocationList_MultipleKeys(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	// Create empty revocation list
	rlData, _, err := CreateRevocationList(rootKey, defaultRevocationListExpiration)
	require.NoError(t, err)

	rl, err := ParseRevocationList(rlData)
	require.NoError(t, err)

	// Add first key
	key1Pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key1ID := computeKeyID(key1Pub)

	rlData, _, err = ExtendRevocationList(rootKey, *rl, key1ID, defaultRevocationListExpiration)
	require.NoError(t, err)

	rl, err = ParseRevocationList(rlData)
	require.NoError(t, err)
	assert.Len(t, rl.Revoked, 1)

	// Add second key
	key2Pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key2ID := computeKeyID(key2Pub)

	rlData, _, err = ExtendRevocationList(rootKey, *rl, key2ID, defaultRevocationListExpiration)
	require.NoError(t, err)

	rl, err = ParseRevocationList(rlData)
	require.NoError(t, err)
	assert.Len(t, rl.Revoked, 2)
	assert.Contains(t, rl.Revoked, key1ID)
	assert.Contains(t, rl.Revoked, key2ID)
}

func TestExtendRevocationList_DuplicateKey(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	// Create empty revocation list
	rlData, _, err := CreateRevocationList(rootKey, defaultRevocationListExpiration)
	require.NoError(t, err)

	rl, err := ParseRevocationList(rlData)
	require.NoError(t, err)

	// Add a key
	keyPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := computeKeyID(keyPub)

	rlData, _, err = ExtendRevocationList(rootKey, *rl, keyID, defaultRevocationListExpiration)
	require.NoError(t, err)

	rl, err = ParseRevocationList(rlData)
	require.NoError(t, err)
	firstRevocationTime := rl.Revoked[keyID]

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Add the same key again
	rlData, _, err = ExtendRevocationList(rootKey, *rl, keyID, defaultRevocationListExpiration)
	require.NoError(t, err)

	rl, err = ParseRevocationList(rlData)
	require.NoError(t, err)
	assert.Len(t, rl.Revoked, 1)

	// The revocation time should be updated
	secondRevocationTime := rl.Revoked[keyID]
	assert.True(t, secondRevocationTime.After(firstRevocationTime) || secondRevocationTime.Equal(firstRevocationTime))
}

func TestExtendRevocationList_UpdatesLastUpdated(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := RootKey{
		PrivateKey{
			Key: rootPriv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(rootPub),
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	// Create revocation list
	rlData, _, err := CreateRevocationList(rootKey, defaultRevocationListExpiration)
	require.NoError(t, err)

	rl, err := ParseRevocationList(rlData)
	require.NoError(t, err)
	firstLastUpdated := rl.LastUpdated

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Extend list
	keyPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyID := computeKeyID(keyPub)

	rlData, _, err = ExtendRevocationList(rootKey, *rl, keyID, defaultRevocationListExpiration)
	require.NoError(t, err)

	rl, err = ParseRevocationList(rlData)
	require.NoError(t, err)

	// LastUpdated should be updated
	assert.True(t, rl.LastUpdated.After(firstLastUpdated))
}

// Integration test

func TestRevocationList_FullWorkflow(t *testing.T) {
	// Create root key
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rootKey := RootKey{
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

	// Step 1: Create empty revocation list
	rlData, sigData, err := CreateRevocationList(rootKey, defaultRevocationListExpiration)
	require.NoError(t, err)

	// Step 2: Validate it
	sig, err := ParseSignature(sigData)
	require.NoError(t, err)

	rl, err := ValidateRevocationList(rootKeys, rlData, *sig)
	require.NoError(t, err)
	assert.Empty(t, rl.Revoked)

	// Step 3: Revoke a key
	revokedPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	revokedKeyID := computeKeyID(revokedPub)

	rlData, sigData, err = ExtendRevocationList(rootKey, *rl, revokedKeyID, defaultRevocationListExpiration)
	require.NoError(t, err)

	// Step 4: Validate the extended list
	sig, err = ParseSignature(sigData)
	require.NoError(t, err)

	rl, err = ValidateRevocationList(rootKeys, rlData, *sig)
	require.NoError(t, err)
	assert.Len(t, rl.Revoked, 1)
	assert.Contains(t, rl.Revoked, revokedKeyID)

	// Step 5: Verify the revocation time is reasonable
	revTime := rl.Revoked[revokedKeyID]
	now := time.Now().UTC()
	assert.True(t, revTime.Before(now) || revTime.Equal(now))
	assert.True(t, now.Sub(revTime) < time.Minute)
}
