package reposign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test RootKey.String()

func TestRootKey_String(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	createdAt := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	expiresAt := time.Date(2034, 1, 15, 10, 30, 0, 0, time.UTC)

	rk := RootKey{
		PrivateKey{
			Key: priv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(pub),
				CreatedAt: createdAt,
				ExpiresAt: expiresAt,
			},
		},
	}

	str := rk.String()
	assert.Contains(t, str, "RootKey")
	assert.Contains(t, str, computeKeyID(pub).String())
	assert.Contains(t, str, "2024-01-15")
	assert.Contains(t, str, "2034-01-15")
}

func TestRootKey_String_NoExpiration(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	createdAt := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	rk := RootKey{
		PrivateKey{
			Key: priv,
			Metadata: KeyMetadata{
				ID:        computeKeyID(pub),
				CreatedAt: createdAt,
				ExpiresAt: time.Time{}, // No expiration
			},
		},
	}

	str := rk.String()
	assert.Contains(t, str, "RootKey")
	assert.Contains(t, str, "0001-01-01") // Zero time format
}

// Test GenerateRootKey

func TestGenerateRootKey_Valid(t *testing.T) {
	expiration := 10 * 365 * 24 * time.Hour // 10 years

	rk, privPEM, pubPEM, err := GenerateRootKey(expiration)
	require.NoError(t, err)
	assert.NotNil(t, rk)
	assert.NotEmpty(t, privPEM)
	assert.NotEmpty(t, pubPEM)

	// Verify the key has correct metadata
	assert.False(t, rk.Metadata.CreatedAt.IsZero())
	assert.False(t, rk.Metadata.ExpiresAt.IsZero())
	assert.True(t, rk.Metadata.ExpiresAt.After(rk.Metadata.CreatedAt))

	// Verify expiration is approximately correct
	expectedExpiration := time.Now().Add(expiration)
	timeDiff := rk.Metadata.ExpiresAt.Sub(expectedExpiration)
	assert.True(t, timeDiff < time.Minute && timeDiff > -time.Minute)
}

func TestGenerateRootKey_ShortExpiration(t *testing.T) {
	expiration := 24 * time.Hour // 1 day

	rk, _, _, err := GenerateRootKey(expiration)
	require.NoError(t, err)
	assert.NotNil(t, rk)

	// Verify expiration
	expectedExpiration := time.Now().Add(expiration)
	timeDiff := rk.Metadata.ExpiresAt.Sub(expectedExpiration)
	assert.True(t, timeDiff < time.Minute && timeDiff > -time.Minute)
}

func TestGenerateRootKey_ZeroExpiration(t *testing.T) {
	rk, _, _, err := GenerateRootKey(0)
	require.NoError(t, err)
	assert.NotNil(t, rk)

	// With zero expiration, ExpiresAt should be equal to CreatedAt
	assert.Equal(t, rk.Metadata.CreatedAt, rk.Metadata.ExpiresAt)
}

func TestGenerateRootKey_PEMFormat(t *testing.T) {
	rk, privPEM, pubPEM, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	// Verify private key PEM
	privBlock, _ := pem.Decode(privPEM)
	require.NotNil(t, privBlock)
	assert.Equal(t, tagRootPrivate, privBlock.Type)

	var privKey PrivateKey
	err = json.Unmarshal(privBlock.Bytes, &privKey)
	require.NoError(t, err)
	assert.Equal(t, rk.Key, privKey.Key)

	// Verify public key PEM
	pubBlock, _ := pem.Decode(pubPEM)
	require.NotNil(t, pubBlock)
	assert.Equal(t, tagRootPublic, pubBlock.Type)

	var pubKey PublicKey
	err = json.Unmarshal(pubBlock.Bytes, &pubKey)
	require.NoError(t, err)
	assert.Equal(t, rk.Metadata.ID, pubKey.Metadata.ID)
}

func TestGenerateRootKey_KeySize(t *testing.T) {
	rk, _, _, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	// Ed25519 private key should be 64 bytes
	assert.Equal(t, ed25519.PrivateKeySize, len(rk.Key))

	// Ed25519 public key should be 32 bytes
	pubKey := rk.Key.Public().(ed25519.PublicKey)
	assert.Equal(t, ed25519.PublicKeySize, len(pubKey))
}

func TestGenerateRootKey_UniqueKeys(t *testing.T) {
	rk1, _, _, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	rk2, _, _, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	// Different keys should have different IDs
	assert.NotEqual(t, rk1.Metadata.ID, rk2.Metadata.ID)
	assert.NotEqual(t, rk1.Key, rk2.Key)
}

// Test ParseRootKey

func TestParseRootKey_Valid(t *testing.T) {
	original, privPEM, _, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	parsed, err := ParseRootKey(privPEM)
	require.NoError(t, err)
	assert.NotNil(t, parsed)

	// Verify the parsed key matches the original
	assert.Equal(t, original.Key, parsed.Key)
	assert.Equal(t, original.Metadata.ID, parsed.Metadata.ID)
	assert.Equal(t, original.Metadata.CreatedAt.Unix(), parsed.Metadata.CreatedAt.Unix())
	assert.Equal(t, original.Metadata.ExpiresAt.Unix(), parsed.Metadata.ExpiresAt.Unix())
}

func TestParseRootKey_InvalidPEM(t *testing.T) {
	_, err := ParseRootKey([]byte("not a valid PEM"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestParseRootKey_EmptyData(t *testing.T) {
	_, err := ParseRootKey([]byte{})
	assert.Error(t, err)
}

func TestParseRootKey_WrongType(t *testing.T) {
	// Generate an artifact key instead of root key
	rootKey, _, _, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	artifactKey, privPEM, _, _, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)

	// Try to parse artifact key as root key
	_, err = ParseRootKey(privPEM)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PEM type")

	// Just to use artifactKey to avoid unused variable warning
	_ = artifactKey
}

func TestParseRootKey_CorruptedJSON(t *testing.T) {
	// Create PEM with corrupted JSON
	corruptedPEM := pem.EncodeToMemory(&pem.Block{
		Type:  tagRootPrivate,
		Bytes: []byte("corrupted json data"),
	})

	_, err := ParseRootKey(corruptedPEM)
	assert.Error(t, err)
}

func TestParseRootKey_InvalidKeySize(t *testing.T) {
	// Create a key with invalid size
	invalidKey := PrivateKey{
		Key: []byte{0x01, 0x02, 0x03}, // Too short
		Metadata: KeyMetadata{
			ID:        KeyID{},
			CreatedAt: time.Now().UTC(),
		},
	}

	privJSON, err := json.Marshal(invalidKey)
	require.NoError(t, err)

	invalidPEM := pem.EncodeToMemory(&pem.Block{
		Type:  tagRootPrivate,
		Bytes: privJSON,
	})

	_, err = ParseRootKey(invalidPEM)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "incorrect Ed25519 private key size")
}

func TestParseRootKey_Roundtrip(t *testing.T) {
	// Generate a key
	original, privPEM, _, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	// Parse it
	parsed, err := ParseRootKey(privPEM)
	require.NoError(t, err)

	// Generate PEM again from parsed key
	privJSON2, err := json.Marshal(parsed.PrivateKey)
	require.NoError(t, err)

	privPEM2 := pem.EncodeToMemory(&pem.Block{
		Type:  tagRootPrivate,
		Bytes: privJSON2,
	})

	// Parse again
	parsed2, err := ParseRootKey(privPEM2)
	require.NoError(t, err)

	// Should still match original
	assert.Equal(t, original.Key, parsed2.Key)
	assert.Equal(t, original.Metadata.ID, parsed2.Metadata.ID)
}

// Test SignArtifactKey

func TestSignArtifactKey_Valid(t *testing.T) {
	rootKey, _, _, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	data := []byte("test data to sign")
	sigData, err := SignArtifactKey(*rootKey, data)
	require.NoError(t, err)
	assert.NotEmpty(t, sigData)

	// Parse and verify signature
	sig, err := ParseSignature(sigData)
	require.NoError(t, err)
	assert.NotEmpty(t, sig.Signature)
	assert.Equal(t, rootKey.Metadata.ID, sig.KeyID)
	assert.Equal(t, "ed25519", sig.Algorithm)
	assert.Equal(t, "sha512", sig.HashAlgo)
	assert.False(t, sig.Timestamp.IsZero())
}

func TestSignArtifactKey_EmptyData(t *testing.T) {
	rootKey, _, _, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	sigData, err := SignArtifactKey(*rootKey, []byte{})
	require.NoError(t, err)
	assert.NotEmpty(t, sigData)

	// Should still be able to parse
	sig, err := ParseSignature(sigData)
	require.NoError(t, err)
	assert.NotEmpty(t, sig.Signature)
}

func TestSignArtifactKey_Verify(t *testing.T) {
	rootKey, _, pubPEM, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	// Parse public key
	pubKey, _, err := parsePublicKey(pubPEM, tagRootPublic)
	require.NoError(t, err)

	// Sign some data
	data := []byte("test data for verification")
	sigData, err := SignArtifactKey(*rootKey, data)
	require.NoError(t, err)

	// Parse signature
	sig, err := ParseSignature(sigData)
	require.NoError(t, err)

	// Reconstruct message
	msg := make([]byte, 0, len(data)+8)
	msg = append(msg, data...)
	msg = binary.LittleEndian.AppendUint64(msg, uint64(sig.Timestamp.Unix()))

	// Verify signature
	valid := ed25519.Verify(pubKey.Key, msg, sig.Signature)
	assert.True(t, valid)
}

func TestSignArtifactKey_DifferentData(t *testing.T) {
	rootKey, _, _, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	data1 := []byte("data1")
	data2 := []byte("data2")

	sig1, err := SignArtifactKey(*rootKey, data1)
	require.NoError(t, err)

	sig2, err := SignArtifactKey(*rootKey, data2)
	require.NoError(t, err)

	// Different data should produce different signatures
	assert.NotEqual(t, sig1, sig2)
}

func TestSignArtifactKey_MultipleSignatures(t *testing.T) {
	rootKey, _, _, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	data := []byte("test data")

	// Sign twice with a small delay
	sig1, err := SignArtifactKey(*rootKey, data)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	sig2, err := SignArtifactKey(*rootKey, data)
	require.NoError(t, err)

	// Signatures should be different due to different timestamps
	assert.NotEqual(t, sig1, sig2)

	// Parse both signatures
	parsed1, err := ParseSignature(sig1)
	require.NoError(t, err)

	parsed2, err := ParseSignature(sig2)
	require.NoError(t, err)

	// Timestamps should be different
	assert.True(t, parsed2.Timestamp.After(parsed1.Timestamp))
}

func TestSignArtifactKey_LargeData(t *testing.T) {
	rootKey, _, _, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	// Create 1MB of data
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	sigData, err := SignArtifactKey(*rootKey, largeData)
	require.NoError(t, err)
	assert.NotEmpty(t, sigData)

	// Verify signature can be parsed
	sig, err := ParseSignature(sigData)
	require.NoError(t, err)
	assert.NotEmpty(t, sig.Signature)
}

func TestSignArtifactKey_TimestampInSignature(t *testing.T) {
	rootKey, _, _, err := GenerateRootKey(365 * 24 * time.Hour)
	require.NoError(t, err)

	beforeSign := time.Now().UTC()
	data := []byte("test data")
	sigData, err := SignArtifactKey(*rootKey, data)
	require.NoError(t, err)
	afterSign := time.Now().UTC()

	sig, err := ParseSignature(sigData)
	require.NoError(t, err)

	// Timestamp should be between before and after
	assert.True(t, sig.Timestamp.After(beforeSign.Add(-time.Second)))
	assert.True(t, sig.Timestamp.Before(afterSign.Add(time.Second)))
}

// Integration test

func TestRootKey_FullWorkflow(t *testing.T) {
	// Step 1: Generate root key
	rootKey, privPEM, pubPEM, err := GenerateRootKey(10 * 365 * 24 * time.Hour)
	require.NoError(t, err)
	assert.NotNil(t, rootKey)
	assert.NotEmpty(t, privPEM)
	assert.NotEmpty(t, pubPEM)

	// Step 2: Parse the private key back
	parsedRootKey, err := ParseRootKey(privPEM)
	require.NoError(t, err)
	assert.Equal(t, rootKey.Key, parsedRootKey.Key)
	assert.Equal(t, rootKey.Metadata.ID, parsedRootKey.Metadata.ID)

	// Step 3: Generate an artifact key using root key
	artifactKey, _, artifactPubPEM, artifactSig, err := GenerateArtifactKey(rootKey, 30*24*time.Hour)
	require.NoError(t, err)
	assert.NotNil(t, artifactKey)

	// Step 4: Verify the artifact key signature
	pubKey, _, err := parsePublicKey(pubPEM, tagRootPublic)
	require.NoError(t, err)

	sig, err := ParseSignature(artifactSig)
	require.NoError(t, err)

	artifactPubKey, _, err := parsePublicKey(artifactPubPEM, tagArtifactPublic)
	require.NoError(t, err)

	// Reconstruct message - SignArtifactKey signs the PEM, not the JSON
	msg := make([]byte, 0, len(artifactPubPEM)+8)
	msg = append(msg, artifactPubPEM...)
	msg = binary.LittleEndian.AppendUint64(msg, uint64(sig.Timestamp.Unix()))

	// Verify with root public key
	valid := ed25519.Verify(pubKey.Key, msg, sig.Signature)
	assert.True(t, valid, "Artifact key signature should be valid")

	// Step 5: Use artifact key to sign data
	testData := []byte("This is test artifact data")
	dataSig, err := SignData(*artifactKey, testData)
	require.NoError(t, err)
	assert.NotEmpty(t, dataSig)

	// Step 6: Verify the artifact data signature
	dataSigParsed, err := ParseSignature(dataSig)
	require.NoError(t, err)

	err = ValidateArtifact([]PublicKey{artifactPubKey}, testData, *dataSigParsed)
	assert.NoError(t, err, "Artifact data signature should be valid")
}

func TestRootKey_ExpiredKeyWorkflow(t *testing.T) {
	// Generate a root key that expires very soon
	rootKey, _, _, err := GenerateRootKey(1 * time.Millisecond)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Try to generate artifact key with expired root key
	_, _, _, _, err = GenerateArtifactKey(rootKey, 30*24*time.Hour)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}
