package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"time"

	"golang.org/x/crypto/blake2s"
)

const (
	tagArtifactPrivate = "ARTIFACT PRIVATE KEY"
	tagArtifactPublic  = "ARTIFACT PUBLIC KEY"
)

// ArtifactHash wraps a hash.Hash and counts bytes written
type ArtifactHash struct {
	hash.Hash
}

// NewArtifactHash returns an initialized ArtifactHash using BLAKE2s
func NewArtifactHash() *ArtifactHash {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic(err) // Should never happen with nil Key
	}
	return &ArtifactHash{Hash: h}
}

func (ah *ArtifactHash) Write(b []byte) (int, error) {
	return ah.Hash.Write(b)
}

// ArtifactKey is a signing Key used to sign artifacts
type ArtifactKey struct {
	PrivateKey
}

func (k ArtifactKey) String() string {
	return fmt.Sprintf(
		"ArtifactKey[ID=%s, CreatedAt=%s, ExpiresAt=%s]",
		k.Metadata.ID,
		k.Metadata.CreatedAt.Format(time.RFC3339),
		k.Metadata.ExpiresAt.Format(time.RFC3339),
	)
}

func GenerateArtifactKey(rootKey *RootKey, expiration time.Duration) (*ArtifactKey, []byte, []byte, []byte, error) {
	// Verify root key is still valid
	if !rootKey.Metadata.ExpiresAt.IsZero() && time.Now().After(rootKey.Metadata.ExpiresAt) {
		return nil, nil, nil, nil, fmt.Errorf("root key has expired on %s", rootKey.Metadata.ExpiresAt.Format(time.RFC3339))
	}

	now := time.Now()
	expirationTime := now.Add(expiration)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	metadata := KeyMetadata{
		ID:        computeKeyID(pub),
		CreatedAt: now.UTC(),
		ExpiresAt: expirationTime.UTC(),
	}

	ak := &ArtifactKey{
		PrivateKey{
			Key:      priv,
			Metadata: metadata,
		},
	}

	// Marshal PrivateKey struct to JSON
	privJSON, err := json.Marshal(ak.PrivateKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Marshal PublicKey struct to JSON
	pubKey := PublicKey{
		Key:      pub,
		Metadata: metadata,
	}
	pubJSON, err := json.Marshal(pubKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Encode to PEM with metadata embedded in bytes
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  tagArtifactPrivate,
		Bytes: privJSON,
	})

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  tagArtifactPublic,
		Bytes: pubJSON,
	})

	// Sign the public key with the root key
	signature, err := SignArtifactKey(*rootKey, pubJSON)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to sign artifact key: %w", err)
	}

	return ak, privPEM, pubPEM, signature, nil
}

func ParseArtifactKey(privKeyPEM []byte) (ArtifactKey, error) {
	pk, err := parsePrivateKey(privKeyPEM, tagArtifactPrivate)
	if err != nil {
		return ArtifactKey{}, fmt.Errorf("failed to parse artifact Key: %w", err)
	}
	return ArtifactKey{pk}, nil
}

func ParseArtifactPubKey(data []byte) (PublicKey, error) {
	pk, _, err := parsePublicKey(data, tagArtifactPublic)
	return pk, err
}

func BundleArtifactKeys(rootKey *RootKey, keys []PublicKey) ([]byte, []byte, error) {
	if len(keys) == 0 {
		return nil, nil, errors.New("no keys to bundle")
	}

	// Create bundle by concatenating PEM-encoded keys
	var pubBundle []byte

	for _, pk := range keys {
		// Marshal PublicKey struct to JSON
		pubJSON, err := json.Marshal(pk)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
		}

		// Encode to PEM
		pubPEM := pem.EncodeToMemory(&pem.Block{
			Type:  tagArtifactPublic,
			Bytes: pubJSON,
		})

		pubBundle = append(pubBundle, pubPEM...)
	}

	// Sign the entire bundle with the root key
	signature, err := SignArtifactKey(*rootKey, pubBundle)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign artifact key bundle: %w", err)
	}

	return pubBundle, signature, nil
}

func SignData(artifactKey ArtifactKey, data []byte) ([]byte, error) {
	h := NewArtifactHash()
	if _, err := h.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write artifact hash: %w", err)
	}
	return signArtifactHash(artifactKey, h.Sum(nil), len(data))
}

// signArtifactHash signs the hash and length of an artifact with timestamp
func signArtifactHash(key ArtifactKey, hash []byte, length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("artifact length must be positive, got %d", length)
	}

	timestamp := time.Now().UTC()

	// Create message: hash || length || timestamp
	msg := make([]byte, 0, len(hash)+8+8)
	msg = append(msg, hash...)
	msg = binary.LittleEndian.AppendUint64(msg, uint64(length))
	msg = binary.LittleEndian.AppendUint64(msg, uint64(timestamp.Unix()))

	sig := ed25519.Sign(key.Key, msg)

	bundle := Signature{
		Signature: sig,
		Timestamp: timestamp,
		KeyID:     key.Metadata.ID,
		Algorithm: "ed25519",
		HashAlgo:  "blake2s",
	}

	return json.Marshal(bundle)
}
