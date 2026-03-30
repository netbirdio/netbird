package reposign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"
)

const (
	tagRootPrivate = "ROOT PRIVATE KEY"
	tagRootPublic  = "ROOT PUBLIC KEY"
)

// RootKey is a root Key used to sign signing keys
type RootKey struct {
	PrivateKey
}

func (k RootKey) String() string {
	return fmt.Sprintf(
		"RootKey[ID=%s, CreatedAt=%s, ExpiresAt=%s]",
		k.Metadata.ID,
		k.Metadata.CreatedAt.Format(time.RFC3339),
		k.Metadata.ExpiresAt.Format(time.RFC3339),
	)
}

func ParseRootKey(privKeyPEM []byte) (*RootKey, error) {
	pk, err := parsePrivateKey(privKeyPEM, tagRootPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root Key: %w", err)
	}
	return &RootKey{pk}, nil
}

// ParseRootPublicKey parses a root public key from PEM format
func ParseRootPublicKey(pubKeyPEM []byte) (PublicKey, error) {
	pk, _, err := parsePublicKey(pubKeyPEM, tagRootPublic)
	if err != nil {
		return PublicKey{}, fmt.Errorf("failed to parse root public key: %w", err)
	}
	return pk, nil
}

// GenerateRootKey generates a new root Key pair with Metadata
func GenerateRootKey(expiration time.Duration) (*RootKey, []byte, []byte, error) {
	now := time.Now()
	expirationTime := now.Add(expiration)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	metadata := KeyMetadata{
		ID:        computeKeyID(pub),
		CreatedAt: now.UTC(),
		ExpiresAt: expirationTime.UTC(),
	}

	rk := &RootKey{
		PrivateKey{
			Key:      priv,
			Metadata: metadata,
		},
	}

	// Marshal PrivateKey struct to JSON
	privJSON, err := json.Marshal(rk.PrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Marshal PublicKey struct to JSON
	pubKey := PublicKey{
		Key:      pub,
		Metadata: metadata,
	}
	pubJSON, err := json.Marshal(pubKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Encode to PEM with metadata embedded in bytes
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  tagRootPrivate,
		Bytes: privJSON,
	})

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  tagRootPublic,
		Bytes: pubJSON,
	})

	return rk, privPEM, pubPEM, nil
}

func SignArtifactKey(rootKey RootKey, data []byte) ([]byte, error) {
	timestamp := time.Now().UTC()

	// This ensures the timestamp is cryptographically bound to the signature
	msg := make([]byte, 0, len(data)+8)
	msg = append(msg, data...)
	msg = binary.LittleEndian.AppendUint64(msg, uint64(timestamp.Unix()))

	sig := ed25519.Sign(rootKey.Key, msg)
	// Create signature bundle with timestamp and Metadata
	bundle := Signature{
		Signature: sig,
		Timestamp: timestamp,
		KeyID:     rootKey.Metadata.ID,
		Algorithm: "ed25519",
		HashAlgo:  "sha512",
	}

	return json.Marshal(bundle)
}
