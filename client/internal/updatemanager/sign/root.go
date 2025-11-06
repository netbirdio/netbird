package sign

import (
	"crypto/ed25519"
	"crypto/rand"
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

func ParseRootKey(privKeyPEM []byte) (*RootKey, error) {
	pk, err := parsePrivateKey(privKeyPEM, tagArtifactPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse artifact Key: %w", err)
	}
	return &RootKey{pk}, nil
}

// GenerateRootKey generates a new root Key pair with Metadata
func GenerateRootKey(expiresAt time.Time) (*RootKey, []byte, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	metadata := KeyMetadata{
		ID:        computeKeyID(pub),
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
	}

	rk := &RootKey{
		PrivateKey{
			Key:      priv,
			Metadata: metadata,
		},
	}

	// Encode private Key with Metadata
	metaJSON, _ := json.Marshal(metadata)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:    tagRootPrivate,
		Headers: map[string]string{"Metadata": string(metaJSON)},
		Bytes:   priv,
	})

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:    tagRootPublic,
		Headers: map[string]string{"Metadata": string(metaJSON)},
		Bytes:   pub,
	})

	return rk, privPEM, pubPEM, nil
}

func SignArtifactKey(rootKey RootKey, data []byte) ([]byte, error) {
	sig := ed25519.Sign(rootKey.Key, data)
	// Create signature bundle with timestamp and Metadata
	bundle := Signature{
		Signature: sig,
		Timestamp: time.Now().UTC(),
		KeyID:     rootKey.Metadata.ID,
		Algorithm: "ed25519",
		HashAlgo:  "sha512",
	}

	return json.Marshal(bundle)
}
