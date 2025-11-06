package sign

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
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

func ParseArtifactKey(privKeyPEM []byte) (*ArtifactKey, error) {
	pk, err := parsePrivateKey(privKeyPEM, tagArtifactPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse artifact Key: %w", err)
	}
	return &ArtifactKey{pk}, nil
}

func (s *ArtifactKey) SignData(data []byte) ([]byte, error) {
	h := NewArtifactHash()
	if _, err := h.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write artifact hash: %w", err)
	}
	return s.signArtifactHash(h.Sum(nil), len(data))
}

// signArtifactHash signs the hash and length of an artifact with timestamp
func (s *ArtifactKey) signArtifactHash(hash []byte, length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("artifact length must be positive, got %d", length)
	}

	// Create message: hash || length || timestamp
	msg := make([]byte, 0, len(hash)+8+8)
	msg = append(msg, hash...)
	msg = binary.LittleEndian.AppendUint64(msg, uint64(length))
	timestamp := time.Now().UTC()
	msg = binary.LittleEndian.AppendUint64(msg, uint64(timestamp.Unix()))

	sig := ed25519.Sign(s.Key, msg)

	bundle := Signature{
		Signature: sig,
		Timestamp: timestamp,
		KeyID:     s.Metadata.ID,
		Algorithm: "ed25519",
		HashAlgo:  "blake2s",
	}

	return json.Marshal(bundle)
}
