package sign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// KeyID is a unique identifier for a Key (first 8 bytes of SHA-256 of public Key)
type KeyID [8]byte

func (k KeyID) String() string {
	return fmt.Sprintf("%x", k[:])
}

// MarshalJSON implements json.Marshaler
func (k KeyID) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

// UnmarshalJSON implements json.Unmarshaler
func (k *KeyID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if len(s) != 16 {
		return fmt.Errorf("invalid KeyID length: %d", len(s))
	}
	for i := 0; i < 8; i++ {
		fmt.Sscanf(s[i*2:i*2+2], "%02x", &k[i])
	}
	return nil
}

// computeKeyID generates a unique ID from a public Key
func computeKeyID(pub ed25519.PublicKey) KeyID {
	h := sha256.Sum256(pub)
	var id KeyID
	copy(id[:], h[:8])
	return id
}

// KeyMetadata contains versioning and lifecycle information for a Key
type KeyMetadata struct {
	ID        KeyID     `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"` // Optional expiration
}

// PublicKey wraps a public Key with its Metadata
type PublicKey struct {
	Key      ed25519.PublicKey
	Metadata KeyMetadata
}

func parsePublicKeyBundle(bundle []byte, typeTag string) ([]PublicKey, error) {
	var keys []PublicKey
	for len(bundle) > 0 {
		keyInfo, rest, err := parsePublicKey(bundle, typeTag)
		if err != nil {
			return nil, err
		}
		keys = append(keys, keyInfo)
		bundle = rest
	}
	if len(keys) == 0 {
		return nil, errors.New("no keys found in bundle")
	}
	return keys, nil
}

func parsePublicKey(data []byte, typeTag string) (PublicKey, []byte, error) {
	b, rest := pem.Decode(data)
	if b == nil {
		return PublicKey{}, nil, errors.New("failed to decode PEM data")
	}
	if b.Type != typeTag {
		return PublicKey{}, nil, fmt.Errorf("PEM type is %q, want %q", b.Type, typeTag)
	}
	if len(b.Bytes) != ed25519.PublicKeySize {
		return PublicKey{}, nil, errors.New("incorrect Ed25519 public Key size")
	}

	pub := ed25519.PublicKey(b.Bytes)
	var meta KeyMetadata
	if metaStr, ok := b.Headers["Metadata"]; ok {
		json.Unmarshal([]byte(metaStr), &meta)
	}
	meta.ID = computeKeyID(pub) // Always recompute ID

	return PublicKey{Key: pub, Metadata: meta}, rest, nil
}

type PrivateKey struct {
	Key      ed25519.PrivateKey
	Metadata KeyMetadata
}

// parsePrivateKey parses a PEM-encoded private Key with Metadata
func parsePrivateKey(data []byte, typeTag string) (PrivateKey, error) {
	b, rest := pem.Decode(data)
	if b == nil {
		return PrivateKey{}, errors.New("failed to decode PEM data")
	}
	if len(rest) > 0 {
		return PrivateKey{}, errors.New("trailing PEM data")
	}
	if b.Type != typeTag {
		return PrivateKey{}, fmt.Errorf("PEM type is %q, want %q", b.Type, typeTag)
	}
	if len(b.Bytes) != ed25519.PrivateKeySize {
		return PrivateKey{}, errors.New("incorrect Ed25519 private Key size")
	}

	var meta KeyMetadata
	if metaStr, ok := b.Headers["Metadata"]; ok {
		_ = json.Unmarshal([]byte(metaStr), &meta)
	}

	return PrivateKey{Key: b.Bytes, Metadata: meta}, nil
}
