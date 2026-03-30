package reposign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

const (
	maxClockSkew = 5 * time.Minute
)

// KeyID is a unique identifier for a Key (first 8 bytes of SHA-256 of public Key)
type KeyID [8]byte

// computeKeyID generates a unique ID from a public Key
func computeKeyID(pub ed25519.PublicKey) KeyID {
	h := sha256.Sum256(pub)
	var id KeyID
	copy(id[:], h[:8])
	return id
}

// MarshalJSON implements json.Marshaler for KeyID
func (k KeyID) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

// UnmarshalJSON implements json.Unmarshaler for KeyID
func (k *KeyID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	parsed, err := ParseKeyID(s)
	if err != nil {
		return err
	}

	*k = parsed
	return nil
}

// ParseKeyID parses a hex string (16 hex chars = 8 bytes) into a KeyID.
func ParseKeyID(s string) (KeyID, error) {
	var id KeyID
	if len(s) != 16 {
		return id, fmt.Errorf("invalid KeyID length: got %d, want 16 hex chars (8 bytes)", len(s))
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return id, fmt.Errorf("failed to decode KeyID: %w", err)
	}

	copy(id[:], b)
	return id, nil
}

func (k KeyID) String() string {
	return fmt.Sprintf("%x", k[:])
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

	// Unmarshal JSON-embedded format
	var pub PublicKey
	if err := json.Unmarshal(b.Bytes, &pub); err != nil {
		return PublicKey{}, nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	// Validate key length
	if len(pub.Key) != ed25519.PublicKeySize {
		return PublicKey{}, nil, fmt.Errorf("incorrect Ed25519 public key size: expected %d, got %d",
			ed25519.PublicKeySize, len(pub.Key))
	}

	// Always recompute ID to ensure integrity
	pub.Metadata.ID = computeKeyID(pub.Key)

	return pub, rest, nil
}

type PrivateKey struct {
	Key      ed25519.PrivateKey
	Metadata KeyMetadata
}

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

	// Unmarshal JSON-embedded format
	var pk PrivateKey
	if err := json.Unmarshal(b.Bytes, &pk); err != nil {
		return PrivateKey{}, fmt.Errorf("failed to unmarshal private key: %w", err)
	}

	// Validate key length
	if len(pk.Key) != ed25519.PrivateKeySize {
		return PrivateKey{}, fmt.Errorf("incorrect Ed25519 private key size: expected %d, got %d",
			ed25519.PrivateKeySize, len(pk.Key))
	}

	return pk, nil
}

func verifyAny(publicRootKeys []PublicKey, msg, sig []byte) bool {
	// Verify with root keys
	var rootKeys []ed25519.PublicKey
	for _, r := range publicRootKeys {
		rootKeys = append(rootKeys, r.Key)
	}

	for _, k := range rootKeys {
		if ed25519.Verify(k, msg, sig) {
			return true
		}
	}
	return false
}
