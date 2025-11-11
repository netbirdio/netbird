package reposign

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

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/blake2s"
)

const (
	tagArtifactPrivate = "ARTIFACT PRIVATE KEY"
	tagArtifactPublic  = "ARTIFACT PUBLIC KEY"

	maxArtifactKeySignatureAge = 10 * 365 * 24 * time.Hour
	maxArtifactSignatureAge    = 10 * 365 * 24 * time.Hour
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
	signature, err := SignArtifactKey(*rootKey, pubPEM)
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

func ValidateArtifactKeys(publicRootKeys []PublicKey, data []byte, signature Signature, revocationList *RevocationList) ([]PublicKey, error) {
	now := time.Now().UTC()
	if signature.Timestamp.After(now.Add(maxClockSkew)) {
		err := fmt.Errorf("signature timestamp is in the future: %v", signature.Timestamp)
		log.Debugf("artifact signature error: %v", err)
		return nil, err
	}
	if now.Sub(signature.Timestamp) > maxArtifactKeySignatureAge {
		err := fmt.Errorf("signature is too old: %v (created %v)", now.Sub(signature.Timestamp), signature.Timestamp)
		log.Debugf("artifact signature error: %v", err)
		return nil, err
	}

	// Reconstruct the signed message: artifact_key_data || timestamp
	msg := make([]byte, 0, len(data)+8)
	msg = append(msg, data...)
	msg = binary.LittleEndian.AppendUint64(msg, uint64(signature.Timestamp.Unix()))

	if !verifyAny(publicRootKeys, msg, signature.Signature) {
		return nil, errors.New("failed to verify signature of artifact keys")
	}

	pubKeys, err := parsePublicKeyBundle(data, tagArtifactPublic)
	if err != nil {
		log.Debugf("failed to parse public keys: %s", err)
		return nil, err
	}

	validKeys := make([]PublicKey, 0, len(pubKeys))
	for _, pubKey := range pubKeys {
		// Filter out expired keys
		if !pubKey.Metadata.ExpiresAt.IsZero() && now.After(pubKey.Metadata.ExpiresAt) {
			log.Debugf("Key %s is expired at %v (current time %v)",
				pubKey.Metadata.ID, pubKey.Metadata.ExpiresAt, now)
			continue
		}

		if revocationList != nil {
			if revTime, revoked := revocationList.Revoked[pubKey.Metadata.ID]; revoked {
				log.Debugf("Key %s is revoked as of %v (created %v)",
					pubKey.Metadata.ID, revTime, pubKey.Metadata.CreatedAt)
				continue
			}
		}
		validKeys = append(validKeys, pubKey)
	}

	if len(validKeys) == 0 {
		log.Debugf("no valid public keys found for artifact keys")
		return nil, fmt.Errorf("all %d artifact keys are revoked", len(pubKeys))
	}

	return validKeys, nil
}

func ValidateArtifact(artifactPubKeys []PublicKey, data []byte, signature Signature) error {
	// Validate signature timestamp
	now := time.Now().UTC()
	if signature.Timestamp.After(now.Add(maxClockSkew)) {
		err := fmt.Errorf("artifact signature timestamp is in the future: %v", signature.Timestamp)
		log.Debugf("failed to verify signature of artifact: %s", err)
		return err
	}
	if now.Sub(signature.Timestamp) > maxArtifactSignatureAge {
		return fmt.Errorf("artifact signature is too old: %v (created %v)",
			now.Sub(signature.Timestamp), signature.Timestamp)
	}

	h := NewArtifactHash()
	if _, err := h.Write(data); err != nil {
		return fmt.Errorf("failed to hash artifact: %w", err)
	}
	hash := h.Sum(nil)

	// Reconstruct the signed message: hash || length || timestamp
	msg := make([]byte, 0, len(hash)+8+8)
	msg = append(msg, hash...)
	msg = binary.LittleEndian.AppendUint64(msg, uint64(len(data)))
	msg = binary.LittleEndian.AppendUint64(msg, uint64(signature.Timestamp.Unix()))

	// Find matching Key and verify
	for _, keyInfo := range artifactPubKeys {
		if keyInfo.Metadata.ID == signature.KeyID {
			// Check Key expiration
			if !keyInfo.Metadata.ExpiresAt.IsZero() &&
				signature.Timestamp.After(keyInfo.Metadata.ExpiresAt) {
				return fmt.Errorf("signing Key %s expired at %v, signature from %v",
					signature.KeyID, keyInfo.Metadata.ExpiresAt, signature.Timestamp)
			}

			if ed25519.Verify(keyInfo.Key, msg, signature.Signature) {
				log.Debugf("artifact verified successfully with Key: %s", signature.KeyID)
				return nil
			}
			return fmt.Errorf("signature verification failed for Key %s", signature.KeyID)
		}
	}

	return fmt.Errorf("no signing Key found with ID %s", signature.KeyID)
}

func SignData(artifactKey ArtifactKey, data []byte) ([]byte, error) {
	if len(data) == 0 { // Check happens too late
		return nil, fmt.Errorf("artifact length must be positive, got %d", len(data))
	}

	h := NewArtifactHash()
	if _, err := h.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write artifact hash: %w", err)
	}

	timestamp := time.Now().UTC()

	if !artifactKey.Metadata.ExpiresAt.IsZero() && timestamp.After(artifactKey.Metadata.ExpiresAt) {
		return nil, fmt.Errorf("artifact key expired at %v", artifactKey.Metadata.ExpiresAt)
	}

	hash := h.Sum(nil)

	// Create message: hash || length || timestamp
	msg := make([]byte, 0, len(hash)+8+8)
	msg = append(msg, hash...)
	msg = binary.LittleEndian.AppendUint64(msg, uint64(len(data)))
	msg = binary.LittleEndian.AppendUint64(msg, uint64(timestamp.Unix()))

	sig := ed25519.Sign(artifactKey.Key, msg)

	bundle := Signature{
		Signature: sig,
		Timestamp: timestamp,
		KeyID:     artifactKey.Metadata.ID,
		Algorithm: "ed25519",
		HashAlgo:  "blake2s",
	}

	return json.Marshal(bundle)
}
