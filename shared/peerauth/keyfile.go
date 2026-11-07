package peerauth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

const pemTypePrivateKey = "PRIVATE KEY"

// LoadSigningKeyFile reads Management's Ed25519 signing key from a PEM PKCS#8 file.
func LoadSigningKeyFile(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read peer auth signing key: %w", err)
	}
	key, err := ParseSigningKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("parse peer auth signing key %s: %w", path, err)
	}
	return key, nil
}

// MarshalSigningKeyPEM encodes Management's Ed25519 signing key as a PEM PKCS#8 block, the format
// ParseSigningKeyPEM reads.
func MarshalSigningKeyPEM(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS#8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: der}), nil
}

// ParseSigningKeyPEM parses Management's Ed25519 signing key from a PEM PKCS#8 block, the format
// `openssl genpkey -algorithm ed25519` writes.
func ParseSigningKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if block.Type != pemTypePrivateKey {
		return nil, fmt.Errorf("PEM block %q, want %q", block.Type, pemTypePrivateKey)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key type %T, want Ed25519", key)
	}
	return priv, nil
}

// ParsePublicKeys builds verifier keys from base64 Management public keys, as Management logs
// them. Several keys let a verifier accept tokens of the old and the new key during a rotation.
func ParsePublicKeys(b64Keys []string) (TokenKeys, error) {
	pubs := make([]ed25519.PublicKey, 0, len(b64Keys))
	for _, s := range b64Keys {
		pub, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return TokenKeys{}, fmt.Errorf("decode public key %d: %w", len(pubs), err)
		}
		if len(pub) != ed25519.PublicKeySize {
			return TokenKeys{}, fmt.Errorf("public key %d: %d bytes, want %d", len(pubs), len(pub), ed25519.PublicKeySize)
		}
		pubs = append(pubs, pub)
	}
	return NewEd25519Keys(pubs)
}
