package peerauth

import (
	"crypto/ed25519"
	"crypto/x509"
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
