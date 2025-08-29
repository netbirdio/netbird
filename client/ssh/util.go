package ssh

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ed25519"
	gossh "golang.org/x/crypto/ssh"
)

// KeyType is a type of SSH key
type KeyType string

// ED25519 is key of type ed25519
const ED25519 KeyType = "ed25519"

// ECDSA is key of type ecdsa
const ECDSA KeyType = "ecdsa"

// RSA is key of type rsa
const RSA KeyType = "rsa"

// RSAKeySize is a size of newly generated RSA key
const RSAKeySize = 2048

// GeneratePrivateKey creates RSA Private Key of specified byte size
func GeneratePrivateKey(keyType KeyType) ([]byte, error) {

	var key crypto.Signer
	var err error
	switch keyType {
	case ED25519:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case ECDSA:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case RSA:
		key, err = rsa.GenerateKey(rand.Reader, RSAKeySize)
	default:
		return nil, fmt.Errorf("unsupported key type %s", keyType)
	}
	if err != nil {
		return nil, err
	}

	pemBytes, err := EncodePrivateKeyToPEM(key)
	if err != nil {
		return nil, err
	}

	return pemBytes, nil
}

// GeneratePublicKey returns the public part of the private key
func GeneratePublicKey(key []byte) ([]byte, error) {
	signer, err := gossh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	strKey := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))
	return []byte(strKey), nil
}

// EncodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func EncodePrivateKeyToPEM(privateKey crypto.Signer) ([]byte, error) {
	mk, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	// pem.Block
	privBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: mk,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)
	return privatePEM, nil
}
