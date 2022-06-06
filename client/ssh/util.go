package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	gossh "golang.org/x/crypto/ssh"
)

// GeneratePrivateKey creates RSA Private Key of specified byte size
func GeneratePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// GeneratePublicKey takes a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns the key in format format "ssh-rsa ..."
func GeneratePublicKey(privateKey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := gossh.NewPublicKey(privateKey)
	if err != nil {
		return nil, err
	}
	return gossh.MarshalAuthorizedKey(publicRsaKey), nil
}

// EncodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func EncodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}
