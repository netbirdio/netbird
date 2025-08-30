package ssh

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// parseSSHPrivateKey parses a private key in either SSH or PKCS8 format
func parseSSHPrivateKey(keyPEM []byte) (ssh.Signer, error) {
	keyStr := string(keyPEM)
	if !strings.Contains(keyStr, "-----BEGIN") {
		keyPEM = []byte("-----BEGIN PRIVATE KEY-----\n" + keyStr + "\n-----END PRIVATE KEY-----")
	}

	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err == nil {
		return signer, nil
	}
	logrus.Debugf("SSH: Failed to parse as SSH format: %v", err)

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		keyPreview := string(keyPEM)
		if len(keyPreview) > 100 {
			keyPreview = keyPreview[:100]
		}
		return nil, fmt.Errorf("decode PEM block from key: %s", keyPreview)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		logrus.Debugf("SSH: Failed to parse as PKCS8: %v", err)
		if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return ssh.NewSignerFromKey(rsaKey)
		}
		if ecKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return ssh.NewSignerFromKey(ecKey)
		}
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	return ssh.NewSignerFromKey(key)
}
