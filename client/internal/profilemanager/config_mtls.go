package profilemanager

import (
	"crypto/tls"
	"fmt"

	log "github.com/sirupsen/logrus"
)

// MTLSConfig holds the paths to a client certificate/key pair and the loaded certificate.
// The KeyPair field is populated at runtime from the paths and is never persisted.
type MTLSConfig struct {
	CertPath string           `json:",omitempty"`
	KeyPath  string           `json:",omitempty"`
	KeyPair  *tls.Certificate `json:"-"`
}

// migrateLegacyClientCertFields copies the old flat ClientCertPath / ClientCertKeyPath fields
// into the IDPClientCert sub-struct, logs a warning, and clears the legacy fields so they are
// not written back to disk on the next save. Returns true if a migration was performed.
func (c *Config) migrateLegacyClientCertFields() bool {
	if c.ClientCertPath == "" && c.ClientCertKeyPath == "" {
		return false
	}
	log.Warn("config contains deprecated ClientCertPath/ClientCertKeyPath fields, migrating to IDPClientCert")
	if c.IDPClientCert.CertPath == "" {
		c.IDPClientCert.CertPath = c.ClientCertPath
	}
	if c.IDPClientCert.KeyPath == "" {
		c.IDPClientCert.KeyPath = c.ClientCertKeyPath
	}
	c.ClientCertPath = ""
	c.ClientCertKeyPath = ""
	return true
}

// applyMTLSCertKeyPair updates the cert/key paths on config from the given input values,
// resets and reloads the cached TLS certificate pair.
// Both paths must either both be set or both be empty; a mismatch is returned as an error.
// It returns whether any field was updated and any error encountered.
func applyMTLSCertKeyPair(config *MTLSConfig, input MTLSConfig) (updated bool, err error) {
	if input.KeyPath != "" {
		config.KeyPath = input.KeyPath
		updated = true
	}

	if input.CertPath != "" {
		config.CertPath = input.CertPath
		updated = true
	}

	// reset cached pair before reloading
	config.KeyPair = nil
	if (config.CertPath == "") != (config.KeyPath == "") {
		return updated, fmt.Errorf("both CertPath and KeyPath must be set together")
	}
	if config.CertPath != "" {
		cert, err := tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
		if err != nil {
			return updated, fmt.Errorf("failed to load mTLS cert/key pair: %w", err)
		}
		config.KeyPair = &cert
		log.Info("Loaded mTLS cert/key pair.")
	}

	return updated, nil
}
