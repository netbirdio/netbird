package auth

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// MTLSConfig stores parsed mTLS validation state for a single protected domain.
type MTLSConfig struct {
	Enabled bool
	CAPool  *x509.CertPool
}

func NewMTLSConfig(enabled bool, caCertPEM string) (*MTLSConfig, error) {
	if !enabled {
		return &MTLSConfig{}, nil
	}
	if strings.TrimSpace(caCertPEM) == "" {
		return nil, errors.New("mtls_auth: ca_cert_pem is required when enabled")
	}
	pool, err := parseClientCAPEM(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("mtls_auth: %w", err)
	}
	return &MTLSConfig{Enabled: true, CAPool: pool}, nil
}

func parseClientCAPEM(caCertPEM string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	remaining := []byte(caCertPEM)
	foundCertificate := false

	for len(remaining) > 0 {
		remaining = trimPEMCommentsAndWhitespace(remaining)
		if len(remaining) == 0 {
			break
		}

		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			return nil, errors.New("ca_cert_pem contains invalid PEM data")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		pool.AddCert(cert)
		foundCertificate = true
	}

	if !foundCertificate {
		return nil, errors.New("ca_cert_pem must contain at least one certificate")
	}

	return pool, nil
}

func trimPEMCommentsAndWhitespace(data []byte) []byte {
	for len(data) > 0 {
		data = bytes.TrimLeft(data, " \t\r\n")
		if len(data) == 0 || data[0] != '#' {
			return data
		}
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
			continue
		}
		return nil
	}
	return data
}

func validateClientCertificate(r *http.Request, cfg *MTLSConfig) error {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return errors.New("client certificate required")
	}

	leaf := r.TLS.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, cert := range r.TLS.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}

	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         cfg.CAPool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return fmt.Errorf("verify client certificate: %w", err)
	}

	return nil
}
