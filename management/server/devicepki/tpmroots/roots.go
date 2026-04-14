// Package tpmroots provides a certificate pool containing manufacturer TPM EK
// root and intermediate CA certificates. Use BuildTPMRootPool() to obtain a
// pool suitable for verifying TPM EK certificate chains.
//
// The bundled PEM files in certs/ are fetched by scripts/fetch-tpm-roots.go.
// When the pool is empty (community build without proprietary CA files),
// VerifyAttestation in attestation.go skips EK chain verification and logs a
// warning — preserving existing dev-mode behaviour.
package tpmroots

import (
	"crypto/x509"
	"embed"
	"encoding/pem"
	"strings"
)

//go:embed certs
var bundledCerts embed.FS

// BuildTPMRootPool returns an x509.CertPool containing all bundled manufacturer
// TPM EK CA certificates. Returns an empty pool (not nil) when no certs are
// embedded, so callers can safely check pool size for the dev-mode warning.
func BuildTPMRootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	entries, err := bundledCerts.ReadDir("certs")
	if err != nil {
		return pool
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		data, err := bundledCerts.ReadFile("certs/" + e.Name())
		if err != nil {
			continue
		}
		pool.AppendCertsFromPEM(data)
	}
	return pool
}

// RootCerts returns the slice of parsed TPM manufacturer CA certificates.
// Returns an empty slice when no PEM files are embedded (dev-mode / community build).
func RootCerts() []*x509.Certificate {
	entries, err := bundledCerts.ReadDir("certs")
	if err != nil {
		return []*x509.Certificate{}
	}
	var certs []*x509.Certificate
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		data, err := bundledCerts.ReadFile("certs/" + e.Name())
		if err != nil {
			continue
		}
		block := data
		for len(block) > 0 {
			var pemBlock *pem.Block
			pemBlock, block = pem.Decode(block)
			if pemBlock == nil {
				break
			}
			cert, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				continue
			}
			certs = append(certs, cert)
		}
	}
	return certs
}
