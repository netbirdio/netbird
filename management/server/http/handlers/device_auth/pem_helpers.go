package device_auth

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// parsePEMCSR decodes a PEM-encoded PKCS#10 CSR and verifies its signature.
func parsePEMCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("unexpected PEM type %q", block.Type)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}
	return csr, nil
}

// parsePEMCert decodes a PEM-encoded X.509 certificate and returns the parsed cert.
func parsePEMCert(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM type %q, want CERTIFICATE", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// certToPEM encodes raw DER certificate bytes as a PEM string.
func certToPEM(derBytes []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
}

// validateCACert checks that cert is a valid CA certificate suitable for use as
// a device auth trust anchor: it must be a CA, have certificate signing key usage,
// and not be expired.
func validateCACert(cert *x509.Certificate) error {
	if !cert.IsCA || !cert.BasicConstraintsValid {
		return fmt.Errorf("certificate is not a CA (missing BasicConstraints or IsCA flag)")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("certificate lacks KeyUsageCertSign")
	}
	if cert.NotAfter.Before(time.Now()) {
		return fmt.Errorf("CA certificate has expired at %s", cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}
