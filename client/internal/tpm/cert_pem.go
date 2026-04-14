package tpm

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

// writePEMCert writes a DER-encoded certificate as a PEM block to w.
func writePEMCert(w io.Writer, derBytes []byte) error {
	return pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
}

// parsePEMCert decodes the first CERTIFICATE PEM block in data and parses it.
func parsePEMCert(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("tpm: no PEM block found in certificate file")
	}
	return x509.ParseCertificate(block.Bytes)
}
