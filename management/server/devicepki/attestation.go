package devicepki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/netbirdio/netbird/management/server/devicepki/tpmroots"
)

// AttestationError is returned when TPM attestation verification fails.
type AttestationError struct {
	Reason string
}

func (e *AttestationError) Error() string {
	return "devicepki/attestation: " + e.Reason
}

// VerifyEKCertChain verifies an EK certificate against the bundled TPM manufacturer
// CA pool. When no manufacturer CAs are bundled (development / open-source build),
// the check is skipped and the function returns nil with a warning log. Callers
// should treat a nil return from an empty pool as "unverified, not failed".
//
// ekCert must be a parsed *x509.Certificate with its raw DER form intact.
func VerifyEKCertChain(ekCert *x509.Certificate) (skipped bool, err error) {
	pool := tpmroots.BuildTPMRootPool()
	if len(tpmroots.RootCerts()) == 0 {
		return true, nil // dev-mode: no manufacturer CAs bundled
	}
	opts := x509.VerifyOptions{Roots: pool}
	if _, verifyErr := ekCert.Verify(opts); verifyErr != nil {
		return false, &AttestationError{Reason: fmt.Sprintf("EK certificate not signed by a known TPM manufacturer CA: %v", verifyErr)}
	}
	return false, nil
}

// VerifyAttestation validates a TPM 2.0 attestation bundle:
//
//  1. Parses ekCertDER as an x509.Certificate.
//  2. Verifies the EK certificate against the TPM manufacturer CA pool returned
//     by tpmroots.BuildTPMRootPool().  If the pool is empty (development mode)
//     the EK cert chain verification is skipped with a logged warning.
//  3. Parses akPubDER as a DER-encoded SubjectPublicKeyInfo.
//  4. Verifies that certifySignature is a valid signature over certifyInfo
//     using the parsed AK public key (SHA-256).
//
// Returns a non-nil *AttestationError on verification failure. Other errors
// indicate parsing or crypto failures.
func VerifyAttestation(ekCertDER, akPubDER, certifyInfo, certifySignature []byte) error {
	if len(ekCertDER) == 0 || len(akPubDER) == 0 || len(certifyInfo) == 0 || len(certifySignature) == 0 {
		return &AttestationError{Reason: "attestation proof fields must not be empty"}
	}

	// Step 1: parse EK certificate.
	ekCert, err := x509.ParseCertificate(ekCertDER)
	if err != nil {
		return fmt.Errorf("devicepki/attestation: parse EK cert: %w", err)
	}

	// Step 2: verify EK cert against the TPM manufacturer CA pool.
	pool := tpmroots.BuildTPMRootPool()
	if pool != nil && len(tpmroots.RootCerts()) > 0 {
		opts := x509.VerifyOptions{Roots: pool}
		if _, err := ekCert.Verify(opts); err != nil {
			return &AttestationError{Reason: fmt.Sprintf("EK certificate chain invalid: %v", err)}
		}
	}
	// When the manufacturer CA pool is empty (development / open-source build) we
	// skip EK chain verification but still verify the AK signature below.

	// Step 3: parse AK public key.
	akPub, err := x509.ParsePKIXPublicKey(akPubDER)
	if err != nil {
		return fmt.Errorf("devicepki/attestation: parse AK public key: %w", err)
	}

	// Step 4: verify AK signature over certifyInfo (SHA-256).
	digest := sha256.Sum256(certifyInfo)
	if err := verifySignature(akPub, digest[:], certifySignature); err != nil {
		return &AttestationError{Reason: fmt.Sprintf("AK signature verification failed: %v", err)}
	}

	return nil
}

// verifySignature verifies a raw signature over a pre-hashed digest using the
// provided public key.  Supports ECDSA (ASN.1 DER) and RSA PKCS#1 v1.5.
func verifySignature(pub crypto.PublicKey, digest, sig []byte) error {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest, sig) {
			return errors.New("ECDSA signature mismatch")
		}
		return nil
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, sig)
	default:
		return fmt.Errorf("unsupported AK public key type %T", pub)
	}
}
