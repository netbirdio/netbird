// Package tpm abstracts over platform-specific hardware security modules:
// TPM 2.0 (Linux/Windows) and Secure Enclave (macOS).
//
// All private key material is non-exportable: cryptographic operations
// happen inside the hardware. The caller only ever receives a crypto.Signer
// whose Sign method delegates into the hardware.
package tpm

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
)

// ErrAttestationNotSupported is returned by AttestationProof on platforms that
// do not support TPM 2.0 Endorsement Key attestation (e.g. macOS Secure Enclave).
var ErrAttestationNotSupported = errors.New("tpm: attestation not supported on this platform")

// ErrKeyNotFound is returned when the requested key ID does not exist in the hardware store.
var ErrKeyNotFound = errors.New("tpm: key not found in secure enclave")

// AttestationProof carries the TPM 2.0 attestation data used during Mode C enrollment.
// Fields match the proto AttestationProof message defined in management.proto.
type AttestationProof struct {
	// EKCert is the DER-encoded Endorsement Key certificate from the TPM manufacturer.
	EKCert []byte
	// AKPublic is the TPM2B_PUBLIC blob of the Attestation Key.
	AKPublic []byte
	// CertifyInfo is the TPM2_Certify attestation data.
	CertifyInfo []byte
	// Signature is the AK signature over CertifyInfo.
	Signature []byte
}

// Provider abstracts over TPM 2.0 (Linux/Windows) and Secure Enclave (macOS).
// All key material is non-exportable — cryptographic operations happen inside hardware.
type Provider interface {
	// GenerateKey creates a non-exportable EC P-256 key in the secure enclave.
	// The operation is idempotent: if a key with keyID already exists, the existing
	// key is returned without creating a new one.
	GenerateKey(ctx context.Context, keyID string) (crypto.Signer, error)

	// LoadKey returns a crypto.Signer backed by an existing hardware key.
	// Returns ErrKeyNotFound if no key with keyID exists.
	LoadKey(ctx context.Context, keyID string) (crypto.Signer, error)

	// StoreCert persists the issued device certificate alongside its key.
	// Storing is safe to call multiple times; repeated calls overwrite the previous cert.
	StoreCert(ctx context.Context, keyID string, cert *x509.Certificate) error

	// LoadCert returns the stored device certificate for the given key.
	// Returns ErrKeyNotFound if no certificate has been stored for keyID.
	LoadCert(ctx context.Context, keyID string) (*x509.Certificate, error)

	// AttestationProof returns a TPM 2.0 attestation bundle for Mode C enrollment.
	// Returns ErrAttestationNotSupported on macOS (Secure Enclave has no EK).
	AttestationProof(ctx context.Context, keyID string) (*AttestationProof, error)

	// ActivateCredential decrypts the credential blob using the TPM's EK and AK,
	// completing the TPM2_ActivateCredential protocol. The credentialBlob is the
	// combined [uint16BE(idObjectLen)|idObject|uint16BE(encSecretLen)|encSecret]
	// blob from BeginTPMAttestationResponse.CredentialBlob.
	// Returns the decrypted secret. On platforms without TPM 2.0, returns an error.
	ActivateCredential(ctx context.Context, credentialBlob []byte) ([]byte, error)

	// Available reports whether the hardware security module is present and accessible.
	// When false, the caller must fall back to legacy (non-hardware) authentication.
	Available() bool
}
