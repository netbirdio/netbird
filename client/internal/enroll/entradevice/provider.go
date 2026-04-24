// Package entradevice is the client-side counterpart to the management
// server's Entra device authentication endpoints (/join/entra/*). It
// orchestrates the challenge/enroll HTTP round-trip and persists the
// resulting state per profile.
//
// The package is split into small pieces so the key-source (private key) can
// be swapped: today we only ship a PFX-backed CertProvider (keys imported
// from Intune PKCS profiles), but the interface is deliberately shaped so a
// Windows CNG / TPM provider can drop in later without touching the enroller.
package entradevice

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// CertProvider is any source of device identity: a cert chain + the ability
// to sign a server-issued nonce with the associated private key.
//
// Implementations:
//
//   - PFXProvider           — loads a .pfx file from disk (cross-platform).
//   - CNGProvider (future)  — uses Windows CNG to sign with a TPM-backed key
//                             without ever extracting it. Windows-only.
type CertProvider interface {
	// CertChainDER returns the cert chain in DER form, leaf first.
	// These are the bytes the server will parse into its CertValidator.
	CertChainDER() ([][]byte, error)

	// SignNonce signs the raw nonce bytes using the private key associated
	// with the leaf certificate. Implementations MUST use SHA-256 as the
	// digest and produce a signature shape the server accepts:
	//
	//   - RSA leaf   -> RSA-PSS with SHA-256 (preferred) or PKCS1v15.
	//   - ECDSA leaf -> ASN.1-DER encoded {R, S}.
	SignNonce(nonce []byte) ([]byte, error)

	// DeviceID extracts the Entra device id the server will use to cross-
	// check the client-supplied value. For certs where the Subject CN is the
	// device id (Entra's convention) this just reads the cert.
	DeviceID() (string, error)
}

// PFXProvider is a CertProvider backed by a standard PKCS#12 (.pfx) file,
// such as the kind Intune deploys to /Cert:\\LocalMachine\\My via a PKCS
// Certificate profile.
type PFXProvider struct {
	leaf    *x509.Certificate
	chain   []*x509.Certificate
	signer  crypto.Signer
}

// LoadPFX reads a PKCS#12 file from disk, unlocks it with the given password,
// and returns a ready PFXProvider. The password may be empty for unprotected
// files (unusual in production).
func LoadPFX(path, password string) (*PFXProvider, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pfx %s: %w", path, err)
	}
	key, leaf, caChain, err := pkcs12.DecodeChain(raw, password)
	if err != nil {
		return nil, fmt.Errorf("decode pfx %s: %w", path, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("pfx private key type %T does not implement crypto.Signer", key)
	}
	// Validate the key type is one the server accepts so we fail fast rather
	// than only on the first enrol attempt.
	switch pub := signer.Public().(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		_ = pub
	default:
		return nil, fmt.Errorf("unsupported pfx key type %T (want RSA or ECDSA)", pub)
	}
	chain := append([]*x509.Certificate{leaf}, caChain...)
	return &PFXProvider{leaf: leaf, chain: chain, signer: signer}, nil
}

// CertChainDER implements CertProvider.
func (p *PFXProvider) CertChainDER() ([][]byte, error) {
	out := make([][]byte, 0, len(p.chain))
	for _, c := range p.chain {
		out = append(out, c.Raw)
	}
	return out, nil
}

// DeviceID implements CertProvider by returning the leaf Subject CN.
func (p *PFXProvider) DeviceID() (string, error) {
	cn := p.leaf.Subject.CommonName
	if cn == "" {
		return "", fmt.Errorf("leaf certificate has no Subject CommonName")
	}
	return cn, nil
}

// SignNonce implements CertProvider.
func (p *PFXProvider) SignNonce(nonce []byte) ([]byte, error) {
	digest := sha256.Sum256(nonce)

	switch k := p.signer.(type) {
	case *rsa.PrivateKey:
		// RSA-PSS is the preferred shape; our server accepts PKCS1v15 too.
		return rsa.SignPSS(rand.Reader, k, crypto.SHA256, digest[:], nil)
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
		if err != nil {
			return nil, fmt.Errorf("ecdsa sign: %w", err)
		}
		return asn1.Marshal(struct{ R, S *big.Int }{r, s})
	default:
		// Fallback for opaque signers (e.g. TPM-backed crypto.Signer
		// wrappers) — they MUST handle RSA-PSS or be paired with a key that
		// matches the preset we set on ECDSA.
		return p.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
}

// EncodeChainB64 is a helper that turns CertChainDER into the []string of
// base64 values the /join/entra/enroll HTTP body expects.
func EncodeChainB64(chain [][]byte) []string {
	out := make([]string, 0, len(chain))
	for _, der := range chain {
		out = append(out, base64.StdEncoding.EncodeToString(der))
	}
	return out
}
