package entra_device

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// CertValidator verifies a client-presented cert chain and the client's
// proof-of-possession signature over the challenge nonce.
type CertValidator struct {
	// TrustRoots is an x509.CertPool containing the Entra / Intune issuing
	// CAs that are acceptable as anchors. If nil, the validator accepts any
	// self-signed leaf — useful in dev, never in prod.
	TrustRoots *x509.CertPool

	// Intermediates may contain known intermediates to speed up path building.
	Intermediates *x509.CertPool

	// Clock overridable for tests.
	Clock func() time.Time
}

// NewCertValidator constructs a validator with a clock defaulting to time.Now.
func NewCertValidator(roots, intermediates *x509.CertPool) *CertValidator {
	return &CertValidator{
		TrustRoots:    roots,
		Intermediates: intermediates,
		Clock:         func() time.Time { return time.Now().UTC() },
	}
}

// Validate parses the DER-encoded cert chain, verifies it chains to one of
// TrustRoots (unless unset) and is currently valid, then verifies the proof
// signature.
//
// certChainB64 is the cert chain as supplied by the client (leaf first).
// nonce is the raw bytes the client was asked to sign. It MUST be retrieved
// from the NonceStore before calling this.
// signatureB64 is the base64-encoded signature bytes.
//
// Each numbered step is in its own helper to keep this function's cognitive
// complexity within SonarCloud's threshold.
func (v *CertValidator) Validate(certChainB64 []string, nonce []byte, signatureB64 string) (*DeviceIdentity, *Error) {
	certs, vErr := decodeCertChain(certChainB64)
	if vErr != nil {
		return nil, vErr
	}
	leaf := certs[0]

	now := v.Clock()
	if vErr := checkTimeWindow(leaf, now); vErr != nil {
		return nil, vErr
	}
	if vErr := v.verifyChain(certs, now); vErr != nil {
		return nil, vErr
	}
	if vErr := verifyProofOfPossession(leaf, nonce, signatureB64); vErr != nil {
		return nil, vErr
	}

	id, ok := extractDeviceID(leaf)
	if !ok {
		return nil, NewError(CodeInvalidCertChain,
			"leaf certificate subject CN is empty; cannot derive Entra device ID", nil)
	}
	return &DeviceIdentity{
		EntraDeviceID:  id,
		CertThumbprint: fingerprintSHA1(leaf),
	}, nil
}

// decodeCertChain base64-decodes and x509-parses each entry in the client-
// supplied chain, preserving leaf-first order.
func decodeCertChain(certChainB64 []string) ([]*x509.Certificate, *Error) {
	if len(certChainB64) == 0 {
		return nil, NewError(CodeInvalidCertChain, "cert_chain is empty", nil)
	}
	certs := make([]*x509.Certificate, 0, len(certChainB64))
	for i, c := range certChainB64 {
		der, err := base64.StdEncoding.DecodeString(c)
		if err != nil {
			return nil, NewError(CodeInvalidCertChain,
				fmt.Sprintf("cert_chain[%d] is not valid base64", i), err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, NewError(CodeInvalidCertChain,
				fmt.Sprintf("cert_chain[%d] could not be parsed as X.509", i), err)
		}
		certs = append(certs, parsed)
	}
	return certs, nil
}

// checkTimeWindow rejects leaves that are not-yet-valid or already expired.
func checkTimeWindow(leaf *x509.Certificate, now time.Time) *Error {
	if now.Before(leaf.NotBefore) {
		return NewError(CodeInvalidCertChain, "leaf certificate is not yet valid", nil)
	}
	if now.After(leaf.NotAfter) {
		return NewError(CodeInvalidCertChain, "leaf certificate has expired", nil)
	}
	return nil
}

// verifyChain runs the x509 path-building + verification against the
// configured trust roots. When TrustRoots is nil the chain step is skipped
// (dev-only). See README "Known production gaps".
func (v *CertValidator) verifyChain(certs []*x509.Certificate, now time.Time) *Error {
	if v.TrustRoots == nil {
		return nil
	}
	intermediates := v.Intermediates
	if len(certs) > 1 {
		if intermediates == nil {
			intermediates = x509.NewCertPool()
		}
		for _, c := range certs[1:] {
			intermediates.AddCert(c)
		}
	}
	opts := x509.VerifyOptions{
		Roots:         v.TrustRoots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny},
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return NewError(CodeInvalidCertChain,
			"certificate chain did not verify against configured trust roots", err)
	}
	return nil
}

// verifyProofOfPossession decodes the signature and verifies it against the
// leaf public key.
func verifyProofOfPossession(leaf *x509.Certificate, nonce []byte, signatureB64 string) *Error {
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return NewError(CodeInvalidSignature, "nonce_signature is not valid base64", err)
	}
	if err := verifySignature(leaf, nonce, sig); err != nil {
		return NewError(CodeInvalidSignature,
			"nonce signature did not verify against leaf public key", err)
	}
	return nil
}

// verifySignature checks sig over nonce using leaf.PublicKey. It supports
// RSA (PKCS1v15 SHA-256) and ECDSA (ASN.1-encoded r,s SHA-256) which are the
// common forms Windows CNG / Intune-provisioned keys produce.
func verifySignature(leaf *x509.Certificate, nonce, sig []byte) error {
	digest := sha256.Sum256(nonce)

	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		return verifyRSA(pub, digest[:], sig)
	case *ecdsa.PublicKey:
		return verifyECDSA(pub, digest[:], sig)
	default:
		return fmt.Errorf("unsupported leaf key type %T", leaf.PublicKey)
	}
}

// verifyRSA accepts both RSA-PSS and PKCS1v15 (Windows CNG / Intune can emit
// either depending on the CSP).
func verifyRSA(pub *rsa.PublicKey, digest, sig []byte) error {
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest, sig, nil); err == nil {
		return nil
	}
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig)
}

// verifyECDSA decodes an ASN.1 DER {R,S} signature and verifies it against
// the leaf public key.
func verifyECDSA(pub *ecdsa.PublicKey, digest, sig []byte) error {
	type ecsig struct{ R, S *big.Int }
	var es ecsig
	if _, err := asn1Unmarshal(sig, &es); err != nil {
		return fmt.Errorf("ecdsa signature: %w", err)
	}
	if es.R == nil || es.S == nil {
		return fmt.Errorf("ecdsa signature missing r/s")
	}
	if pub.Curve == nil {
		// Fall back to P-256, which is what Windows CNG + most Intune SCEP
		// profiles emit.
		pub.Curve = elliptic.P256()
	}
	if !ecdsa.Verify(pub, digest, es.R, es.S) {
		return fmt.Errorf("ecdsa verify failed")
	}
	return nil
}

// extractDeviceID pulls the Entra device object ID from the cert. Entra
// device certs have Subject CN == device object ID (GUID).
func extractDeviceID(leaf *x509.Certificate) (string, bool) {
	cn := strings.TrimSpace(leaf.Subject.CommonName)
	if cn == "" {
		return "", false
	}
	// Entra uses raw GUID string without CN= prefix; accept either form.
	cn = strings.TrimPrefix(cn, "CN=")
	return cn, true
}

func fingerprintSHA1(leaf *x509.Certificate) string {
	h := sha1.Sum(leaf.Raw)
	return hex.EncodeToString(h[:])
}

// asn1Unmarshal is declared as a function variable so tests can stub it without
// pulling in encoding/asn1 everywhere (the real implementation is wired below).
var asn1Unmarshal = func(data []byte, dst any) ([]byte, error) {
	return realASN1Unmarshal(data, dst)
}
