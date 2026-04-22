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
func (v *CertValidator) Validate(certChainB64 []string, nonce []byte, signatureB64 string) (*DeviceIdentity, *Error) {
	if len(certChainB64) == 0 {
		return nil, NewError(CodeInvalidCertChain, "cert_chain is empty", nil)
	}

	// 1. Decode certs.
	var certs []*x509.Certificate
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
	leaf := certs[0]

	// 2. Time window.
	now := v.Clock()
	if now.Before(leaf.NotBefore) {
		return nil, NewError(CodeInvalidCertChain,
			"leaf certificate is not yet valid", nil)
	}
	if now.After(leaf.NotAfter) {
		return nil, NewError(CodeInvalidCertChain,
			"leaf certificate has expired", nil)
	}

	// 3. Chain verification — only if trust roots are configured.
	if v.TrustRoots != nil {
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
		if _, err := leaf.Verify(opts); err != nil {
			return nil, NewError(CodeInvalidCertChain,
				"certificate chain did not verify against configured trust roots", err)
		}
	}

	// 4. Proof of possession.
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, NewError(CodeInvalidSignature,
			"nonce_signature is not valid base64", err)
	}
	if err := verifySignature(leaf, nonce, sig); err != nil {
		return nil, NewError(CodeInvalidSignature,
			"nonce signature did not verify against leaf public key", err)
	}

	id, _ := extractDeviceID(leaf)
	return &DeviceIdentity{
		EntraDeviceID:  id,
		CertThumbprint: fingerprintSHA1(leaf),
	}, nil
}

// verifySignature checks sig over nonce using leaf.PublicKey. It supports
// RSA (PKCS1v15 SHA-256) and ECDSA (ASN.1-encoded r,s SHA-256) which are the
// common forms Windows CNG / Intune-provisioned keys produce.
func verifySignature(leaf *x509.Certificate, nonce, sig []byte) error {
	digest := sha256.Sum256(nonce)

	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		// Try PSS first, then PKCS1v15. Some signers emit either.
		if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, nil); err == nil {
			return nil
		}
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
	case *ecdsa.PublicKey:
		type ecsig struct{ R, S *big.Int }
		var es ecsig
		if _, err := asn1Unmarshal(sig, &es); err != nil {
			return fmt.Errorf("ecdsa signature: %w", err)
		}
		if es.R == nil || es.S == nil {
			return fmt.Errorf("ecdsa signature missing r/s")
		}
		if pub.Curve == nil {
			// Fall back to P-256, which is what Windows CNG + most Intune
			// SCEP profiles emit.
			pub.Curve = elliptic.P256()
		}
		if !ecdsa.Verify(pub, digest[:], es.R, es.S) {
			return fmt.Errorf("ecdsa verify failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported leaf key type %T", leaf.PublicKey)
	}
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
