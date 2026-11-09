package certproof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"
)

var errUnsupportedScheme = errors.New("unsupported signature scheme for OS keystore")

type sigScheme int

const (
	schemeECDSASHA256 sigScheme = iota + 1
	schemeECDSASHA384
	schemeRSAPSSSHA256
)

// schemeFor maps a crypto.Signer request onto the schemes the OS keystores perform.
func schemeFor(pub crypto.PublicKey, opts crypto.SignerOpts) (sigScheme, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		switch opts.HashFunc() {
		case crypto.SHA256:
			return schemeECDSASHA256, nil
		case crypto.SHA384:
			return schemeECDSASHA384, nil
		}
	case *rsa.PublicKey:
		if pss, ok := opts.(*rsa.PSSOptions); ok && pss.Hash == crypto.SHA256 {
			return schemeRSAPSSSHA256, nil
		}
	}
	return 0, fmt.Errorf("%w: %T with %v", errUnsupportedScheme, pub, opts.HashFunc())
}

// buildChain extends leaf with the issuers found in pool up to a self-signed certificate.
func buildChain(leaf *x509.Certificate, pool []*x509.Certificate) []*x509.Certificate {
	chain := []*x509.Certificate{leaf}
	current := leaf
	for current.CheckSignatureFrom(current) != nil {
		issuer := issuerIn(current, pool, chain)
		if issuer == nil {
			break
		}
		chain = append(chain, issuer)
		current = issuer
	}
	return chain
}

func issuerIn(cert *x509.Certificate, pool, seen []*x509.Certificate) *x509.Certificate {
	for _, candidate := range pool {
		if slices.ContainsFunc(seen, candidate.Equal) {
			continue
		}
		if cert.CheckSignatureFrom(candidate) == nil {
			return candidate
		}
	}
	return nil
}

// ecdsaSignatureASN1 converts the fixed-width r||s form emitted by CNG into the DER form Go verifies.
func ecdsaSignatureASN1(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw)%2 != 0 {
		return nil, errors.New("malformed raw ECDSA signature")
	}
	half := len(raw) / 2
	return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:half]), new(big.Int).SetBytes(raw[half:])})
}
