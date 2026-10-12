package certposture

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrNoCertificateInPEM = errors.New("no certificate found in PEM data")

// ParseCAs builds a root pool from PEM encoded CA certificates.
func ParseCAs(pems []string) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	for _, p := range pems {
		if !roots.AppendCertsFromPEM([]byte(p)) {
			return nil, ErrNoCertificateInPEM
		}
	}
	return roots, nil
}

// VerifyChain reports whether the leaf (chain[0]) chains to one of roots using the
// remaining certificates as intermediates.
func VerifyChain(chain []*x509.Certificate, roots *x509.CertPool, now time.Time) error {
	if len(chain) == 0 {
		return ErrEmptyChain
	}
	_, err := VerifiedChain(chain[0], chain[1:], roots, now)
	return err
}

// VerifiedChain finds a path from leaf to one of roots through any of intermediates,
// trying every candidate issuer rather than the first that matches, and returns it
// without the root, leaf first. It applies the same rules as VerifyChain.
func VerifiedChain(leaf *x509.Certificate, intermediates []*x509.Certificate, roots *x509.CertPool, now time.Time) ([]*x509.Certificate, error) {
	pool := x509.NewCertPool()
	for _, cert := range intermediates {
		pool.AddCert(cert)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: pool,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, err
	}
	chain := chains[0]
	if len(chain) > 1 {
		chain = chain[:len(chain)-1]
	}
	return chain, nil
}

// ChainMatchesCAs is VerifyChain over the PEM forms stored in peer meta and check config.
func ChainMatchesCAs(chainPEM string, caPEMs []string, now time.Time) bool {
	roots, err := ParseCAs(caPEMs)
	if err != nil {
		return false
	}
	return chainMatchesPool(chainPEM, roots, now)
}

// AnyChainMatchesCAs reports whether at least one of the peer's verified chains
// is anchored in one of the configured CAs.
func AnyChainMatchesCAs(chainPEMs, caPEMs []string, now time.Time) bool {
	roots, err := ParseCAs(caPEMs)
	if err != nil {
		return false
	}
	for _, chainPEM := range chainPEMs {
		if chainMatchesPool(chainPEM, roots, now) {
			return true
		}
	}
	return false
}

func chainMatchesPool(chainPEM string, roots *x509.CertPool, now time.Time) bool {
	chain, err := ParseChainPEM(chainPEM)
	if err != nil {
		return false
	}
	return VerifyChain(chain, roots, now) == nil
}

func EncodeChainPEM(chain []*x509.Certificate) string {
	var b strings.Builder
	for _, cert := range chain {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	return b.String()
}

func ParseChainPEM(chainPEM string) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	rest := []byte(chainPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, ErrNoCertificateInPEM
	}
	return chain, nil
}
