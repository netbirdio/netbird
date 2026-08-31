package certposture

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

const (
	SigAlgECDSASHA256  = "ecdsa-sha256"
	SigAlgECDSASHA384  = "ecdsa-sha384"
	SigAlgRSAPSSSHA256 = "rsa-pss-sha256"
	SigAlgEd25519      = "ed25519"

	proofDomain = "netbird-posture-cert-v1"
	minRSABits  = 2048
)

var (
	ErrUnsupportedKey   = errors.New("unsupported certificate key")
	ErrEmptyChain       = errors.New("certificate chain is empty")
	ErrSignatureInvalid = errors.New("certificate proof signature is invalid")
	ErrSigAlgMismatch   = errors.New("signature algorithm does not match the certificate key")
)

// Proof is a client's demonstration that it holds the private key of the leaf
// certificate in Chain, made by signing the challenge nonce bound to its peer key.
type Proof struct {
	Nonce     []byte
	Chain     [][]byte
	SigAlg    string
	Signature []byte
}

// Sign produces the proof signature for a nonce using the leaf's private key. The key
// never leaves the signer, which may be backed by a file, a TPM or an OS keystore.
func Sign(signer crypto.Signer, nonce, peerKey []byte) (string, []byte, error) {
	sigAlg, err := sigAlgFor(signer.Public())
	if err != nil {
		return "", nil, err
	}

	msg := proofMessage(nonce, peerKey)
	var sig []byte
	switch sigAlg {
	case SigAlgECDSASHA256:
		d := sha256.Sum256(msg)
		sig, err = signer.Sign(rand.Reader, d[:], crypto.SHA256)
	case SigAlgECDSASHA384:
		d := sha512.Sum384(msg)
		sig, err = signer.Sign(rand.Reader, d[:], crypto.SHA384)
	case SigAlgRSAPSSSHA256:
		d := sha256.Sum256(msg)
		sig, err = signer.Sign(rand.Reader, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	case SigAlgEd25519:
		sig, err = signer.Sign(rand.Reader, msg, crypto.Hash(0))
	}
	if err != nil {
		return "", nil, fmt.Errorf("sign certificate proof: %w", err)
	}
	return sigAlg, sig, nil
}

// Verify checks that the proof's nonce was issued by this challenger to peerKey and is
// still fresh, and that the signature validates against the leaf's public key. It
// returns the parsed chain on success. Chain trust is deliberately not evaluated here.
func (c *Challenger) Verify(proof Proof, peerKey []byte, now time.Time) ([]*x509.Certificate, error) {
	if err := c.verifyNonce(proof.Nonce, peerKey, now); err != nil {
		return nil, err
	}
	chain, err := parseChain(proof.Chain)
	if err != nil {
		return nil, err
	}
	leaf := chain[0]
	sigAlg, err := sigAlgFor(leaf.PublicKey)
	if err != nil {
		return nil, err
	}
	if sigAlg != proof.SigAlg {
		return nil, ErrSigAlgMismatch
	}
	if !verifySignature(leaf.PublicKey, sigAlg, proofMessage(proof.Nonce, peerKey), proof.Signature) {
		return nil, ErrSignatureInvalid
	}
	return chain, nil
}

func proofMessage(nonce, peerKey []byte) []byte {
	msg := make([]byte, 0, len(proofDomain)+len(nonce)+len(peerKey))
	msg = append(msg, proofDomain...)
	msg = append(msg, nonce...)
	return append(msg, peerKey...)
}

func sigAlgFor(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return SigAlgECDSASHA256, nil
		case elliptic.P384():
			return SigAlgECDSASHA384, nil
		}
	case *rsa.PublicKey:
		if k.N.BitLen() >= minRSABits {
			return SigAlgRSAPSSSHA256, nil
		}
	case ed25519.PublicKey:
		return SigAlgEd25519, nil
	}
	return "", ErrUnsupportedKey
}

func verifySignature(pub crypto.PublicKey, sigAlg string, msg, sig []byte) bool {
	switch sigAlg {
	case SigAlgECDSASHA256:
		d := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), d[:], sig)
	case SigAlgECDSASHA384:
		d := sha512.Sum384(msg)
		return ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), d[:], sig)
	case SigAlgRSAPSSSHA256:
		d := sha256.Sum256(msg)
		return rsa.VerifyPSS(pub.(*rsa.PublicKey), crypto.SHA256, d[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	case SigAlgEd25519:
		return ed25519.Verify(pub.(ed25519.PublicKey), msg, sig)
	}
	return false
}

func parseChain(der [][]byte) ([]*x509.Certificate, error) {
	if len(der) == 0 {
		return nil, ErrEmptyChain
	}
	chain := make([]*x509.Certificate, 0, len(der))
	for _, raw := range der {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}
