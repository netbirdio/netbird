package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// KeyPEMType is the PEM block type of a TPM 2.0 key file as defined by
// draft-bottomley-tpm2-keys and written by tpm2-openssl and tpm2-tss-engine.
const KeyPEMType = "TSS2 PRIVATE KEY"

var ErrKeyNeedsAuth = errors.New("TPM key requires an authorization value")

// eccSRKTemplate is the TCG reference ECC-P256 storage root key. A key whose parent is
// a hierarchy rather than a persistent handle was wrapped by the primary this template
// derives, and tpm2-openssl and tpm2-tss-engine derive the same one, so the TPM
// reproduces the identical parent from the hierarchy seed without anything being stored.
var eccSRKTemplate = legacy.Public{
	Type:       legacy.AlgECC,
	NameAlg:    legacy.AlgSHA256,
	Attributes: legacy.FlagStorageDefault | legacy.FlagNoDA,
	ECCParameters: &legacy.ECCParams{
		Symmetric: &legacy.SymScheme{Alg: legacy.AlgAES, KeyBits: 128, Mode: legacy.AlgCFB},
		Sign:      &legacy.SigScheme{Alg: legacy.AlgNull},
		CurveID:   legacy.CurveNISTP256,
	},
}

// ParseKey reads a TSS2 key file and returns a signer that produces every signature
// inside the TPM; only the digest goes in and only the signature comes out. Keys guarded
// by an authorization value are rejected, since nothing can supply it without prompting.
func ParseKey(der []byte) (crypto.Signer, error) {
	key, err := parseTSS2(der)
	if err != nil {
		return nil, err
	}
	if !key.EmptyAuth {
		return nil, ErrKeyNeedsAuth
	}

	public, err := legacy.DecodePublic(key.PublicKey[2:])
	if err != nil {
		return nil, fmt.Errorf("decode TSS2 public area: %w", err)
	}
	pub, err := public.Key()
	if err != nil {
		return nil, fmt.Errorf("decode TSS2 public key: %w", err)
	}
	return &keySigner{key: key, public: pub}, nil
}

type keySigner struct {
	key    *tss2Key
	public crypto.PublicKey
}

func (s *keySigner) Public() crypto.PublicKey {
	return s.public
}

// Sign loads the key under its parent, signs, and releases both handles. The TPM is
// opened per signature so no handle outlives the call, which matters on a device whose
// transient object slots are few and shared with everything else on the host.
func (s *keySigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	rwc, err := Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rwc.Close() }()

	parent := tpmutil.Handle(s.key.Parent)
	if !persistentHandle(s.key.Parent) {
		parent, _, err = legacy.CreatePrimary(rwc, parent, legacy.PCRSelection{}, "", "", eccSRKTemplate)
		if err != nil {
			return nil, fmt.Errorf("create TPM primary: %w", err)
		}
		defer func() { _ = legacy.FlushContext(rwc, parent) }()
	}

	public, private := s.key.blobs()
	handle, _, err := legacy.Load(rwc, parent, "", public, private)
	if err != nil {
		return nil, fmt.Errorf("load TPM key: %w", err)
	}
	defer func() { _ = legacy.FlushContext(rwc, handle) }()

	switch pub := s.public.(type) {
	case *ecdsa.PublicKey:
		return signECDSA(rwc, handle, digest, pub.Curve)
	case *rsa.PublicKey:
		return signRSA(rwc, handle, digest, opts)
	default:
		return nil, fmt.Errorf("unsupported TPM key type %T", s.public)
	}
}

// signECDSA returns the signature as the ASN.1 sequence crypto.Signer is defined to
// return; the TPM hands back the two integers on their own.
func signECDSA(rw io.ReadWriter, handle tpmutil.Handle, digest []byte, curve elliptic.Curve) ([]byte, error) {
	hash, err := eccHash(curve)
	if err != nil {
		return nil, err
	}
	sig, err := legacy.Sign(rw, handle, "", digest, nil, &legacy.SigScheme{Alg: legacy.AlgECDSA, Hash: hash})
	if err != nil {
		return nil, fmt.Errorf("TPM ECDSA signature: %w", err)
	}
	if sig.ECC == nil {
		return nil, fmt.Errorf("TPM returned a %v signature for an ECDSA key", sig.Alg)
	}
	return asn1.Marshal(struct{ R, S *big.Int }{sig.ECC.R, sig.ECC.S})
}

func signRSA(rw io.ReadWriter, handle tpmutil.Handle, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash, err := legacy.HashToAlgorithm(opts.HashFunc())
	if err != nil {
		return nil, fmt.Errorf("TPM hash algorithm: %w", err)
	}

	scheme := &legacy.SigScheme{Alg: legacy.AlgRSASSA, Hash: hash}
	if pss, ok := opts.(*rsa.PSSOptions); ok {
		// The TPM chooses the salt length itself, the digest length on most chips, so
		// only a request for that length is taken. PSSSaltLengthAuto asks for the
		// largest salt the key allows and is refused. Verify with PSSSaltLengthAuto.
		if pss.SaltLength != rsa.PSSSaltLengthEqualsHash &&
			pss.SaltLength != len(digest) {
			return nil, fmt.Errorf("TPM cannot produce a PSS signature with salt length %d", pss.SaltLength)
		}
		scheme.Alg = legacy.AlgRSAPSS
	}

	sig, err := legacy.Sign(rw, handle, "", digest, nil, scheme)
	if err != nil {
		return nil, fmt.Errorf("TPM RSA signature: %w", err)
	}
	if sig.RSA == nil {
		return nil, fmt.Errorf("TPM returned a %v signature for an RSA key", sig.Alg)
	}
	return sig.RSA.Signature, nil
}

func eccHash(curve elliptic.Curve) (legacy.Algorithm, error) {
	switch curve {
	case elliptic.P256():
		return legacy.AlgSHA256, nil
	case elliptic.P384():
		return legacy.AlgSHA384, nil
	case elliptic.P521():
		return legacy.AlgSHA512, nil
	default:
		return 0, fmt.Errorf("unsupported curve %s", curve.Params().Name)
	}
}
