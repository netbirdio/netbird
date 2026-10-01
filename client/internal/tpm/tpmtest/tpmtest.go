// Package tpmtest builds TSS2 key files for tests, with or without a TPM behind them.
package tpmtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"
)

const (
	p256Bytes = 32

	// KeyPEMType is the PEM block type of a TPM 2.0 key file.
	KeyPEMType = "TSS2 PRIVATE KEY"
)

// oidLoadableKey is the key type of draft-bottomley-tpm2-keys that a parent wraps.
var oidLoadableKey = asn1.ObjectIdentifier{2, 23, 133, 10, 1, 3}

// tss2KeyDER is the ASN.1 container, written out independently of the parser under test
// so that an encoder bug and a decoder bug cannot cancel out. Policy, secret and auth
// policy are left out entirely: they are optional, and a key that carries them is
// refused anyway.
type tss2KeyDER struct {
	Type       asn1.ObjectIdentifier
	EmptyAuth  bool `asn1:"optional,explicit,tag:0"`
	Parent     int
	PublicKey  []byte
	PrivateKey []byte
}

// Option adjusts a key before it is encoded.
type Option func(*tss2KeyDER)

// WithParent names the handle the key is wrapped by, instead of the owner hierarchy.
func WithParent(handle int) Option {
	return func(k *tss2KeyDER) { k.Parent = handle }
}

// WithAuth marks the key as guarded by an authorization value, which this client refuses
// because nothing can supply one without prompting.
func WithAuth() Option {
	return func(k *tss2KeyDER) { k.EmptyAuth = false }
}

// SigningTemplate is the public area of an unrestricted P-256 signing key with no fixed
// scheme, the shape tpm2-openssl creates certificate keys in.
func SigningTemplate() tpm2.Public {
	return tpm2.Public{
		Type:          tpm2.AlgECC,
		NameAlg:       tpm2.AlgSHA256,
		Attributes:    tpm2.FlagSign | tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagNoDA,
		ECCParameters: &tpm2.ECCParams{CurveID: tpm2.CurveNISTP256},
	}
}

// KeyPEM encodes pub as a TSS2 PRIVATE KEY over a placeholder private blob: it parses
// and reports pub, but no TPM can load it.
func KeyPEM(t *testing.T, pub *ecdsa.PublicKey, opts ...Option) string {
	t.Helper()
	require.Equal(t, elliptic.P256(), pub.Curve, "fixture keys must be P-256")
	area := SigningTemplate()
	area.ECCParameters.Point = tpm2.ECPoint{
		XRaw: pub.X.FillBytes(make([]byte, p256Bytes)),
		YRaw: pub.Y.FillBytes(make([]byte, p256Bytes)),
	}
	encoded, err := area.Encode()
	require.NoError(t, err)
	return EncodePEM(t, encoded, []byte("placeholder"), opts...)
}

// EncodePEM wraps the public and private blobs TPM2_Create returned into a TSS2 PRIVATE
// KEY, giving each the TPM2B length prefix the format carries them with.
func EncodePEM(t *testing.T, public, private []byte, opts ...Option) string {
	t.Helper()

	key := tss2KeyDER{
		Type:       oidLoadableKey,
		EmptyAuth:  true,
		Parent:     int(tpm2.HandleOwner),
		PublicKey:  prefixTPM2B(public),
		PrivateKey: prefixTPM2B(private),
	}
	for _, opt := range opts {
		opt(&key)
	}

	der, err := asn1.Marshal(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: KeyPEMType, Bytes: der}))
}

func prefixTPM2B(b []byte) []byte {
	out := make([]byte, 0, len(b)+2)
	out = append(out, byte(len(b)>>8), byte(len(b)))
	return append(out, b...)
}

// ECCSRKTemplate is the TCG reference ECC-P256 storage root key, the parent a key under
// a hierarchy is wrapped by. Tests that create a key in a real TPM have to use the same
// template the signer re-derives it with.
var ECCSRKTemplate = tpm2.Public{
	Type:       tpm2.AlgECC,
	NameAlg:    tpm2.AlgSHA256,
	Attributes: tpm2.FlagStorageDefault | tpm2.FlagNoDA,
	ECCParameters: &tpm2.ECCParams{
		Symmetric: &tpm2.SymScheme{Alg: tpm2.AlgAES, KeyBits: 128, Mode: tpm2.AlgCFB},
		Sign:      &tpm2.SigScheme{Alg: tpm2.AlgNull},
		CurveID:   tpm2.CurveNISTP256,
	},
}
