// Package tpmtest builds TSS2 key files for tests, with or without a TPM behind them.
package tpmtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/tpm/tss2"
)

const p256Bytes = 32

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
func KeyPEM(t *testing.T, pub *ecdsa.PublicKey, opts ...tss2.TPMOption) string {
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

// EncodePEM wraps the public and private blobs TPM2_Create returned into a TSS2 PRIVATE KEY.
func EncodePEM(t *testing.T, public, private []byte, opts ...tss2.TPMOption) string {
	t.Helper()
	pemBytes, err := tss2.New(public, private, opts...).EncodeToMemory()
	require.NoError(t, err)
	return string(pemBytes)
}
