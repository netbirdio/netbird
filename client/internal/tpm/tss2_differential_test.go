package tpm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"testing"

	legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/tpm/tss2"

	"github.com/netbirdio/netbird/client/internal/tpm/tpmtest"
)

// publicArea builds the public area of a P-256 signing key holding pub.
func publicArea(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	area := tpmtest.SigningTemplate()
	area.ECCParameters.Point = legacy.ECPoint{
		XRaw: pub.X.FillBytes(make([]byte, 32)),
		YRaw: pub.Y.FillBytes(make([]byte, 32)),
	}
	encoded, err := area.Encode()
	require.NoError(t, err)
	return encoded
}

// TestParseTSS2_AgreesWithStep is scaffolding for one commit: it holds the replacement
// parser against the library it replaces, over bytes that library itself wrote, so the
// swap is checked rather than asserted. It goes away with the dependency.
func TestParseTSS2_AgreesWithStep(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	public := publicArea(t, &key.PublicKey)

	for _, tc := range []struct {
		name string
		opts []tss2.TPMOption
	}{
		{name: "owner hierarchy parent"},
		{name: "persistent parent", opts: []tss2.TPMOption{tss2.WithParent(0x81000001)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := tss2.New(public, []byte("placeholder"), tc.opts...).EncodeToMemory()
			require.NoError(t, err)
			block, _ := pem.Decode(encoded)
			require.NotNil(t, block)

			want, err := tss2.ParsePrivateKey(block.Bytes)
			require.NoError(t, err)
			got, err := parseTSS2(block.Bytes)
			require.NoError(t, err, "the replacement must accept what the library writes")

			assert.Equal(t, want.Type, got.Type, "key type")
			assert.Equal(t, want.EmptyAuth, got.EmptyAuth, "emptyAuth")
			assert.Equal(t, want.Parent, got.Parent, "parent handle")
			assert.Equal(t, want.PublicKey, got.PublicKey, "public area")
			assert.Equal(t, want.PrivateKey, got.PrivateKey, "private area")

			wantPub, err := want.Public()
			require.NoError(t, err)
			signer, err := ParseKey(block.Bytes)
			require.NoError(t, err)
			assert.Equal(t, wantPub, signer.Public(), "the decoded public key must be identical")
			assert.True(t, key.PublicKey.Equal(signer.Public()), "and must be the key the fixture was built from")
		})
	}
}

// TestEncodeTSS2_ReadableByStep checks the other direction: the fixtures the tests are
// built on are the shape the format calls for, not merely the shape this package reads.
func TestEncodeTSS2_ReadableByStep(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		opts []tpmtest.Option
	}{
		{name: "owner hierarchy parent"},
		{name: "persistent parent", opts: []tpmtest.Option{tpmtest.WithParent(0x81000001)}},
		{name: "needs authorization", opts: []tpmtest.Option{tpmtest.WithAuth()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			block, _ := pem.Decode([]byte(tpmtest.KeyPEM(t, &key.PublicKey, tc.opts...)))
			require.NotNil(t, block)

			want, err := tss2.ParsePrivateKey(block.Bytes)
			require.NoError(t, err, "the library under replacement must accept our fixtures")
			got, err := parseTSS2(block.Bytes)
			require.NoError(t, err)

			assert.Equal(t, want.EmptyAuth, got.EmptyAuth, "emptyAuth")
			assert.Equal(t, want.Parent, got.Parent, "parent handle")
			assert.Equal(t, want.PublicKey, got.PublicKey, "public area")
		})
	}
}
