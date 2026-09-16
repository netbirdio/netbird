package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/tpm/tss2"

	"github.com/netbirdio/netbird/client/internal/tpm/tpmtest"
)

func TestParseKey_ReportsPublicKeyWithoutTouchingTPM(t *testing.T) {
	key := newP256Key(t)

	signer, err := ParseKey(decodePEM(t, tpmtest.KeyPEM(t, &key.PublicKey)))
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(signer.Public()), "signer must expose the key the TPM holds")
}

func TestParseKey_RejectsKeyWithAuthorization(t *testing.T) {
	key := newP256Key(t)
	withAuth := func(k *tss2.TPMKey) { k.EmptyAuth = false }

	_, err := ParseKey(decodePEM(t, tpmtest.KeyPEM(t, &key.PublicKey, withAuth)))
	assert.ErrorIs(t, err, ErrKeyNeedsAuth)
}

func TestParseKey_RejectsMalformedKey(t *testing.T) {
	_, err := ParseKey([]byte("not a TSS2 key"))
	assert.Error(t, err)
}

func TestSign_FailsWhenTPMIsUnreachable(t *testing.T) {
	t.Setenv(DeviceEnv, filepath.Join(t.TempDir(), "missing"))
	signer, err := ParseKey(decodePEM(t, tpmtest.KeyPEM(t, &newP256Key(t).PublicKey)))
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("challenge"))
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	assert.Error(t, err, "signing must not fall back to software when the TPM is missing")
}

func newP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func decodePEM(t *testing.T, pemData string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(pemData))
	require.NotNil(t, block)
	require.Equal(t, KeyPEMType, block.Type)
	return block.Bytes
}
