package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/pem"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	_, err := ParseKey(decodePEM(t, tpmtest.KeyPEM(t, &key.PublicKey, tpmtest.WithAuth())))
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

// TestSignRSA_RefusesSaltLengthsTheTPMDoesNotChoose checks the salt-length gate, which
// runs before the TPM is touched: the TPM picks the salt itself, so a request for the
// maximum salt (PSSSaltLengthAuto) or any other explicit length is refused.
func TestSignRSA_RefusesSaltLengthsTheTPMDoesNotChoose(t *testing.T) {
	digest := sha256.Sum256([]byte("challenge"))
	for _, salt := range []int{rsa.PSSSaltLengthAuto, 20, 222} {
		_, err := signRSA(nil, 0, digest[:], &rsa.PSSOptions{SaltLength: salt, Hash: crypto.SHA256})
		assert.ErrorContains(t, err, "salt length", "salt length %d must be refused", salt)
	}
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
