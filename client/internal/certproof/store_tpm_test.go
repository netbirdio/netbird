package certproof

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/tpm/tss2"

	"github.com/netbirdio/netbird/client/internal/tpm"
	"github.com/netbirdio/netbird/client/internal/tpm/tpmtest"
	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/certposture/certtest"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestFileStore_TPMKeyFile(t *testing.T) {
	ca := certtest.NewCA(t, "corp")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := ca.Issue(t, key, "device")

	dir := t.TempDir()
	writeFile(t, dir, "device.pem", certtest.CertPEM(leaf))
	writeFile(t, dir, "device.key", tpmtest.KeyPEM(t, &key.PublicKey))

	// A key that needs a password can never be used silently, so its certificate is skipped.
	locked := certtest.ECDSAKey(t)
	withAuth := func(k *tss2.TPMKey) { k.EmptyAuth = false }
	writeFile(t, dir, "locked.pem", certtest.CertPEM(ca.Issue(t, locked, "locked")))
	writeFile(t, dir, "locked.key", tpmtest.KeyPEM(t, locked.Public().(*ecdsa.PublicKey), withAuth))

	candidates, err := NewFileStore(dir).Candidates(context.Background())
	require.NoError(t, err)
	require.Len(t, candidates, 1, "only the key without an authorization value is usable")
	assert.True(t, leaf.Equal(candidates[0].Chain[0]), "candidate must carry the device certificate")
	assert.True(t, key.PublicKey.Equal(candidates[0].Signer.Public()), "signer must report the certificate's key")
}

// TestCollect_TPMKeyEndToEnd runs against the TPM named by NB_TPM_DEVICE, for example a
// swtpm started with:
//
//	swtpm socket --tpm2 --server type=unixio,path=/tmp/swtpm.sock \
//	  --ctrl type=unixio,path=/tmp/swtpm.ctrl --flags not-need-init,startup-clear
//
// It creates a key the way tpm2-openssl does, under a transient ECC primary in the owner
// hierarchy, and proves the certificate for it through the regular file store.
func TestCollect_TPMKeyEndToEnd(t *testing.T) {
	if os.Getenv(tpm.DeviceEnv) == "" {
		t.Skipf("set %s to a TPM device or swtpm socket to run", tpm.DeviceEnv)
	}
	public, private := createTPMKey(t)
	keyPEM := tpmtest.EncodePEM(t, public, private)
	block, _ := pem.Decode([]byte(keyPEM))
	require.NotNil(t, block)
	signer, err := tpm.ParseKey(block.Bytes)
	require.NoError(t, err)

	ca := certtest.NewCA(t, "corp")
	leaf := ca.Issue(t, signer, "device")
	dir := t.TempDir()
	writeFile(t, dir, "device.pem", certtest.CertPEM(leaf))
	writeFile(t, dir, "device.key", keyPEM)

	challenger := certposture.NewChallenger([]byte("secret"))
	now := time.Now()
	nonce := challenger.Nonce(peerKey, now)
	checks := []*proto.Checks{{CertificateChallenge: &proto.CertificateChallenge{Nonce: nonce, CaCertificates: []string{ca.PEM}}}}

	proofs := Collect(context.Background(), NewFileStore(dir), checks, peerKey)
	require.Len(t, proofs, 1, "the TPM-held key must prove the certificate")
	chain, err := challenger.Verify(proofs[0], peerKey, now)
	require.NoError(t, err)
	assert.True(t, leaf.Equal(chain[0]), "proof must carry the device certificate")
}

func createTPMKey(t *testing.T) (public, private []byte) {
	t.Helper()
	rwc, err := tpm.Open()
	require.NoError(t, err)
	defer func() { _ = rwc.Close() }()

	parent, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", tss2.ECCSRKTemplate)
	require.NoError(t, err)
	defer func() { _ = tpm2.FlushContext(rwc, parent) }()

	private, public, _, _, _, err = tpm2.CreateKey(rwc, parent, tpm2.PCRSelection{}, "", "", tpmtest.SigningTemplate())
	require.NoError(t, err)
	return public, private
}
