package certproof

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/certposture/certtest"
	"github.com/netbirdio/netbird/shared/management/proto"
)

var peerKey = []byte("peer-public-key-aaaaaaaaaaaaaaaa")

func TestCollect_ProvesOneMatchingCertificatePerChallenge(t *testing.T) {
	corpCA := certtest.NewCA(t, "corp-root")
	otherCA := certtest.NewCA(t, "other-root")
	unrelatedCA := certtest.NewCA(t, "unrelated-root")

	dir := storeDir(t)
	deviceKey := certtest.ECDSAKey(t)
	device := corpCA.Issue(t, deviceKey, "device")
	writeFile(t, dir, "device.pem", certtest.CertPEM(device)+certtest.KeyPEM(t, deviceKey))

	otherKey := certtest.RSAKey(t)
	writeFile(t, dir, "other.crt", certtest.CertPEM(otherCA.Issue(t, otherKey, "other")))
	writeFile(t, dir, "other.key", certtest.KeyPEM(t, otherKey))

	writeFile(t, dir, "keyless.crt", certtest.CertPEM(corpCA.Issue(t, certtest.ECDSAKey(t), "keyless")))
	writeFile(t, dir, "notes.txt", "ignored")

	challenger := certposture.NewChallenger([]byte("secret"))
	nonce := challenger.Nonce(peerKey, time.Now())
	challenge := func(cas ...string) *proto.Checks {
		return &proto.Checks{CertificateChallenge: &proto.CertificateChallenge{Nonce: nonce, CaCertificates: cas}}
	}
	checks := []*proto.Checks{
		{Files: []string{"/usr/bin/agent"}},
		challenge(corpCA.PEM),
		challenge(corpCA.PEM),
		challenge(otherCA.PEM),
		challenge(unrelatedCA.PEM),
		challenge("not a pem"),
	}

	proofs := Collect(context.Background(), NewFileStore(dir), checks, peerKey)

	require.Len(t, proofs, 2)
	var subjects []string
	for _, p := range proofs {
		chain, err := challenger.Verify(p, peerKey, time.Now())
		require.NoError(t, err)
		subjects = append(subjects, chain[0].Subject.CommonName)
	}
	assert.ElementsMatch(t, []string{"device", "other"}, subjects)
}

func TestCollect_NothingToProve(t *testing.T) {
	dir := storeDir(t)
	key := certtest.ECDSAKey(t)
	ca := certtest.NewCA(t, "root")
	writeFile(t, dir, "device.pem", certtest.CertPEM(ca.Issue(t, key, "device"))+certtest.KeyPEM(t, key))

	tests := []struct {
		name   string
		store  Store
		checks []*proto.Checks
	}{
		{"no checks", NewFileStore(dir), nil},
		{"files only", NewFileStore(dir), []*proto.Checks{{Files: []string{"/bin/x"}}}},
		{"challenge without nonce", NewFileStore(dir), []*proto.Checks{{CertificateChallenge: &proto.CertificateChallenge{CaCertificates: []string{ca.PEM}}}}},
		{"missing store dir", NewFileStore(filepath.Join(dir, "missing")), []*proto.Checks{{CertificateChallenge: &proto.CertificateChallenge{Nonce: make([]byte, certposture.NonceSize), CaCertificates: []string{ca.PEM}}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Nil(t, Collect(context.Background(), tt.store, tt.checks, peerKey))
		})
	}
}

func TestFileStore_ChainWithIntermediate(t *testing.T) {
	root := certtest.NewCA(t, "root")
	intermediate := certtest.NewIntermediate(t, root, "intermediate")
	key := certtest.ECDSAKey(t)
	leaf := intermediate.Issue(t, key, "device")

	dir := storeDir(t)
	writeFile(t, dir, "device.pem", certtest.CertPEM(leaf)+certtest.CertPEM(intermediate.Cert)+certtest.KeyPEM(t, key))

	candidates, err := NewFileStore(dir).Candidates(context.Background())
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Len(t, candidates[0].Chain, 2)

	roots, err := certposture.ParseCAs([]string{root.PEM})
	require.NoError(t, err)
	assert.NoError(t, certposture.VerifyChain(candidates[0].Chain, roots, time.Now()))
}

// storeDir is a PEM directory the store accepts: t.TempDir follows the umask, which
// leaves the directory group-writable on systems with a user-private group umask.
func storeDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	return dir
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
}

func TestCollectChallenges_RefusesMalformedInput(t *testing.T) {
	ca := certtest.NewCA(t, "corp-root")
	dir := storeDir(t)
	key := certtest.ECDSAKey(t)
	writeFile(t, dir, "device.pem", certtest.CertPEM(ca.Issue(t, key, "device"))+certtest.KeyPEM(t, key))
	store := NewFileStore(dir)
	nonce := certposture.NewChallenger([]byte("secret")).Nonce(peerKey, time.Now())

	tests := []struct {
		name    string
		nonce   []byte
		peerKey []byte
		want    int
	}{
		{"issued nonce and peer key are signed", nonce, peerKey, 1},
		{"short nonce is not signed", nonce[:8], peerKey, 0},
		{"oversized nonce is not signed", append(append([]byte{}, nonce...), 0), peerKey, 0},
		{"short peer key is not signed", nonce, peerKey[:16], 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenges := []*proto.CertificateChallenge{{Nonce: tt.nonce, CaCertificates: []string{ca.PEM}}}
			assert.Len(t, CollectChallenges(context.Background(), store, challenges, tt.peerKey), tt.want,
				"the device key signs only what management could have issued")
		})
	}
}

func TestFileStore_SkipsKeyOfAnotherCertificate(t *testing.T) {
	ca := certtest.NewCA(t, "corp-root")
	dir := storeDir(t)

	// A stale key next to a renewed certificate, sorted before the good pair, must not
	// produce a proof that management rejects and stop the search there.
	writeFile(t, dir, "a-renewed.crt", certtest.CertPEM(ca.Issue(t, certtest.ECDSAKey(t), "renewed")))
	writeFile(t, dir, "a-renewed.key", certtest.KeyPEM(t, certtest.ECDSAKey(t)))
	goodKey := certtest.ECDSAKey(t)
	good := ca.Issue(t, goodKey, "good")
	writeFile(t, dir, "b-good.pem", certtest.CertPEM(good)+certtest.KeyPEM(t, goodKey))

	candidates, err := NewFileStore(dir).Candidates(context.Background())
	require.NoError(t, err)
	require.Len(t, candidates, 1, "only the certificate whose key matches is a candidate")
	assert.True(t, good.Equal(candidates[0].Chain[0]), "the matching pair is kept")

	challenger := certposture.NewChallenger([]byte("secret"))
	now := time.Now()
	nonce := challenger.Nonce(peerKey, now)
	proofs := CollectChallenges(context.Background(), NewFileStore(dir), []*proto.CertificateChallenge{{Nonce: nonce, CaCertificates: []string{ca.PEM}}}, peerKey)
	require.Len(t, proofs, 1)
	_, err = challenger.Verify(proofs[0], peerKey, now)
	assert.NoError(t, err, "the proof sent is one management accepts")
}

// staticStore hands out fixed candidates, for scenarios no on-disk layout can express.
type staticStore []Candidate

func (s staticStore) Candidates(context.Context) ([]Candidate, error) { return s, nil }

func TestCollectChallenges_RoutesAroundExpiredCopyOfRenewedIntermediate(t *testing.T) {
	root := certtest.NewCA(t, "root")
	intermediate := certtest.NewIntermediate(t, root, "issuing-ca")

	// Renewing a CA with the same key pair leaves two certificates with the same
	// subject and key in the store. The expired one sorts first here.
	expiredTmpl := *intermediate.Cert
	expiredTmpl.SerialNumber = big.NewInt(1)
	expiredTmpl.NotBefore = time.Now().Add(-72 * time.Hour)
	expiredTmpl.NotAfter = time.Now().Add(-48 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &expiredTmpl, root.Cert, intermediate.Key.Public(), root.Key)
	require.NoError(t, err)
	expired, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	key := certtest.ECDSAKey(t)
	leaf := intermediate.Issue(t, key, "device")
	pool := []*x509.Certificate{expired, intermediate.Cert}

	chain := buildChain(leaf, pool)
	require.Len(t, chain, 2)
	require.True(t, expired.Equal(chain[1]), "precondition: the first-match chain runs through the expired copy")

	challenger := certposture.NewChallenger([]byte("secret"))
	now := time.Now()
	nonce := challenger.Nonce(peerKey, now)
	store := staticStore{{Chain: chain, Signer: key, Intermediates: pool}}

	proofs := CollectChallenges(context.Background(), store, []*proto.CertificateChallenge{{Nonce: nonce, CaCertificates: []string{root.PEM}}}, peerKey)

	require.Len(t, proofs, 1, "a valid path through the renewed intermediate exists, so the challenge is answered")
	verified, err := challenger.Verify(proofs[0], peerKey, now)
	require.NoError(t, err)
	assert.True(t, intermediate.Cert.Equal(verified[1]), "the proof carries the valid intermediate, not the expired copy")
	assert.True(t, certposture.ChainMatchesCAs(certposture.EncodeChainPEM(verified), []string{root.PEM}, now),
		"management's own check accepts the chain the proof carries")
}

func TestCollectChallenges_ProvesALeafOncePerDistinctChain(t *testing.T) {
	rootA := certtest.NewCA(t, "root-a")
	rootB := certtest.NewCA(t, "root-b")
	issuer := certtest.NewIntermediate(t, rootA, "issuing-ca")

	// The same issuing CA cross-signed by a second root: one leaf, two valid paths.
	crossTmpl := *issuer.Cert
	crossTmpl.SerialNumber = big.NewInt(2)
	der, err := x509.CreateCertificate(rand.Reader, &crossTmpl, rootB.Cert, issuer.Key.Public(), rootB.Key)
	require.NoError(t, err)
	cross, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	key := certtest.ECDSAKey(t)
	leaf := issuer.Issue(t, key, "device")
	pool := []*x509.Certificate{issuer.Cert, cross}
	store := staticStore{{Chain: buildChain(leaf, pool), Signer: key, Intermediates: pool}}

	challenger := certposture.NewChallenger([]byte("secret"))
	now := time.Now()
	nonce := challenger.Nonce(peerKey, now)
	challenges := []*proto.CertificateChallenge{
		{Nonce: nonce, CaCertificates: []string{rootA.PEM}},
		{Nonce: nonce, CaCertificates: []string{rootB.PEM}},
		{Nonce: nonce, CaCertificates: []string{rootA.PEM}},
	}

	proofs := CollectChallenges(context.Background(), store, challenges, peerKey)

	require.Len(t, proofs, 2, "one proof per distinct chain, the repeated root-a challenge reuses the first")
	for _, root := range []*certtest.CA{rootA, rootB} {
		matched := false
		for _, p := range proofs {
			chain, err := challenger.Verify(p, peerKey, now)
			require.NoError(t, err)
			matched = matched || certposture.ChainMatchesCAs(certposture.EncodeChainPEM(chain), []string{root.PEM}, now)
		}
		assert.True(t, matched, "management can match a chain for the check that trusts %s", root.Cert.Subject.CommonName)
	}
}
