package certproof

import (
	"context"
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

	dir := t.TempDir()
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
	dir := t.TempDir()
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
		{"missing store dir", NewFileStore(filepath.Join(dir, "missing")), []*proto.Checks{{CertificateChallenge: &proto.CertificateChallenge{Nonce: []byte{1}, CaCertificates: []string{ca.PEM}}}}},
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

	dir := t.TempDir()
	writeFile(t, dir, "device.pem", certtest.CertPEM(leaf)+certtest.CertPEM(intermediate.Cert)+certtest.KeyPEM(t, key))

	candidates, err := NewFileStore(dir).Candidates(context.Background())
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Len(t, candidates[0].Chain, 2)

	roots, err := certposture.ParseCAs([]string{root.PEM})
	require.NoError(t, err)
	assert.NoError(t, certposture.VerifyChain(candidates[0].Chain, roots, time.Now()))
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
}
