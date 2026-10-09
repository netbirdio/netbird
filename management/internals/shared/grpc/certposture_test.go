package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/certposture/certtest"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestCertificateChallenge_StampAndVerifyRoundTrip(t *testing.T) {
	serverKey := generateKey(t)
	peerKey := generateKey(t).PublicKey()
	ca := certtest.NewCA(t, "corp-root")
	ctx := context.Background()

	checks := toProtocolChecks(ctx, []*nmdata.PostureChecks{{
		ID:     "cert-check",
		Checks: nmdata.ChecksDefinition{CertificateCheck: &nmdata.CertificateCheck{CACertificates: []string{ca.PEM}}},
	}})
	require.Len(t, checks, 1)
	require.Equal(t, []string{ca.PEM}, checks[0].GetCertificateChallenge().GetCaCertificates())
	require.Empty(t, checks[0].GetCertificateChallenge().GetNonce())

	stampCertificateChallenges(checks, peerKey, serverKey)
	nonce := checks[0].GetCertificateChallenge().GetNonce()
	require.NotEmpty(t, nonce)

	deviceKey := certtest.ECDSAKey(t)
	leaf := ca.Issue(t, deviceKey, "device")
	sigAlg, sig, err := certposture.Sign(deviceKey, nonce, peerKey[:])
	require.NoError(t, err)
	proofs := []*proto.CertificateProof{{Nonce: nonce, Chain: [][]byte{leaf.Raw}, SigAlg: sigAlg, Signature: sig}}

	s := &Server{secretsManager: &TimeBasedAuthSecretsManager{wgKey: serverKey}}

	chains := s.verifiedCertificates(ctx, peerKey, proofs)
	require.Len(t, chains, 1)
	assert.True(t, certposture.ChainMatchesCAs(chains[0], []string{ca.PEM}, time.Now()))

	t.Run("proof replayed by another peer is rejected", func(t *testing.T) {
		assert.Nil(t, s.verifiedCertificates(ctx, generateKey(t).PublicKey(), proofs))
	})
	t.Run("nonce from another management key is rejected", func(t *testing.T) {
		other := &Server{secretsManager: &TimeBasedAuthSecretsManager{wgKey: generateKey(t)}}
		assert.Nil(t, other.verifiedCertificates(ctx, peerKey, proofs))
	})
	t.Run("one invalid proof rejects the whole set", func(t *testing.T) {
		bad := &proto.CertificateProof{Nonce: nonce, Chain: [][]byte{leaf.Raw}, SigAlg: sigAlg, Signature: []byte("junk")}
		assert.Nil(t, s.verifiedCertificates(ctx, peerKey, append(proofs, bad)))
	})
	t.Run("no proofs yields no certificates", func(t *testing.T) {
		assert.Nil(t, s.verifiedCertificates(ctx, peerKey, nil))
	})
}

func TestStampCertificateChallenges_SkipsFileOnlyChecks(t *testing.T) {
	checks := []*proto.Checks{{Files: []string{"/bin/agent"}}}
	stampCertificateChallenges(checks, generateKey(t).PublicKey(), generateKey(t))
	assert.Nil(t, checks[0].GetCertificateChallenge())
}

func generateKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	return key
}
