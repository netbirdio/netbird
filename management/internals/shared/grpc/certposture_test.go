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
	const encryptionKey = "data-store-encryption-key"
	challenger := newCertChallenger(encryptionKey, generateKey(t))
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

	stampCertificateChallenges(checks, challenger, peerKey)
	nonce := checks[0].GetCertificateChallenge().GetNonce()
	require.NotEmpty(t, nonce)

	deviceKey := certtest.ECDSAKey(t)
	leaf := ca.Issue(t, deviceKey, "device")
	sigAlg, sig, err := certposture.Sign(deviceKey, nonce, peerKey[:])
	require.NoError(t, err)
	proofs := []*proto.CertificateProof{{Nonce: nonce, Chain: [][]byte{leaf.Raw}, SigAlg: sigAlg, Signature: sig}}

	s := &Server{challenger: challenger}

	chains := s.verifiedCertificates(ctx, peerKey, proofs)
	require.Len(t, chains, 1)
	assert.True(t, certposture.ChainMatchesCAs(chains[0], []string{ca.PEM}, time.Now()))

	t.Run("proof replayed by another peer is rejected", func(t *testing.T) {
		assert.Nil(t, s.verifiedCertificates(ctx, generateKey(t).PublicKey(), proofs))
	})
	t.Run("nonce from another deployment's secret is rejected", func(t *testing.T) {
		other := &Server{challenger: newCertChallenger("a-different-encryption-key", generateKey(t))}
		assert.Nil(t, other.verifiedCertificates(ctx, peerKey, proofs))
	})
	t.Run("a second instance with the same encryption key accepts it", func(t *testing.T) {
		// The point of deriving from the stored key: another instance, with its own
		// freshly generated WireGuard key, verifies what this one issued. This is also
		// what a restart looks like, and it used to reject.
		peer := &Server{challenger: newCertChallenger(encryptionKey, generateKey(t))}
		assert.Len(t, peer.verifiedCertificates(ctx, peerKey, proofs), 1)
	})
	t.Run("an invalid proof is dropped without the valid ones", func(t *testing.T) {
		// A device proving its machine certificate while a user store answers with a key
		// it cannot use must keep the machine certificate.
		bad := &proto.CertificateProof{Nonce: nonce, Chain: [][]byte{leaf.Raw}, SigAlg: sigAlg, Signature: []byte("junk")}
		chains := s.verifiedCertificates(ctx, peerKey, append([]*proto.CertificateProof{bad}, proofs...))
		require.Len(t, chains, 1, "the valid proof survives the invalid one")
		assert.True(t, certposture.ChainMatchesCAs(chains[0], []string{ca.PEM}, time.Now()))
	})
	t.Run("only invalid proofs yield no certificates", func(t *testing.T) {
		bad := &proto.CertificateProof{Nonce: nonce, Chain: [][]byte{leaf.Raw}, SigAlg: sigAlg, Signature: []byte("junk")}
		assert.Empty(t, s.verifiedCertificates(ctx, peerKey, []*proto.CertificateProof{bad}))
	})
	t.Run("no proofs yields no certificates", func(t *testing.T) {
		assert.Nil(t, s.verifiedCertificates(ctx, peerKey, nil))
	})
}

func TestStampCertificateChallenges_SkipsFileOnlyChecks(t *testing.T) {
	checks := []*proto.Checks{{Files: []string{"/bin/agent"}}}
	stampCertificateChallenges(checks, newCertChallenger("key", generateKey(t)), generateKey(t).PublicKey())
	assert.Nil(t, checks[0].GetCertificateChallenge())
}

func generateKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	return key
}
