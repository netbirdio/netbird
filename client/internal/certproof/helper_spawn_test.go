//go:build darwin || windows

package certproof

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/certposture/certtest"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestMergeProofs_ProvesACertificateHeldByBothStoresOnce(t *testing.T) {
	ca := certtest.NewCA(t, "corp-root")
	shared := ca.Issue(t, certtest.ECDSAKey(t), "shared")
	userOnly := ca.Issue(t, certtest.ECDSAKey(t), "user-only")

	device := []certposture.Proof{{Chain: [][]byte{shared.Raw}}}
	user := []certposture.Proof{{Chain: [][]byte{shared.Raw}}, {Chain: [][]byte{userOnly.Raw}}, {}}

	merged := mergeProofs(device, user)

	require.Len(t, merged, 2, "the shared leaf is proven once and the empty chain is dropped")
	assert.Equal(t, shared.Raw, merged[0].Chain[0], "the device proof keeps its place")
	assert.Equal(t, userOnly.Raw, merged[1].Chain[0], "the user-only certificate is appended")
}

func TestMergeProofs_KeepsDeviceProofsWhenNoUserSession(t *testing.T) {
	ca := certtest.NewCA(t, "corp-root")
	device := []certposture.Proof{{Chain: [][]byte{ca.Issue(t, certtest.ECDSAKey(t), "device").Raw}}}

	merged := mergeProofs(device, nil)

	require.Len(t, merged, 1, "a machine with nobody signed in still sends its device proof")
	assert.Equal(t, sha256.Sum256(device[0].Chain[0]), sha256.Sum256(merged[0].Chain[0]), "the device proof is unchanged")
}

func TestHelperRequest_CarriesEveryChallenge(t *testing.T) {
	ca := certtest.NewCA(t, "corp-root")
	challenges := []*proto.CertificateChallenge{
		{Nonce: []byte("first"), CaCertificates: []string{ca.PEM}},
		{Nonce: []byte("second")},
	}

	req := helperRequest(challenges, peerKey)

	require.Len(t, req.Challenges, 2, "every challenge must reach the helper")
	assert.Equal(t, peerKey, req.PeerKey, "the peer key binds the signature to this machine")
	assert.Equal(t, []byte("first"), req.Challenges[0].Nonce, "the nonce must survive unchanged")
	assert.Equal(t, []string{ca.PEM}, req.Challenges[0].CACertificates, "the accepted CAs must survive unchanged")
	assert.Empty(t, req.Challenges[1].CACertificates, "a challenge without CAs stays without CAs")
}
