package certproof

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/certposture/certtest"
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

func TestMergeProofs_KeepsAnotherChainOfTheSameLeaf(t *testing.T) {
	root := certtest.NewCA(t, "corp-root")
	interA := root.Issue(t, certtest.ECDSAKey(t), "inter-a")
	interB := root.Issue(t, certtest.ECDSAKey(t), "inter-b")
	leaf := root.Issue(t, certtest.ECDSAKey(t), "leaf")

	// Management checks each chain against each check's CAs, so the same leaf proven
	// through another chain is a different proof, not a duplicate.
	device := []certposture.Proof{{Chain: [][]byte{leaf.Raw, interA.Raw}}}
	user := []certposture.Proof{{Chain: [][]byte{leaf.Raw, interB.Raw}}, {Chain: [][]byte{leaf.Raw, interA.Raw}}}

	merged := mergeProofs(device, user)

	require.Len(t, merged, 2, "the chain only the user store holds is kept, the one both hold is not repeated")
	assert.Equal(t, interB.Raw, merged[1].Chain[1], "the user's chain through the other intermediate is appended")
}
