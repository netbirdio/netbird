package certproof

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/certposture/certtest"
)

func TestConsoleUser_OnlyADesktopSessionCanBeValidated(t *testing.T) {
	tests := []struct {
		name    string
		user    ConsoleUser
		desktop bool
	}{
		{"logged in user", ConsoleUser{Name: "maycon", UID: 501, GID: 20}, true},
		{"login window as root", ConsoleUser{Name: "root", UID: 0}, false},
		{"login window by name", ConsoleUser{Name: "loginwindow", UID: 0}, false},
		{"named user still at uid 0", ConsoleUser{Name: "admin", UID: 0}, false},
		{"no console user", ConsoleUser{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.desktop, tt.user.hasDesktop(), "only a real desktop session offers a login keychain")
		})
	}
}

// CurrentConsoleUser runs against the real SystemConfiguration framework. A machine with
// a desktop open must report a non-root user; a headless runner must report none.
func TestCurrentConsoleUser_AgreesWithItself(t *testing.T) {
	user, ok := CurrentConsoleUser()
	if !ok {
		t.Log("no console user, running headless")
		return
	}
	assert.NotEmpty(t, user.Name, "a console user must have a name")
	assert.NotZero(t, user.UID, "a desktop session never belongs to uid 0")
	assert.True(t, user.hasDesktop(), "a reported console user must be a desktop session")
}

func TestMergeProofs_ProvesACertificateHeldByBothKeychainsOnce(t *testing.T) {
	ca := certtest.NewCA(t, "corp-root")
	key := certtest.ECDSAKey(t)
	shared := ca.Issue(t, key, "shared")
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

	require.Len(t, merged, 1, "a Mac at the login window still sends its device proof")
	assert.Equal(t, sha256.Sum256(device[0].Chain[0]), sha256.Sum256(merged[0].Chain[0]), "the device proof is unchanged")
}
