package profilemanager

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The serialized form is how the tvOS SDK stores a profile and how the iOS SDK
// copies one in memory, so it must round-trip whatever a profile legitimately
// holds — including no identity at all, which is the state mobile logout leaves
// behind when it clears both keys in place. Refusing that document here broke
// logout, profile switching and the login that follows them.
func TestConfigFromJSONRoundTripsALoggedOutProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exported.json")
	stored, err := UpdateOrCreateConfig(ConfigInput{ConfigPath: path, ManagementURL: DefaultManagementURL})
	require.NoError(t, err)
	require.NotEmpty(t, stored.PrivateKey, "a provisioned config is the fixture this test starts from")
	require.NotEmpty(t, stored.SSHKey)

	exported, err := ConfigToJSON(stored)
	require.NoError(t, err)

	restored, err := ConfigFromJSON(exported)
	require.NoError(t, err, "a config exported after a login must load")
	require.Equal(t, stored.PrivateKey, restored.PrivateKey, "the restored peer is not the stored one")
	require.Equal(t, stored.SSHKey, restored.SSHKey)

	// What mobile logout leaves on disk.
	loggedOut := stored.clone()
	loggedOut.PrivateKey = ""
	loggedOut.SSHKey = ""

	document, err := ConfigToJSON(loggedOut)
	require.NoError(t, err)

	reloaded, err := ConfigFromJSON(document)
	require.NoError(t, err, "a logged-out profile must still load")
	require.Empty(t, reloaded.PrivateKey, "loading must not mint a key nothing will write down")
	require.Empty(t, reloaded.SSHKey)
	require.Equal(t, stored.ManagementURL.String(), reloaded.ManagementURL.String(),
		"the rest of the profile survives the logout")
}
