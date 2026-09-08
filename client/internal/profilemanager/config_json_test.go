package profilemanager

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The serialized form is how the tvOS SDK stores a profile, and its callers
// connect with whatever comes back. A document with no identity used to be
// completed by apply() minting keys, which meant connecting as a peer nothing
// could persist; it is now refused, since the only honest answer to "restore
// this config" for a config that was never logged in is to say so.
func TestConfigFromJSONRefusesADocumentWithoutAnIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exported.json")
	stored, err := UpdateOrCreateConfig(ConfigInput{ConfigPath: path, ManagementURL: DefaultManagementURL})
	require.NoError(t, err)
	require.NotEmpty(t, stored.PrivateKey, "a provisioned config is the fixture this test needs")
	require.NotEmpty(t, stored.SSHKey)

	exported, err := ConfigToJSON(stored)
	require.NoError(t, err)

	restored, err := ConfigFromJSON(exported)
	require.NoError(t, err, "a config exported after a login must load")
	require.Equal(t, stored.PrivateKey, restored.PrivateKey, "the restored peer is not the stored one")
	require.Equal(t, stored.SSHKey, restored.SSHKey)

	for _, missing := range []struct {
		name  string
		strip func(*Config)
	}{
		{"no WireGuard key", func(c *Config) { c.PrivateKey = "" }},
		{"no SSH key", func(c *Config) { c.SSHKey = "" }},
		{"no keys at all", func(c *Config) { c.PrivateKey = ""; c.SSHKey = "" }},
	} {
		t.Run(missing.name, func(t *testing.T) {
			incomplete := stored.clone()
			missing.strip(incomplete)

			document, err := ConfigToJSON(incomplete)
			require.NoError(t, err)

			_, err = ConfigFromJSON(document)
			require.ErrorIs(t, err, ErrConfigWithoutIdentity)
		})
	}
}
