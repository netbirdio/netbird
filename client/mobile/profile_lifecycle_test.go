package mobile

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// loadAsTheMobileSDKsDo replays what the iOS SDK does with a stored profile:
// read the config, serialize it, and load it back. Client.SetConfigFromJSON
// stores that document for tvOS, Auth.SetConfigFromJSON authenticates with it,
// and copyConfig round-trips a Config through the same pair to take an
// in-memory copy before applying the MDM overlay.
func loadAsTheMobileSDKsDo(t *testing.T, configPath string) *profilemanager.Config {
	t.Helper()

	stored, err := profilemanager.GetExistingConfig(configPath)
	require.NoError(t, err, "read the stored profile")

	document, err := profilemanager.ConfigToJSON(stored)
	require.NoError(t, err, "serialize the stored profile")

	reloaded, err := profilemanager.ConfigFromJSON(document)
	require.NoError(t, err, "load the profile back")
	return reloaded
}

// A profile survives the whole round its user puts it through: created, logged
// out, loaded again, and switched away from and back.
//
// Logout is the step that makes this worth asserting. It clears the peer's
// keys in place so the next login registers a new peer rather than bringing
// the old one back, which leaves a profile that legitimately carries no
// identity — and both mobile SDKs go on loading that profile through the
// serialized form. A load that refused it, or a creation that never wrote an
// identity in the first place, breaks logout and profile switching on iOS and
// Android without any of it being visible from the desktop client.
func TestProfileSurvivesLogoutAndReload(t *testing.T) {
	pm := newTestProfileManager(t)

	created, err := pm.AddProfile("work")
	require.NoError(t, err)
	require.NoError(t, pm.SwitchProfile(profilemanager.DefaultProfileName))

	// Created: the profile carries the identity it will connect with.
	require.NotEmpty(t, privateKeyOf(t, pm, created.ID), "a new profile was written with no identity")

	configPath, err := pm.GetConfigPath(created.ID)
	require.NoError(t, err)

	before := loadAsTheMobileSDKsDo(t, configPath)
	require.NotEmpty(t, before.PrivateKey)
	managementURL := before.ManagementURL.String()

	// Logged out: the identity is gone, on purpose.
	require.NoError(t, pm.LogoutProfile(created.ID))
	require.Empty(t, privateKeyOf(t, pm, created.ID), "logout left the peer's key behind")

	// Loaded again: the profile is still readable, and loading it neither
	// fails nor mints a key that nothing would write down.
	after := loadAsTheMobileSDKsDo(t, configPath)
	assert.Empty(t, after.PrivateKey, "loading a logged-out profile minted a key nothing will persist")
	assert.Empty(t, after.SSHKey)
	assert.Equal(t, managementURL, after.ManagementURL.String(), "the rest of the profile did not survive the logout")

	// Switched away from and back: still the same profile, still loadable.
	require.NoError(t, pm.SwitchProfile(created.ID))
	require.NoError(t, pm.SwitchProfile(profilemanager.DefaultProfileName))
	require.NoError(t, pm.SwitchProfile(created.ID))

	active, err := pm.GetActiveProfile()
	require.NoError(t, err)
	assert.Equal(t, created.ID, active.ID)

	assert.Equal(t, managementURL, loadAsTheMobileSDKsDo(t, configPath).ManagementURL.String())
}

// The profile the SDKs fall back to gets the same treatment, since it is the
// one a mobile client without an explicit profile runs on.
func TestDefaultProfileSurvivesLogoutAndReload(t *testing.T) {
	pm := newTestProfileManager(t)
	require.NoError(t, pm.SwitchProfile(profilemanager.DefaultProfileName))

	configPath, err := pm.GetConfigPath(profilemanager.DefaultProfileName)
	require.NoError(t, err)
	require.NotEmpty(t, loadAsTheMobileSDKsDo(t, configPath).PrivateKey)

	require.NoError(t, pm.LogoutProfile(profilemanager.DefaultProfileName))

	reloaded := loadAsTheMobileSDKsDo(t, configPath)
	assert.Empty(t, reloaded.PrivateKey)
	assert.NotNil(t, reloaded.ManagementURL, "the profile lost its management URL")
}
