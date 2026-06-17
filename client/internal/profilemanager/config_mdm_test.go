package profilemanager

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/mdm"
)

// fakeFetcher implements mdm.PolicyFetcher returning a pre-set policy
// map. Test helper used to construct a Loader without touching the OS
// or any package-level state.
type fakeFetcher struct{ values map[string]any }

func (f *fakeFetcher) Fetch() map[string]any { return f.values }

// loaderFor builds an mdm.Loader whose loadPlatform returns the
// supplied Policy's underlying values.
func loaderFor(policy *mdm.Policy) *mdm.Loader {
	if policy == nil || policy.IsEmpty() {
		return mdm.NewLoader(&fakeFetcher{values: nil})
	}
	values := make(map[string]any)
	for _, k := range policy.ManagedKeys() {
		if v, ok := policy.GetString(k); ok {
			values[k] = v
			continue
		}
		if v, ok := policy.GetBool(k); ok {
			values[k] = v
			continue
		}
		if v, ok := policy.GetInt(k); ok {
			values[k] = v
			continue
		}
		if v, ok := policy.GetStringSlice(k); ok {
			values[k] = v
		}
	}
	return mdm.NewLoader(&fakeFetcher{values: values})
}

// configWithMDM is the test convenience that builds a Config via
// UpdateOrCreateConfig and overlays the supplied MDM policy on top —
// mirrors the production pattern (Server.getConfig / Client.applyMDMOverlay)
// where the Loader lives outside Config and the apply step is driven
// by the lifecycle owner.
func configWithMDM(t *testing.T, input ConfigInput, policy *mdm.Policy) *Config {
	t.Helper()
	cfg, err := UpdateOrCreateConfig(input)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	cfg.ApplyMDMPolicy(loaderFor(policy).Load())
	return cfg
}

func TestApply_MDMEmpty_NoEnforcement(t *testing.T) {
	cfg := configWithMDM(t, ConfigInput{
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
	}, mdm.NewPolicy(nil))

	assert.True(t, cfg.Policy().IsEmpty(), "no MDM source ⇒ empty Policy")
	assert.False(t, cfg.Policy().HasKey(mdm.KeyManagementURL))
	assert.Empty(t, cfg.Policy().ManagedKeys())

	// Default management URL still resolves.
	assert.Equal(t, DefaultManagementURL, cfg.ManagementURL.String())
}

func TestApply_MDMOnly_OverridesDefaults(t *testing.T) {
	const mdmURL = "https://corp.mdm.example.com:443"

	cfg := configWithMDM(t, ConfigInput{
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
	}, mdm.NewPolicy(map[string]any{
		mdm.KeyManagementURL:       mdmURL,
		mdm.KeyDisableClientRoutes: true,
		mdm.KeyBlockInbound:        true,
	}))

	assert.Equal(t, mdmURL, cfg.ManagementURL.String())
	assert.True(t, cfg.DisableClientRoutes)
	assert.True(t, cfg.BlockInbound)

	assert.True(t, cfg.Policy().HasKey(mdm.KeyManagementURL))
	assert.True(t, cfg.Policy().HasKey(mdm.KeyDisableClientRoutes))
	assert.True(t, cfg.Policy().HasKey(mdm.KeyBlockInbound))
	assert.False(t, cfg.Policy().HasKey(mdm.KeyAllowServerSSH))
}

func TestApply_MDMBeatsCLIInput(t *testing.T) {
	const mdmURL = "https://mdm.example.com:443"
	const cliURL = "https://cli.example.com:443"

	cfg := configWithMDM(t, ConfigInput{
		ConfigPath:    filepath.Join(t.TempDir(), "config.json"),
		ManagementURL: cliURL,
	}, mdm.NewPolicy(map[string]any{
		mdm.KeyManagementURL: mdmURL,
	}))

	// MDM wins over CLI-supplied management URL.
	assert.Equal(t, mdmURL, cfg.ManagementURL.String())
	assert.True(t, cfg.Policy().HasKey(mdm.KeyManagementURL))
}

func TestApply_MDMInvalidURL_KeepsPreviousValue(t *testing.T) {
	cfg := configWithMDM(t, ConfigInput{
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
	}, mdm.NewPolicy(map[string]any{
		mdm.KeyManagementURL: "not-a-url",
	}))

	// Invalid MDM URL is logged and skipped: default URL stays in place
	// to keep the client functional.
	assert.Equal(t, DefaultManagementURL, cfg.ManagementURL.String())

	// But the key is still considered MDM-managed (admin intent is to
	// enforce, daemon rejects user writes to this field — phase-1 scaffolding
	// reflects this by keeping Policy.HasKey true even on parse failure).
	assert.True(t, cfg.Policy().HasKey(mdm.KeyManagementURL))
}

func TestApply_MDMBoolKeysOverrideOnDiskValue(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "config.json")

	// Seed without MDM.
	configWithMDM(t, ConfigInput{
		ConfigPath:          tmp,
		DisableClientRoutes: boolPtr(false),
		RosenpassEnabled:    boolPtr(false),
	}, mdm.NewPolicy(nil))

	// Now enable MDM enforcement for these keys.
	cfg := configWithMDM(t, ConfigInput{
		ConfigPath: tmp,
	}, mdm.NewPolicy(map[string]any{
		mdm.KeyDisableClientRoutes: true,
		mdm.KeyRosenpassEnabled:    true,
	}))

	assert.True(t, cfg.DisableClientRoutes, "MDM override should flip on-disk false to true")
	assert.True(t, cfg.RosenpassEnabled)
	assert.True(t, cfg.Policy().HasKey(mdm.KeyDisableClientRoutes))
	assert.True(t, cfg.Policy().HasKey(mdm.KeyRosenpassEnabled))
}

func TestApply_MDMPreSharedKeyRedactionSentinelRejected(t *testing.T) {
	const maskSentinel = "**********"

	cfg := configWithMDM(t, ConfigInput{
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
	}, mdm.NewPolicy(map[string]any{
		mdm.KeyPreSharedKey: maskSentinel,
	}))

	// Mask sentinel must not be persisted as the actual PSK.
	assert.NotEqual(t, maskSentinel, cfg.PreSharedKey)
	// Key still marked managed so user writes are still rejected.
	assert.True(t, cfg.Policy().HasKey(mdm.KeyPreSharedKey))
}

func boolPtr(b bool) *bool { return &b }
