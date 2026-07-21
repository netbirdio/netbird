package profilemanager

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/mdm"
)

// withMDMPolicy temporarily overrides the package-level loadMDMPolicy hook so
// apply() observes the supplied Policy. The original loader is restored at
// test cleanup.
func withMDMPolicy(t *testing.T, policy *mdm.Policy) {
	t.Helper()
	prev := loadMDMPolicy
	loadMDMPolicy = func() *mdm.Policy { return policy }
	t.Cleanup(func() { loadMDMPolicy = prev })
}

func TestApply_MDMEmpty_NoEnforcement(t *testing.T) {
	withMDMPolicy(t, mdm.NewPolicy(nil))

	cfg, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
	})
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.True(t, cfg.Policy().IsEmpty(), "no MDM source ⇒ empty Policy")
	assert.False(t, cfg.Policy().HasKey(mdm.KeyManagementURL))
	assert.Empty(t, cfg.Policy().ManagedKeys())

	// Default management URL still resolves.
	assert.Equal(t, DefaultManagementURL, cfg.ManagementURL.String())
}

func TestApply_MDMOnly_OverridesDefaults(t *testing.T) {
	const mdmURL = "https://corp.mdm.example.com:443"
	withMDMPolicy(t, mdm.NewPolicy(map[string]any{
		mdm.KeyManagementURL:       mdmURL,
		mdm.KeyDisableClientRoutes: true,
		mdm.KeyBlockInbound:        true,
	}))

	cfg, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
	})
	require.NoError(t, err)
	require.NotNil(t, cfg)

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

	withMDMPolicy(t, mdm.NewPolicy(map[string]any{
		mdm.KeyManagementURL: mdmURL,
	}))

	cfg, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath:    filepath.Join(t.TempDir(), "config.json"),
		ManagementURL: cliURL,
	})
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// MDM wins over CLI-supplied management URL.
	assert.Equal(t, mdmURL, cfg.ManagementURL.String())
	assert.True(t, cfg.Policy().HasKey(mdm.KeyManagementURL))
}

func TestApply_MDMInvalidURL_KeepsPreviousValue(t *testing.T) {
	withMDMPolicy(t, mdm.NewPolicy(map[string]any{
		mdm.KeyManagementURL: "not-a-url",
	}))

	cfg, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
	})
	require.NoError(t, err)
	require.NotNil(t, cfg)

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
	withMDMPolicy(t, mdm.NewPolicy(nil))
	_, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath:          tmp,
		DisableClientRoutes: boolPtr(false),
		RosenpassEnabled:    boolPtr(false),
	})
	require.NoError(t, err)

	// Now enable MDM enforcement for these keys.
	withMDMPolicy(t, mdm.NewPolicy(map[string]any{
		mdm.KeyDisableClientRoutes: true,
		mdm.KeyRosenpassEnabled:    true,
	}))

	cfg, err := UpdateOrCreateConfig(ConfigInput{ConfigPath: tmp})
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.True(t, cfg.DisableClientRoutes, "MDM override should flip on-disk false to true")
	assert.True(t, cfg.RosenpassEnabled)
	assert.True(t, cfg.Policy().HasKey(mdm.KeyDisableClientRoutes))
	assert.True(t, cfg.Policy().HasKey(mdm.KeyRosenpassEnabled))
}

func TestApply_MDMVNCKeys(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "config.json")

	// Seed without MDM: VNC off, approval prompt on.
	withMDMPolicy(t, mdm.NewPolicy(nil))
	_, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath:         tmp,
		ServerVNCAllowed:   boolPtr(false),
		DisableVNCApproval: boolPtr(false),
	})
	require.NoError(t, err)

	// MDM enforces VNC on and disables the approval prompt.
	withMDMPolicy(t, mdm.NewPolicy(map[string]any{
		mdm.KeyAllowServerVNC:     true,
		mdm.KeyDisableVNCApproval: true,
	}))

	cfg, err := UpdateOrCreateConfig(ConfigInput{ConfigPath: tmp})
	require.NoError(t, err)
	require.NotNil(t, cfg)

	require.NotNil(t, cfg.ServerVNCAllowed)
	assert.True(t, *cfg.ServerVNCAllowed, "MDM override should flip on-disk false to true")
	require.NotNil(t, cfg.DisableVNCApproval)
	assert.True(t, *cfg.DisableVNCApproval)
	assert.True(t, cfg.Policy().HasKey(mdm.KeyAllowServerVNC))
	assert.True(t, cfg.Policy().HasKey(mdm.KeyDisableVNCApproval))
}

func TestApply_MDMLazyConnection(t *testing.T) {
	cases := []struct {
		name string
		raw  any
		want string
	}{
		{"native true", true, "on"},
		{"native false", false, "off"},
		{"string on", "on", "on"},
		{"string off", "off", "off"},
		{"string yes", "yes", "on"},
		{"string no", "no", "off"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withMDMPolicy(t, mdm.NewPolicy(map[string]any{
				mdm.KeyLazyConnection: c.raw,
			}))

			cfg, err := UpdateOrCreateConfig(ConfigInput{
				ConfigPath: filepath.Join(t.TempDir(), "config.json"),
			})
			require.NoError(t, err)
			require.NotNil(t, cfg)

			assert.Equal(t, c.want, cfg.LazyConnection)
			assert.True(t, cfg.Policy().HasKey(mdm.KeyLazyConnection))
		})
	}
}

func TestApply_MDMPreSharedKeyRedactionSentinelRejected(t *testing.T) {
	const maskSentinel = "**********"

	withMDMPolicy(t, mdm.NewPolicy(map[string]any{
		mdm.KeyPreSharedKey: maskSentinel,
	}))

	cfg, err := UpdateOrCreateConfig(ConfigInput{
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
	})
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Mask sentinel must not be persisted as the actual PSK.
	assert.NotEqual(t, maskSentinel, cfg.PreSharedKey)
	// Key still marked managed so user writes are still rejected.
	assert.True(t, cfg.Policy().HasKey(mdm.KeyPreSharedKey))
}

func boolPtr(b bool) *bool { return &b }
