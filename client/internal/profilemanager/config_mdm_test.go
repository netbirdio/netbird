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

func TestApply_MDMLocalMetrics(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "config.json")

	// Seed without MDM.
	configWithMDM(t, ConfigInput{
		ConfigPath:          tmp,
		LocalMetricsEnabled: boolPtr(false),
	}, mdm.NewPolicy(nil))

	// Now enable MDM enforcement for these keys.
	cfg := configWithMDM(t, ConfigInput{
		ConfigPath: tmp,
	}, mdm.NewPolicy(map[string]any{
		mdm.KeyEnableLocalMetrics:  true,
		mdm.KeyLocalMetricsAddress: "127.0.0.1:9292",
	}))

	assert.True(t, cfg.LocalMetricsEnabled, "MDM override should flip on-disk false to true")
	assert.Equal(t, "127.0.0.1:9292", cfg.LocalMetricsAddress)
	assert.True(t, cfg.Policy().HasKey(mdm.KeyEnableLocalMetrics))
	assert.True(t, cfg.Policy().HasKey(mdm.KeyLocalMetricsAddress))
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
			cfg := configWithMDM(t, ConfigInput{
				ConfigPath: filepath.Join(t.TempDir(), "config.json"),
			}, mdm.NewPolicy(map[string]any{
				mdm.KeyLazyConnection: c.raw,
			}))

			assert.Equal(t, c.want, cfg.LazyConnection)
			assert.True(t, cfg.Policy().HasKey(mdm.KeyLazyConnection))
		})
	}
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

func TestMDMConflicts_PreSharedKey(t *testing.T) {
	policy := mdm.NewPolicy(map[string]any{
		mdm.KeyPreSharedKey: "mdm-enforced-psk",
	})
	empty := ""
	sentinel := "**********"
	same := "mdm-enforced-psk"
	other := "user-psk"

	tests := []struct {
		name string
		psk  *string
		want []string
	}{
		{name: "unset", psk: nil, want: nil},
		{name: "explicit empty", psk: &empty, want: []string{mdm.KeyPreSharedKey}},
		{name: "sentinel echo", psk: &sentinel, want: nil},
		{name: "same value", psk: &same, want: nil},
		{name: "divergent", psk: &other, want: []string{mdm.KeyPreSharedKey}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, MDMConflicts(ConfigInput{PreSharedKey: tc.psk}, policy))
		})
	}
}

func TestMDMConflicts_RemoteJobsAndLocalMetrics(t *testing.T) {
	policy := mdm.NewPolicy(map[string]any{
		mdm.KeyRemoteJobsAllowed:   false,
		mdm.KeyEnableLocalMetrics:  true,
		mdm.KeyLocalMetricsAddress: "127.0.0.1:9999",
	})
	sameAddr := "127.0.0.1:9999"
	otherAddr := "0.0.0.0:9999"
	emptyAddr := ""

	tests := []struct {
		name  string
		input ConfigInput
		want  []string
	}{
		{name: "unset", input: ConfigInput{}, want: nil},
		{name: "echo", input: ConfigInput{
			RemoteJobsAllowed:   boolPtr(false),
			LocalMetricsEnabled: boolPtr(true),
			LocalMetricsAddress: &sameAddr,
		}, want: nil},
		{name: "remote jobs divergent", input: ConfigInput{RemoteJobsAllowed: boolPtr(true)}, want: []string{mdm.KeyRemoteJobsAllowed}},
		{name: "metrics disabled", input: ConfigInput{LocalMetricsEnabled: boolPtr(false)}, want: []string{mdm.KeyEnableLocalMetrics}},
		{name: "metrics address divergent", input: ConfigInput{LocalMetricsAddress: &otherAddr}, want: []string{mdm.KeyLocalMetricsAddress}},
		{name: "metrics address explicit empty", input: ConfigInput{LocalMetricsAddress: &emptyAddr}, want: []string{mdm.KeyLocalMetricsAddress}},
		{name: "all divergent", input: ConfigInput{
			RemoteJobsAllowed:   boolPtr(true),
			LocalMetricsEnabled: boolPtr(false),
			LocalMetricsAddress: &otherAddr,
		}, want: []string{mdm.KeyRemoteJobsAllowed, mdm.KeyEnableLocalMetrics, mdm.KeyLocalMetricsAddress}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, MDMConflicts(tc.input, policy))
		})
	}
}

func boolPtr(b bool) *bool { return &b }
