package profilemanager

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

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
		if v, ok := policy.GetInt(k); ok {
			values[k] = v
			continue
		}
		if v, ok := policy.GetBool(k); ok {
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

func TestApply_MDMVNCKeys(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "config.json")

	// Seed without MDM: VNC off, approval prompt on.
	configWithMDM(t, ConfigInput{
		ConfigPath:         tmp,
		ServerVNCAllowed:   boolPtr(false),
		DisableVNCApproval: boolPtr(false),
	}, mdm.NewPolicy(nil))

	// MDM enforces VNC on and disables the approval prompt.
	cfg := configWithMDM(t, ConfigInput{
		ConfigPath: tmp,
	}, mdm.NewPolicy(map[string]any{
		mdm.KeyAllowServerVNC:     true,
		mdm.KeyDisableVNCApproval: true,
	}))

	require.NotNil(t, cfg.ServerVNCAllowed)
	assert.True(t, *cfg.ServerVNCAllowed, "MDM override should flip on-disk false to true")
	require.NotNil(t, cfg.DisableVNCApproval)
	assert.True(t, *cfg.DisableVNCApproval)
	assert.True(t, cfg.Policy().HasKey(mdm.KeyAllowServerVNC))
	assert.True(t, cfg.Policy().HasKey(mdm.KeyDisableVNCApproval))
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
	const maskSentinel = mdm.PreSharedKeyRedactedSentinel

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
	sentinel := mdm.PreSharedKeyRedactedSentinel
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

// persistedIFaceBlackList reads the blacklist straight from the profile file,
// bypassing apply(), to prove what actually reached the disk.
func persistedIFaceBlackList(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var onDisk Config
	require.NoError(t, json.Unmarshal(raw, &onDisk))
	return onDisk.IFaceBlackList
}

func TestApply_MDMExtraIFaceBlackList_AddsToResolvedList(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "config.json")

	// The device carries its own exclusion from the CLI flag; MDM adds the
	// fleet-wide ones on top, without replacing either the defaults or it.
	cfg := configWithMDM(t, ConfigInput{
		ConfigPath:          tmp,
		ExtraIFaceBlackList: []string{"vmnet"},
	}, mdm.NewPolicy(map[string]any{
		mdm.KeyExtraIFaceBlackList: []string{"vxlan", "gre"},
	}))

	for _, want := range append(slices.Clone(DefaultInterfaceBlacklist), "vmnet", "vxlan", "gre") {
		assert.Contains(t, cfg.IFaceBlackList, want, "effective blacklist should contain %q", want)
	}
	assert.True(t, cfg.Policy().HasKey(mdm.KeyExtraIFaceBlackList))

}

func TestApply_MDMExtraIFaceBlackList_NotPersistedByLaterWrite(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "config.json")
	policy := mdm.NewPolicy(map[string]any{mdm.KeyExtraIFaceBlackList: []string{"vxlan", "gre"}})

	managed := configWithMDM(t, ConfigInput{ConfigPath: tmp}, policy)
	require.Contains(t, managed.IFaceBlackList, "vxlan", "precondition: MDM entry applied")

	// A settings change while the policy is active rewrites the profile file,
	// as SetConfig or `netbird up --extra-iface-blacklist` would.
	configWithMDM(t, ConfigInput{ConfigPath: tmp, ExtraIFaceBlackList: []string{"vmnet"}}, policy)

	onDisk := persistedIFaceBlackList(t, tmp)
	assert.Contains(t, onDisk, "vmnet", "the device's own entry belongs to the profile file")
	assert.NotContains(t, onDisk, "vxlan", "MDM entries must never be written to the profile file")
	assert.NotContains(t, onDisk, "gre", "MDM entries must never be written to the profile file")
}

func TestApply_MDMExtraIFaceBlackList_DoesNotWriteIntoSharedBackingArray(t *testing.T) {
	// A Config copied by value shares its blacklist backing array with the
	// original; spare capacity must not let the overlay write into it.
	shared := make([]string, 1, 4)
	shared[0] = "docker"
	original := Config{IFaceBlackList: shared}
	overlaid := original

	overlaid.ApplyMDMPolicy(mdm.NewPolicy(map[string]any{mdm.KeyExtraIFaceBlackList: "vxlan"}))

	require.Equal(t, []string{"docker", "vxlan"}, overlaid.IFaceBlackList, "precondition: MDM entry applied")
	assert.Equal(t, []string{"docker"}, original.IFaceBlackList, "the original list must be unchanged")
	assert.Equal(t, "", shared[:cap(shared)][1], "the shared backing array must not receive the MDM entry")
}

func TestApply_MDMExtraIFaceBlackList_CommaSeparatedString(t *testing.T) {
	cfg := configWithMDM(t, ConfigInput{
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
	}, mdm.NewPolicy(map[string]any{
		// An ADMX text box arrives as a single REG_SZ: blanks, empty items,
		// repeats and an entry already in the defaults must all collapse.
		mdm.KeyExtraIFaceBlackList: " vxlan, gre,,vxlan , docker",
	}))

	assert.Equal(t, 1, countOf(cfg.IFaceBlackList, "vxlan"), "vxlan should appear once in %v", cfg.IFaceBlackList)
	assert.Equal(t, 1, countOf(cfg.IFaceBlackList, "gre"), "gre should appear once in %v", cfg.IFaceBlackList)
	assert.Equal(t, 1, countOf(cfg.IFaceBlackList, "docker"), "docker is a default and must not be duplicated in %v", cfg.IFaceBlackList)
	assert.NotContains(t, cfg.IFaceBlackList, "", "empty items must be dropped")
}

func TestApply_MDMExtraIFaceBlackList_RemovedWhenPolicyDropsKey(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "config.json")

	managed := configWithMDM(t, ConfigInput{ConfigPath: tmp}, mdm.NewPolicy(map[string]any{
		mdm.KeyExtraIFaceBlackList: "vxlan",
	}))
	require.Contains(t, managed.IFaceBlackList, "vxlan", "precondition: MDM entry applied")

	// The next policy reload resolves the profile again from disk, as the
	// lifecycle owners do, and the admin has removed the key meanwhile.
	unmanaged := configWithMDM(t, ConfigInput{ConfigPath: tmp}, mdm.NewPolicy(nil))
	assert.NotContains(t, unmanaged.IFaceBlackList, "vxlan", "entry must vanish once the policy drops it")
	assert.ElementsMatch(t, DefaultInterfaceBlacklist, unmanaged.IFaceBlackList, "only the defaults should remain")
}

func TestApply_MDMExtraIFaceBlackList_ReapplyIsIdempotent(t *testing.T) {
	policy := mdm.NewPolicy(map[string]any{mdm.KeyExtraIFaceBlackList: []string{"vxlan"}})
	cfg := configWithMDM(t, ConfigInput{ConfigPath: filepath.Join(t.TempDir(), "config.json")}, policy)

	cfg.ApplyMDMPolicy(policy)

	assert.Equal(t, 1, countOf(cfg.IFaceBlackList, "vxlan"), "re-applying must not duplicate in %v", cfg.IFaceBlackList)
}

func TestApply_MDMExtraIFaceBlackList_InvalidTypeIgnored(t *testing.T) {
	cfg := configWithMDM(t, ConfigInput{
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
	}, mdm.NewPolicy(map[string]any{
		mdm.KeyExtraIFaceBlackList: 42,
	}))

	assert.ElementsMatch(t, DefaultInterfaceBlacklist, cfg.IFaceBlackList, "a non-list value must leave the blacklist untouched")
	assert.True(t, cfg.Policy().HasKey(mdm.KeyExtraIFaceBlackList), "the key is still reported as managed")
}

func countOf(list []string, item string) int {
	n := 0
	for _, v := range list {
		if v == item {
			n++
		}
	}
	return n
}

func boolPtr(b bool) *bool { return &b }

func TestApply_MDMNetworkBoolKeysOverrideOnDiskValue(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "config.json")

	// The profile file holds the opposite of every value MDM is about to
	// enforce, so each assertion proves the override and not a default.
	configWithMDM(t, ConfigInput{
		ConfigPath:           tmp,
		DisableDNS:           boolPtr(false),
		DisableIPv6:          boolPtr(false),
		DisableFirewall:      boolPtr(false),
		BlockLANAccess:       boolPtr(false),
		DisableNotifications: boolPtr(true),
		NetworkMonitor:       boolPtr(true),
	}, mdm.NewPolicy(nil))
	before, err := os.ReadFile(tmp)
	require.NoError(t, err)

	cfg := configWithMDM(t, ConfigInput{ConfigPath: tmp}, mdm.NewPolicy(map[string]any{
		mdm.KeyDisableDNS:           true,
		mdm.KeyDisableIPv6:          "yes",
		mdm.KeyDisableFirewall:      int64(1),
		mdm.KeyBlockLANAccess:       true,
		mdm.KeyDisableNotifications: false,
		mdm.KeyNetworkMonitor:       "off",
		mdm.KeyDisableIPv6Discovery: true,
	}))

	assert.True(t, cfg.DisableDNS, "disableDNS")
	assert.True(t, cfg.DisableIPv6, "disableIPv6 from a string literal")
	assert.True(t, cfg.DisableFirewall, "disableFirewall from a REG_DWORD")
	assert.True(t, cfg.BlockLANAccess, "blockLANAccess")
	require.NotNil(t, cfg.DisableNotifications)
	assert.False(t, *cfg.DisableNotifications, "disableNotifications")
	require.NotNil(t, cfg.NetworkMonitor)
	assert.False(t, *cfg.NetworkMonitor, "networkMonitor")
	assert.True(t, cfg.DisableIPv6Discovery, "disableIPv6Discovery")

	after, err := os.ReadFile(tmp)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "MDM values must not reach the profile file")
}

func TestApply_MDMNetworkBoolKeys_UnparseableValueKeepsProfileValue(t *testing.T) {
	cfg := configWithMDM(t, ConfigInput{
		ConfigPath: filepath.Join(t.TempDir(), "config.json"),
		DisableDNS: boolPtr(true),
	}, mdm.NewPolicy(map[string]any{
		mdm.KeyDisableDNS: "maybe",
	}))

	assert.True(t, cfg.DisableDNS, "an unparseable bool must not flip the profile value")
	assert.True(t, cfg.Policy().HasKey(mdm.KeyDisableDNS), "the key stays managed so user writes are still rejected")
}

func TestMDMConflicts_NetworkBoolKeys(t *testing.T) {
	policy := mdm.NewPolicy(map[string]any{
		mdm.KeyDisableDNS:           true,
		mdm.KeyDisableIPv6:          true,
		mdm.KeyDisableFirewall:      true,
		mdm.KeyBlockLANAccess:       true,
		mdm.KeyDisableNotifications: true,
		mdm.KeyNetworkMonitor:       false,
	})

	tests := []struct {
		name  string
		input ConfigInput
		want  []string
	}{
		{name: "unset", input: ConfigInput{}, want: nil},
		{name: "echo", input: ConfigInput{
			DisableDNS:           boolPtr(true),
			DisableIPv6:          boolPtr(true),
			DisableFirewall:      boolPtr(true),
			BlockLANAccess:       boolPtr(true),
			DisableNotifications: boolPtr(true),
			NetworkMonitor:       boolPtr(false),
		}, want: nil},
		{name: "all divergent", input: ConfigInput{
			DisableDNS:           boolPtr(false),
			DisableIPv6:          boolPtr(false),
			DisableFirewall:      boolPtr(false),
			BlockLANAccess:       boolPtr(false),
			DisableNotifications: boolPtr(false),
			NetworkMonitor:       boolPtr(true),
		}, want: []string{
			mdm.KeyDisableDNS, mdm.KeyDisableIPv6, mdm.KeyDisableFirewall,
			mdm.KeyBlockLANAccess, mdm.KeyDisableNotifications, mdm.KeyNetworkMonitor,
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, MDMConflicts(tc.input, policy), "conflicting keys")
		})
	}
}

func TestApply_MDMNetworkValueKeysOverrideOnDiskValue(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "config.json")
	iface := "utun250"
	mtu := uint16(1400)
	interval := time.Minute
	configWithMDM(t, ConfigInput{
		ConfigPath:       tmp,
		InterfaceName:    &iface,
		MTU:              &mtu,
		DNSRouteInterval: &interval,
		NATExternalIPs:   []string{"198.51.100.1"},
	}, mdm.NewPolicy(nil))
	before, err := os.ReadFile(tmp)
	require.NoError(t, err)

	cfg := configWithMDM(t, ConfigInput{ConfigPath: tmp}, mdm.NewPolicy(map[string]any{
		mdm.KeyInterfaceName:    "utun100",
		mdm.KeyMTU:              int64(1280),
		mdm.KeyDNSRouteInterval: "90s",
		mdm.KeyNATExternalIPs:   " 203.0.113.7, 203.0.113.8/10.0.0.1,,203.0.113.7",
	}))

	assert.Equal(t, "utun100", cfg.WgIface, "interfaceName")
	assert.Equal(t, uint16(1280), cfg.MTU, "mtu")
	assert.Equal(t, 90*time.Second, cfg.DNSRouteInterval, "dnsRouteInterval")
	assert.Equal(t, []string{"203.0.113.7", "203.0.113.8/10.0.0.1"}, cfg.NATExternalIPs,
		"natExternalIPs is split, trimmed and deduplicated")

	after, err := os.ReadFile(tmp)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "MDM values must not reach the profile file")
}

func TestApply_MDMNetworkValueKeys_InvalidValueKeepsProfileValue(t *testing.T) {
	iface := "utun250"
	mtu := uint16(1400)
	interval := time.Minute
	input := ConfigInput{
		InterfaceName:    &iface,
		MTU:              &mtu,
		DNSRouteInterval: &interval,
	}

	tests := []struct {
		name  string
		key   string
		value any
		check func(t *testing.T, cfg *Config)
	}{
		{"mtu below minimum", mdm.KeyMTU, int64(100), func(t *testing.T, cfg *Config) {
			assert.Equal(t, mtu, cfg.MTU, "mtu")
		}},
		{"mtu above maximum", mdm.KeyMTU, int64(70000), func(t *testing.T, cfg *Config) {
			assert.Equal(t, mtu, cfg.MTU, "mtu")
		}},
		{"interval not a duration", mdm.KeyDNSRouteInterval, "90", func(t *testing.T, cfg *Config) {
			assert.Equal(t, time.Minute, cfg.DNSRouteInterval, "dnsRouteInterval")
		}},
		{"interval negative", mdm.KeyDNSRouteInterval, "-1m", func(t *testing.T, cfg *Config) {
			assert.Equal(t, time.Minute, cfg.DNSRouteInterval, "dnsRouteInterval")
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := input
			in.ConfigPath = filepath.Join(t.TempDir(), "config.json")
			cfg := configWithMDM(t, in, mdm.NewPolicy(map[string]any{tc.key: tc.value}))
			tc.check(t, cfg)
			assert.True(t, cfg.Policy().HasKey(tc.key), "the key stays managed so user writes are still rejected")
		})
	}
}

func TestMDMConflicts_NetworkValueKeys(t *testing.T) {
	policy := mdm.NewPolicy(map[string]any{
		mdm.KeyInterfaceName:    "utun100",
		mdm.KeyMTU:              int64(1280),
		mdm.KeyDNSRouteInterval: "90s",
		mdm.KeyNATExternalIPs:   "203.0.113.7,203.0.113.8",
	})
	sameIface, otherIface := "utun100", "utun7"
	sameMTU, otherMTU := uint16(1280), uint16(1400)
	sameInterval, otherInterval := 90*time.Second, time.Minute

	tests := []struct {
		name  string
		input ConfigInput
		want  []string
	}{
		{name: "unset", input: ConfigInput{}, want: nil},
		{name: "echo", input: ConfigInput{
			InterfaceName:    &sameIface,
			MTU:              &sameMTU,
			DNSRouteInterval: &sameInterval,
			NATExternalIPs:   []string{"203.0.113.7", "203.0.113.8"},
		}, want: nil},
		{name: "all divergent", input: ConfigInput{
			InterfaceName:    &otherIface,
			MTU:              &otherMTU,
			DNSRouteInterval: &otherInterval,
			NATExternalIPs:   []string{"203.0.113.9"},
		}, want: []string{
			mdm.KeyInterfaceName, mdm.KeyMTU,
			mdm.KeyDNSRouteInterval, mdm.KeyNATExternalIPs,
		}},
		{name: "clearing a managed list", input: ConfigInput{
			NATExternalIPs: []string{},
		}, want: []string{mdm.KeyNATExternalIPs}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, MDMConflicts(tc.input, policy), "conflicting keys")
		})
	}
}

func TestIsUtunName(t *testing.T) {
	// macOS only accepts utun followed by the unit number; anything else makes
	// interface creation fail and would leave the device offline.
	for name, want := range map[string]bool{
		"utun100": true,
		"utun0":   true,
		"utun":    false,
		"utunabc": false,
		"utun1a":  false,
		"nbmdm":   false,
		"wt0":     false,
	} {
		assert.Equal(t, want, isUtunName(name), "isUtunName(%q)", name)
	}
}

func TestApply_MDMSSHKeysOverrideOnDiskValue(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "config.json")

	// The profile file holds the opposite of every value MDM is about to
	// enforce, so each assertion proves the override and not a default.
	configWithMDM(t, ConfigInput{
		ConfigPath:                    tmp,
		EnableSSHRoot:                 boolPtr(false),
		EnableSSHSFTP:                 boolPtr(false),
		EnableSSHLocalPortForwarding:  boolPtr(false),
		EnableSSHRemotePortForwarding: boolPtr(true),
		DisableSSHAuth:                boolPtr(false),
		SSHJWTCacheTTL:                intPtr(0),
	}, mdm.NewPolicy(nil))
	before, err := os.ReadFile(tmp)
	require.NoError(t, err)

	cfg := configWithMDM(t, ConfigInput{ConfigPath: tmp}, mdm.NewPolicy(map[string]any{
		mdm.KeyEnableSSHRoot:                 true,
		mdm.KeyEnableSSHSFTP:                 "yes",
		mdm.KeyEnableSSHLocalPortForwarding:  int64(1),
		mdm.KeyEnableSSHRemotePortForwarding: false,
		mdm.KeyDisableSSHAuth:                true,
		mdm.KeySSHJWTCacheTTL:                int64(3600),
	}))

	require.NotNil(t, cfg.EnableSSHRoot)
	assert.True(t, *cfg.EnableSSHRoot, "enableSSHRoot")
	require.NotNil(t, cfg.EnableSSHSFTP)
	assert.True(t, *cfg.EnableSSHSFTP, "enableSSHSFTP from a string literal")
	require.NotNil(t, cfg.EnableSSHLocalPortForwarding)
	assert.True(t, *cfg.EnableSSHLocalPortForwarding, "enableSSHLocalPortForwarding from a REG_DWORD")
	require.NotNil(t, cfg.EnableSSHRemotePortForwarding)
	assert.False(t, *cfg.EnableSSHRemotePortForwarding, "enableSSHRemotePortForwarding")
	require.NotNil(t, cfg.DisableSSHAuth)
	assert.True(t, *cfg.DisableSSHAuth, "disableSSHAuth")
	require.NotNil(t, cfg.SSHJWTCacheTTL)
	assert.Equal(t, 3600, *cfg.SSHJWTCacheTTL, "sshJWTCacheTTL")

	after, err := os.ReadFile(tmp)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "MDM values must not reach the profile file")
}

func TestApply_MDMSSHJWTCacheTTL_OutOfRangeKeepsProfileValue(t *testing.T) {
	for _, v := range []int64{-1, 1 << 40} {
		cfg := configWithMDM(t, ConfigInput{
			ConfigPath:     filepath.Join(t.TempDir(), "config.json"),
			SSHJWTCacheTTL: intPtr(600),
		}, mdm.NewPolicy(map[string]any{mdm.KeySSHJWTCacheTTL: v}))

		require.NotNil(t, cfg.SSHJWTCacheTTL)
		assert.Equal(t, 600, *cfg.SSHJWTCacheTTL, "TTL %d must be skipped", v)
	}
}

func TestMDMConflicts_SSHKeys(t *testing.T) {
	policy := mdm.NewPolicy(map[string]any{
		mdm.KeyEnableSSHRoot:                 true,
		mdm.KeyEnableSSHSFTP:                 true,
		mdm.KeyEnableSSHLocalPortForwarding:  true,
		mdm.KeyEnableSSHRemotePortForwarding: false,
		mdm.KeyDisableSSHAuth:                false,
		mdm.KeySSHJWTCacheTTL:                int64(3600),
	})

	tests := []struct {
		name  string
		input ConfigInput
		want  []string
	}{
		{name: "unset", input: ConfigInput{}, want: nil},
		{name: "echo", input: ConfigInput{
			EnableSSHRoot:                 boolPtr(true),
			EnableSSHSFTP:                 boolPtr(true),
			EnableSSHLocalPortForwarding:  boolPtr(true),
			EnableSSHRemotePortForwarding: boolPtr(false),
			DisableSSHAuth:                boolPtr(false),
			SSHJWTCacheTTL:                intPtr(3600),
		}, want: nil},
		{name: "all divergent", input: ConfigInput{
			EnableSSHRoot:                 boolPtr(false),
			EnableSSHSFTP:                 boolPtr(false),
			EnableSSHLocalPortForwarding:  boolPtr(false),
			EnableSSHRemotePortForwarding: boolPtr(true),
			DisableSSHAuth:                boolPtr(true),
			SSHJWTCacheTTL:                intPtr(60),
		}, want: []string{
			mdm.KeyEnableSSHRoot, mdm.KeyEnableSSHSFTP, mdm.KeyEnableSSHLocalPortForwarding,
			mdm.KeyEnableSSHRemotePortForwarding, mdm.KeyDisableSSHAuth, mdm.KeySSHJWTCacheTTL,
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, MDMConflicts(tc.input, policy), "conflicting keys")
		})
	}
}

func TestApply_MDMForceRelayOverridesOnDiskValue(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "config.json")
	configWithMDM(t, ConfigInput{ConfigPath: tmp, ForceRelay: boolPtr(false)}, mdm.NewPolicy(nil))
	before, err := os.ReadFile(tmp)
	require.NoError(t, err)

	cfg := configWithMDM(t, ConfigInput{ConfigPath: tmp}, mdm.NewPolicy(map[string]any{mdm.KeyForceRelay: true}))

	assert.True(t, cfg.ForceRelay, "the policy value applies")
	after, err := os.ReadFile(tmp)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "the policy value is never written to the profile")
}

func TestMDMConflicts_ForceRelay(t *testing.T) {
	policy := mdm.NewPolicy(map[string]any{mdm.KeyForceRelay: true})

	assert.Nil(t, MDMConflicts(ConfigInput{}, policy), "an unset value does not conflict")
	assert.Nil(t, MDMConflicts(ConfigInput{ForceRelay: boolPtr(true)}, policy), "a value matching the policy does not conflict")
	assert.Equal(t, []string{mdm.KeyForceRelay}, MDMConflicts(ConfigInput{ForceRelay: boolPtr(false)}, policy), "a differing value conflicts")
}
