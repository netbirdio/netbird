package mdm

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		assert.Equal(t, want, IsUtunName(name), "IsUtunName(%q)", name)
	}
}

func TestIsLinuxInterfaceName(t *testing.T) {
	// The kernel refuses these names, so interface creation would fail and
	// leave the device offline.
	for name, want := range map[string]bool{
		"wt0":              true,
		"nb-mdm_1":         true,
		"fifteen-chars15":  true,
		"sixteen-chars-16": false,
		"":                 false,
		".":                false,
		"..":               false,
		"bad/name":         false,
		"bad:name":         false,
		"bad name":         false,
		"tab\tname":        false,
		"wt%d":             false,
	} {
		assert.Equal(t, want, isLinuxInterfaceName(name), "isLinuxInterfaceName(%q)", name)
	}
}

// An admin typo in a tuning key must not lock the setting to a value nothing
// applies: the key is dropped, so the UI shows the control and the daemon
// accepts the user's own value.
func TestUnusableTuningValueLeavesSettingToUser(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value any
	}{
		{"mtu above maximum", KeyMTU, int64(9000)},
		{"mtu below minimum", KeyMTU, int64(100)},
		{"mtu not a number", KeyMTU, "big"},
		{"port zero", KeyWireguardPort, int64(0)},
		{"port above range", KeyWireguardPort, int64(70000)},
		{"ttl negative", KeySSHJWTCacheTTL, int64(-1)},
		{"interval not a duration", KeyDNSRouteInterval, "90"},
		{"interval negative", KeyDNSRouteInterval, "-1m"},
		{"interface name empty", KeyInterfaceName, ""},
		{"nat mappings not a list", KeyNATExternalIPs, 42},
		{"nat mapping not an IP", KeyNATExternalIPs, "not-an-ip"},
		{"nat mapping with an empty internal part", KeyNATExternalIPs, "203.0.113.10/"},
		{"nat mapping with too many parts", KeyNATExternalIPs, "203.0.113.10/10.0.0.1/eth0"},
		{"nat mappings with one bad entry", KeyNATExternalIPs, "203.0.113.10,bad"},
		{"nat mapping with a v4 CIDR suffix", KeyNATExternalIPs, "203.0.113.10/32"},
		{"nat mapping with a v6 CIDR suffix", KeyNATExternalIPs, "2001:db8::1/64"},
		{"nat mapping with a zoned external", KeyNATExternalIPs, "fe80::1%eth0"},
		{"nat mapping with a zoned internal", KeyNATExternalIPs, "203.0.113.10/fe80::1%eth0"},
		{"blacklist not a list", KeyExtraIFaceBlackList, 42},
	}
	if runtime.GOOS == "darwin" {
		tests = append(tests, struct {
			name  string
			key   string
			value any
		}{"interface name not utun on macOS", KeyInterfaceName, "nbmdm"})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := NewPolicy(map[string]any{tc.key: tc.value, KeyBlockInbound: true})

			assert.False(t, policy.HasKey(tc.key), "an unusable value must not leave %s managed", tc.key)
			assert.True(t, policy.HasKey(KeyBlockInbound), "the other keys must survive")
			assert.Empty(t, ResolveConflicts(policy, []ConflictCheck{ConflictInt64(KeyMTU, ptr(int64(1400)))}),
				"the user's own value must not be refused")
		})
	}
}

func TestUsableTuningValueStaysManaged(t *testing.T) {
	policy := NewPolicy(map[string]any{
		KeyMTU:              int64(1400),
		KeyWireguardPort:    int64(51821),
		KeySSHJWTCacheTTL:   int64(0),
		KeyDNSRouteInterval: "90s",
		KeyNATExternalIPs:   "203.0.113.10,203.0.113.11/10.0.0.5,203.0.113.12/eth0",
	})

	for _, key := range []string{KeyMTU, KeyWireguardPort, KeySSHJWTCacheTTL, KeyDNSRouteInterval, KeyNATExternalIPs} {
		assert.Equal(t, managedHere(key), policy.HasKey(key), "%s holds a usable value and must stay managed", key)
	}
}

// managedHere reports whether a usable value for key stays managed on this
// platform: iOS and tvOS drop every mtu, since the app fixes the tunnel MTU.
func managedHere(key string) bool {
	return key != KeyMTU || runtime.GOOS != "ios"
}

// A security boolean the client cannot read is locked to its restrictive
// value: leaving it to the user could open what the policy was there to close.
func TestUnreadableSecurityBooleanFailsClosed(t *testing.T) {
	policy := NewPolicy(map[string]any{
		KeyBlockInbound:   "maybe",
		KeyEnableSSHRoot:  "often",
		KeyAllowServerSSH: []string{"true"},
		KeyAllowServerVNC: "sometimes",
	})

	want := map[string]bool{
		KeyBlockInbound:   true,
		KeyEnableSSHRoot:  false,
		KeyAllowServerSSH: false,
		KeyAllowServerVNC: false,
	}
	for key, restrictive := range want {
		got, ok := policy.GetBool(key)
		require.True(t, ok, "an unreadable %s must stay managed", key)
		assert.Equal(t, restrictive, got, "an unreadable %s must enforce its restrictive value", key)
	}
}

// Any other boolean the client cannot read is dropped like an unusable tuning
// value: there is no safe side to pick, so the user keeps control.
func TestUnreadableBooleanLeavesSettingToUser(t *testing.T) {
	policy := NewPolicy(map[string]any{
		KeyDisableDNS:  "perhaps",
		KeyForceRelay:  "maybe",
		KeyDisableIPv6: true,
	})

	for _, key := range []string{KeyDisableDNS, KeyForceRelay} {
		assert.False(t, policy.HasKey(key), "an unreadable %s must not stay managed", key)
	}
	assert.True(t, policy.HasKey(KeyDisableIPv6), "a readable boolean must stay managed")
}

func TestSecurityBoolFallbacksAreBoolKeys(t *testing.T) {
	for key := range securityBoolFallbacks {
		assert.Contains(t, boolKeys, key, "%s needs to be read as a boolean to fail closed", key)
	}
}

func TestBoolKeysAreNotTuningKeys(t *testing.T) {
	for _, key := range boolKeys {
		_, tuning := valueChecks[key]
		assert.False(t, tuning, "%s cannot be both a boolean and a tuning key", key)
	}
}

func ptr[T any](v T) *T { return &v }
