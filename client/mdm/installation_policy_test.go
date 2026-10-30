package mdm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/instance"
)

type splitFetcher struct {
	global map[string]any
	own    map[instance.Name]map[string]any
}

func (f splitFetcher) Fetch() map[string]any { return f.global }

func (f splitFetcher) FetchInstallation(name instance.Name) map[string]any { return f.own[name] }

func useInstallation(t *testing.T, name string) {
	t.Helper()
	inst, err := instance.ForPlatform("windows", name)
	require.NoError(t, err)
	instance.SetCurrent(inst)
	t.Cleanup(func() { instance.SetCurrent(instance.Default()) })
}

var machinePolicy = map[string]any{
	KeyManagementURL:             "https://vpn.globex.example:443",
	KeyPreSharedKey:              "secret",
	KeyWireguardPort:             int64(51820),
	KeyEnableLocalMetrics:        true,
	KeyLocalMetricsAddress:       "127.0.0.1:9191",
	KeyBlockInbound:              true,
	KeyDisableProfiles:           true,
	KeyAllowServerSSH:            false,
	KeyDisableNamedInstallations: false,
}

// T-POL-U1: a named installation takes the machine's posture values, not its
// network identity, and its own key overrides.
func TestNamedInstallationPolicy(t *testing.T) {
	useInstallation(t, "acme")
	f := splitFetcher{global: machinePolicy, own: map[instance.Name]map[string]any{
		"acme": {
			KeyManagementURL:             "https://vpn.acme.example:443",
			KeyBlockInbound:              false,
			KeyDisableNamedInstallations: false,
		},
	}}

	p := NewLoader(f).Load()

	url, ok := p.GetString(KeyManagementURL)
	assert.True(t, ok, "own managementURL applies")
	assert.Equal(t, "https://vpn.acme.example:443", url, "own managementURL")
	for _, k := range []string{KeyPreSharedKey, KeyWireguardPort, KeyEnableLocalMetrics, KeyLocalMetricsAddress} {
		assert.False(t, p.HasKey(k), "machine-wide %s must not reach a named installation", k)
	}
	blocked, _ := p.GetBool(KeyBlockInbound)
	assert.False(t, blocked, "own blockInbound overrides")
	assert.True(t, p.HasKey(KeyDisableProfiles), "machine posture applies")
	assert.True(t, p.HasKey(KeyDisableNamedInstallations), "machine-only value stays")
}

func TestNamedInstallationWithoutOwnPolicy(t *testing.T) {
	useInstallation(t, "work")
	p := NewLoader(splitFetcher{global: machinePolicy}).Load()

	assert.False(t, p.HasKey(KeyManagementURL), "no managementURL")
	blocked, ok := p.GetBool(KeyBlockInbound)
	assert.True(t, ok && blocked, "machine blockInbound applies")
}

func TestDefaultInstallationPolicyUnchanged(t *testing.T) {
	f := splitFetcher{global: machinePolicy, own: map[instance.Name]map[string]any{
		"acme": {KeyBlockInbound: false},
	}}
	p := NewLoader(f).Load()
	assert.ElementsMatch(t, sortedKeys(machinePolicy), p.ManagedKeys(), "the default installation sees the machine policy as is")
}

// SBS-POL-04: the machine policy forbids named installations, and an
// installation's own key cannot lift it.
func TestNamedInstallationsDisabled(t *testing.T) {
	useInstallation(t, "acme")
	f := splitFetcher{
		global: map[string]any{KeyDisableNamedInstallations: int64(1)},
		own:    map[instance.Name]map[string]any{"acme": {KeyDisableNamedInstallations: int64(0)}},
	}
	assert.True(t, NewLoader(f).Load().NamedInstallationsDisabled(), "machine value wins")

	f.global = map[string]any{KeyDisableNamedInstallations: "garbage"}
	assert.True(t, NewLoader(f).Load().NamedInstallationsDisabled(), "unparseable value forbids")

	assert.False(t, NewLoader(splitFetcher{}).Load().NamedInstallationsDisabled(), "absent value allows")
}
