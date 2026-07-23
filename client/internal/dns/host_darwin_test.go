//go:build !ios

package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testInterfaceName = "utun999"

// generateShortDomains generates domains like a.com, b.com, ..., aa.com, ab.com, etc.
func generateShortDomains(count int) []string {
	domains := make([]string, 0, count)
	for i := range count {
		label := ""
		n := i
		for {
			label = string(rune('a'+n%26)) + label
			n = n/26 - 1
			if n < 0 {
				break
			}
		}
		domains = append(domains, label+".com")
	}
	return domains
}

// generateLongDomains generates domains like subdomain-000.department.organization-name.example.com
func generateLongDomains(count int) []string {
	domains := make([]string, 0, count)
	for i := range count {
		domains = append(domains, fmt.Sprintf("subdomain-%03d.department.organization-name.example.com", i))
	}
	return domains
}

func TestSplitDomainsIntoBatches(t *testing.T) {
	tests := []struct {
		name            string
		domains         []string
		expectedCount   int
		checkAllPresent bool
	}{
		{
			name:          "empty",
			domains:       nil,
			expectedCount: 0,
		},
		{
			name:            "under_limit",
			domains:         generateShortDomains(10),
			expectedCount:   1,
			checkAllPresent: true,
		},
		{
			name:            "at_element_limit",
			domains:         generateShortDomains(50),
			expectedCount:   1,
			checkAllPresent: true,
		},
		{
			name:            "over_element_limit",
			domains:         generateShortDomains(51),
			expectedCount:   2,
			checkAllPresent: true,
		},
		{
			name:            "triple_element_limit",
			domains:         generateShortDomains(150),
			expectedCount:   3,
			checkAllPresent: true,
		},
		{
			name:            "long_domains_hit_byte_limit",
			domains:         generateLongDomains(50),
			checkAllPresent: true,
		},
		{
			name:            "500_short_domains",
			domains:         generateShortDomains(500),
			expectedCount:   10,
			checkAllPresent: true,
		},
		{
			name:            "500_long_domains",
			domains:         generateLongDomains(500),
			checkAllPresent: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			batches := splitDomainsIntoBatches(tc.domains)

			if tc.expectedCount > 0 {
				assert.Len(t, batches, tc.expectedCount, "expected %d batches", tc.expectedCount)
			}

			// Verify each batch respects limits
			for i, batch := range batches {
				assert.LessOrEqual(t, len(batch), maxDomainsPerResolverEntry,
					"batch %d exceeds element limit", i)

				totalBytes := 0
				for j, d := range batch {
					if j > 0 {
						totalBytes++
					}
					totalBytes += len(d)
				}
				assert.LessOrEqual(t, totalBytes, maxDomainBytesPerResolverEntry,
					"batch %d exceeds byte limit (%d bytes)", i, totalBytes)
			}

			if tc.checkAllPresent {
				var all []string
				for _, batch := range batches {
					all = append(all, batch...)
				}
				assert.Equal(t, tc.domains, all, "all domains should be present in order")
			}
		})
	}
}

func TestGetOriginalNameservers(t *testing.T) {
	configurator := &systemConfigurator{
		createdKeys:   make(map[string]struct{}),
		interfaceName: testInterfaceName,
		origNameservers: []netip.Addr{
			netip.MustParseAddr("8.8.8.8"),
			netip.MustParseAddr("1.1.1.1"),
		},
	}

	servers := configurator.getOriginalNameservers()
	assert.Len(t, servers, 2)
	assert.Equal(t, netip.MustParseAddr("8.8.8.8"), servers[0])
	assert.Equal(t, netip.MustParseAddr("1.1.1.1"), servers[1])
}

// TestGetOriginalNameserversFromSystem uses a read-only "show" call and never mutates host DNS state,
// so it stays untagged rather than in the privileged suite.
func TestGetOriginalNameserversFromSystem(t *testing.T) {
	configurator := &systemConfigurator{
		createdKeys:   make(map[string]struct{}),
		interfaceName: testInterfaceName,
	}

	_, err := configurator.getSystemDNSSettings()
	require.NoError(t, err)

	servers := configurator.getOriginalNameservers()

	require.NotEmpty(t, servers, "expected at least one DNS server from system configuration")

	for _, server := range servers {
		assert.True(t, server.IsValid(), "server address should be valid")
		assert.False(t, server.IsUnspecified(), "server address should not be unspecified")
	}

	t.Logf("found %d original nameservers: %v", len(servers), servers)
}

func TestGetKeyWithInput(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		iface    string
		key      string
		expected string
	}{
		{
			name:     "search key",
			format:   netbirdDNSStateKeyFormat,
			iface:    "utun0",
			key:      searchSuffix,
			expected: "State:/Network/Service/NetBird-utun0-Search/DNS",
		},
		{
			name:     "match key",
			format:   netbirdDNSStateKeyFormat,
			iface:    "utun0",
			key:      matchSuffix,
			expected: "State:/Network/Service/NetBird-utun0-Match/DNS",
		},
		{
			name:     "local key",
			format:   netbirdDNSStateKeyFormat,
			iface:    "utun0",
			key:      localSuffix,
			expected: "State:/Network/Service/NetBird-utun0-Local/DNS",
		},
		{
			name:     "different interface",
			format:   netbirdDNSStateKeyFormat,
			iface:    "utun100",
			key:      searchSuffix,
			expected: "State:/Network/Service/NetBird-utun100-Search/DNS",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := getKeyWithInput(tc.format, tc.iface, tc.key)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestNewHostManagerWithInterfaceName(t *testing.T) {
	manager, err := newHostManager("utun42")
	require.NoError(t, err)
	assert.Equal(t, "utun42", manager.interfaceName)
	assert.NotNil(t, manager.createdKeys)
}

func TestNewHostManagerWithEmptyInterfaceName(t *testing.T) {
	manager, err := newHostManager("")
	require.Error(t, err)
	assert.Nil(t, manager)
	assert.Contains(t, err.Error(), "interfaceName must not be empty")
}

func TestMultipleInterfacesGenerateDifferentKeys(t *testing.T) {
	iface1 := "utun0"
	iface2 := "utun1"

	for _, suffix := range []string{searchSuffix, matchSuffix, localSuffix} {
		key1 := getKeyWithInput(netbirdDNSStateKeyFormat, iface1, suffix)
		key2 := getKeyWithInput(netbirdDNSStateKeyFormat, iface2, suffix)
		assert.NotEqual(t, key1, key2, "keys for different interfaces should differ (suffix=%s)", suffix)
		assert.Contains(t, key1, iface1)
		assert.Contains(t, key2, iface2)
	}

	key1 := fmt.Sprintf(netbirdDNSStateKeyIndexedFormat, iface1, matchSuffix, 0)
	key2 := fmt.Sprintf(netbirdDNSStateKeyIndexedFormat, iface2, matchSuffix, 0)
	assert.NotEqual(t, key1, key2)
	assert.Contains(t, key1, iface1)
	assert.Contains(t, key2, iface2)
}

func TestShutdownStateIncludesInterfaceName(t *testing.T) {
	state := &ShutdownState{
		InterfaceName: "utun42",
		CreatedKeys:   []string{"key1", "key2"},
	}
	assert.Equal(t, "utun42", state.InterfaceName)
	assert.Equal(t, "dns_state", state.Name())
}

func TestPrimaryServiceKeyFormatNotAffected(t *testing.T) {
	// primaryServiceStateKeyFormat has only one %s placeholder for the service UUID.
	// It must NOT be called with getKeyWithInput (which expects iface + key).
	serviceUUID := "12345678-ABCD-1234-ABCD-123456789ABC"
	result := fmt.Sprintf(primaryServiceStateKeyFormat, serviceUUID)
	assert.Equal(t, "State:/Network/Service/12345678-ABCD-1234-ABCD-123456789ABC/DNS", result)
}

// TestDiscoverExistingKeysEmptyInterface short-circuits before any system configuration lookup.
func TestDiscoverExistingKeysEmptyInterface(t *testing.T) {
	cfg := &systemConfigurator{createdKeys: make(map[string]struct{})}
	keys, err := cfg.discoverExistingKeys()
	require.NoError(t, err)
	assert.Empty(t, keys, "scoped discovery must return none for an empty interface name")
}

func TestDiscoverExistingKeysEmptySystemList(t *testing.T) {
	setScutilPath(t, "/usr/bin/true")

	cfg := &systemConfigurator{createdKeys: make(map[string]struct{}), interfaceName: testInterfaceName}
	keys, err := cfg.discoverExistingKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestShutdownStateCleanupPreservesStateOnDiscoveryErrors(t *testing.T) {
	setScutilPath(t, filepath.Join(t.TempDir(), "missing-scutil"))

	tests := []struct {
		name  string
		state ShutdownState
		want  string
	}{
		{
			name:  "scoped discovery",
			state: ShutdownState{InterfaceName: testInterfaceName},
			want:  "discover removable DNS keys",
		},
		{
			name:  "legacy discovery",
			state: ShutdownState{},
			want:  "discover legacy DNS keys",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manager := statemanager.New(filepath.Join(t.TempDir(), "state.json"))
			manager.RegisterState(&ShutdownState{})
			require.NoError(t, manager.UpdateState(&tc.state))
			require.NoError(t, manager.PersistState(context.Background()))

			err := manager.CleanupStateByName(tc.state.Name())
			require.Error(t, err)
			assert.ErrorContains(t, err, tc.want)
			assert.Equal(t, &tc.state, manager.GetState(&ShutdownState{}))
		})
	}
}

func setScutilPath(t *testing.T, path string) {
	t.Helper()
	original := scutilPath
	scutilPath = path
	t.Cleanup(func() { scutilPath = original })
}

func TestIndexedScopedKeysFromListSparse(t *testing.T) {
	dnsKeys := "  subKey [0] = State:/Network/Service/NetBird-utun999-Match-0/DNS\n" +
		"  subKey [1] = State:/Network/Service/NetBird-utun999-Match-2/DNS\n" +
		"  subKey [2] = State:/Network/Service/NetBird-utun999-Search-1/DNS\n"

	assert.Equal(t, []string{
		"State:/Network/Service/NetBird-utun999-Search-1/DNS",
		"State:/Network/Service/NetBird-utun999-Match-0/DNS",
		"State:/Network/Service/NetBird-utun999-Match-2/DNS",
	}, scopedKeysFromList(dnsKeys, testInterfaceName))
}

func TestScopedKeysFromListIsolation(t *testing.T) {
	dnsKeys := "  subKey [0] = State:/Network/Service/NetBird-utun999-Search/DNS\n" +
		"  subKey [1] = State:/Network/Service/NetBird-utun999-Match/DNS\n" +
		"  subKey [2] = State:/Network/Service/NetBird-utun999-Local/DNS\n" +
		"  subKey [3] = State:/Network/Service/NetBird-utun999-Match-0/DNS\n" +
		"  subKey [4] = State:/Network/Service/NetBird-Match/DNS\n" +
		"  subKey [5] = State:/Network/Service/NetBird-Match-0/DNS\n" +
		"  subKey [6] = State:/Network/Service/NetBird-utun1-Match-0/DNS\n"

	assert.Equal(t, []string{
		"State:/Network/Service/NetBird-utun999-Search/DNS",
		"State:/Network/Service/NetBird-utun999-Match/DNS",
		"State:/Network/Service/NetBird-utun999-Local/DNS",
		"State:/Network/Service/NetBird-utun999-Match-0/DNS",
	}, scopedKeysFromList(dnsKeys, testInterfaceName))
}

func TestPersistShutdownStatePreservesKeys(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "state.json")
	stateManager := statemanager.New(stateFile)
	stateManager.RegisterState(&ShutdownState{})
	configurator := &systemConfigurator{
		createdKeys: map[string]struct{}{
			"k1": {},
			"k2": {},
		},
		interfaceName: testInterfaceName,
	}

	require.NoError(t, configurator.persistShutdownState(stateManager))

	loadedStateManager := statemanager.New(stateFile)
	loadedStateManager.RegisterState(&ShutdownState{})
	require.NoError(t, loadedStateManager.LoadState(&ShutdownState{}))
	state, ok := loadedStateManager.GetState(&ShutdownState{}).(*ShutdownState)
	require.True(t, ok)
	assert.Equal(t, testInterfaceName, state.InterfaceName)
	assert.ElementsMatch(t, []string{"k1", "k2"}, state.CreatedKeys)
}

func TestShutdownStateUnmarshalLegacyJSON(t *testing.T) {
	tests := []struct {
		name              string
		json              string
		expectedIface     string
		expectedKeys      []string
		expectedKeysCount int
	}{
		{
			name:              "legacy format (PascalCase, no interface)",
			json:              `{"CreatedKeys":["State:/Network/Service/NetBird-Match/DNS","State:/Network/Service/NetBird-Search/DNS"]}`,
			expectedIface:     "",
			expectedKeys:      []string{"State:/Network/Service/NetBird-Match/DNS", "State:/Network/Service/NetBird-Search/DNS"},
			expectedKeysCount: 2,
		},
		{
			name:              "intermediate format (snake_case, with interface)",
			json:              `{"interface_name":"utun0","created_keys":["State:/Network/Service/NetBird-utun0-Match-0/DNS"]}`,
			expectedIface:     "utun0",
			expectedKeys:      []string{"State:/Network/Service/NetBird-utun0-Match-0/DNS"},
			expectedKeysCount: 1,
		},
		{
			name:              "empty legacy state",
			json:              `{}`,
			expectedIface:     "",
			expectedKeysCount: 0,
		},
		{
			name:              "legacy with empty keys",
			json:              `{"CreatedKeys":[]}`,
			expectedIface:     "",
			expectedKeysCount: 0,
		},
		{
			name:              "mixed fields: canonical PascalCase wins when populated",
			json:              `{"interface_name":"utun0","created_keys":["new-key"],"CreatedKeys":["old-key"]}`,
			expectedIface:     "utun0",
			expectedKeys:      []string{"old-key"},
			expectedKeysCount: 1,
		},
		{
			name:              "mixed fields: canonical wins even when explicitly empty",
			json:              `{"created_keys":["snake-key"],"CreatedKeys":[]}`,
			expectedIface:     "",
			expectedKeys:      []string{},
			expectedKeysCount: 0,
		},
		{
			name:              "mixed fields: canonical wins even when explicitly null",
			json:              `{"created_keys":["snake-key"],"CreatedKeys":null}`,
			expectedIface:     "",
			expectedKeys:      nil,
			expectedKeysCount: 0,
		},
		{
			name:              "snake_case fills in only when canonical is absent",
			json:              `{"created_keys":["old-key"]}`,
			expectedIface:     "",
			expectedKeys:      []string{"old-key"},
			expectedKeysCount: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var state ShutdownState
			err := json.Unmarshal([]byte(tc.json), &state)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedIface, state.InterfaceName)
			assert.Len(t, state.CreatedKeys, tc.expectedKeysCount)
			if tc.expectedKeys != nil {
				assert.Equal(t, tc.expectedKeys, state.CreatedKeys)
			}
		})
	}
}

func TestShutdownStateMarshalDowngradeCompat(t *testing.T) {
	state := &ShutdownState{
		InterfaceName: "utun0",
		CreatedKeys:   []string{"key1", "key2"},
	}
	data, err := json.Marshal(state)
	require.NoError(t, err)

	var legacy struct {
		CreatedKeys []string
	}
	require.NoError(t, json.Unmarshal(data, &legacy))
	assert.Equal(t, state.CreatedKeys, legacy.CreatedKeys)
}

func TestShutdownStateUnmarshalIntermediateSnakeCase(t *testing.T) {
	data := []byte(`{"created_keys":["key1"],"interface_name":"utun0"}`)
	var state ShutdownState
	require.NoError(t, json.Unmarshal(data, &state))
	assert.Equal(t, "utun0", state.InterfaceName)
	assert.Equal(t, []string{"key1"}, state.CreatedKeys)
}

func TestPersistenceRoundTrip(t *testing.T) {
	state := &ShutdownState{
		InterfaceName: "utun0",
		CreatedKeys:   []string{"key1", "key2", "key3"},
	}
	data, err := json.Marshal(state)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"CreatedKeys"`, "marshaled JSON must use the canonical PascalCase field name")

	var got ShutdownState
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, state.InterfaceName, got.InterfaceName)
	assert.Equal(t, state.CreatedKeys, got.CreatedKeys)
}

func TestShutdownStateUnmarshalMalformed(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"invalid syntax", `{"CreatedKeys":`},
		{"wrong type for CreatedKeys", `{"CreatedKeys":"not-an-array"}`},
		{"wrong type for interface_name", `{"interface_name":123}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var state ShutdownState
			err := json.Unmarshal([]byte(tc.json), &state)
			assert.Error(t, err)
		})
	}
}

func TestIsScutilFailure(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		stderr string
		want   bool
	}{
		{name: "permission denied despite exit 0", stdout: "Permission denied\n", want: true},
		{name: "permission denied on stderr", stderr: "Permission denied\n", want: true},
		{name: "permission denied with period", stdout: "Permission denied.\n", want: true},
		{name: "permission denied, different case", stdout: "permission DENIED\n", want: true},
		{name: "permission denied with surrounding whitespace", stdout: "  Permission denied  \n", want: true},
		{name: "could not open configuration daemon", stderr: "Could not open configuration daemon socket\n", want: true},
		{name: "operation not permitted", stdout: "Operation not permitted\n", want: true},
		{name: "no such key is not a failure", stdout: "No such key\n", want: false},
		{name: "empty output is not a failure", want: false},
		{name: "normal show output is not a failure", stdout: "<dictionary> {\n  ServerAddresses : <array> {\n    0 : 100.64.0.1\n  }\n}\n", want: false},
		{name: "normal list output is not a failure", stdout: "  subKey [0] = State:/Network/Service/NetBird-utun0-Match/DNS\n", want: false},
		{name: "domain containing 'permission' is not a failure", stdout: "SupplementalMatchDomains : <array> {\n  0 : permission-test.example.com\n}\n", want: false},
		{name: "domain containing 'denied' is not a failure", stdout: "SupplementalMatchDomains : <array> {\n  0 : access-denied.example.com\n}\n", want: false},
		{name: "key name containing 'permission' is not a failure", stdout: "  subKey [0] = State:/Network/Service/NetBird-permission-test/DNS\n", want: false},
		{name: "sentence mentioning permission without matching the exact line is not a failure", stdout: "User lacks permission to view this, but the command still ran.\n", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isScutilFailure([]byte(tc.stdout), []byte(tc.stderr)))
		})
	}
}
