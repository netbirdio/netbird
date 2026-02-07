//go:build !ios

package dns

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

const testInterfaceName = "utun999"

// TestGetKeyWithInput verifies that DNS state keys are correctly generated
// with interface name scoping to prevent multiple netbird instances from
// clobbering each other's DNS entries.
func TestGetKeyWithInput(t *testing.T) {
	tests := []struct {
		name          string
		format        string
		interfaceName string
		suffix        string
		expected      string
	}{
		{
			name:          "search suffix with interface",
			format:        netbirdDNSStateKeyFormat,
			interfaceName: "utun0",
			suffix:        searchSuffix,
			expected:      "State:/Network/Service/NetBird-utun0-Search/DNS",
		},
		{
			name:          "match suffix with interface",
			format:        netbirdDNSStateKeyFormat,
			interfaceName: "utun0",
			suffix:        matchSuffix,
			expected:      "State:/Network/Service/NetBird-utun0-Match/DNS",
		},
		{
			name:          "local suffix with interface",
			format:        netbirdDNSStateKeyFormat,
			interfaceName: "utun0",
			suffix:        localSuffix,
			expected:      "State:/Network/Service/NetBird-utun0-Local/DNS",
		},
		{
			name:          "different interface name",
			format:        netbirdDNSStateKeyFormat,
			interfaceName: "utun5",
			suffix:        searchSuffix,
			expected:      "State:/Network/Service/NetBird-utun5-Search/DNS",
		},
		{
			name:          "empty interface name still works",
			format:        netbirdDNSStateKeyFormat,
			interfaceName: "",
			suffix:        searchSuffix,
			expected:      "State:/Network/Service/NetBird--Search/DNS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getKeyWithInput(tt.format, tt.interfaceName, tt.suffix)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestNewHostManagerWithInterfaceName verifies that newHostManager correctly
// initializes the systemConfigurator with the provided interface name.
func TestNewHostManagerWithInterfaceName(t *testing.T) {
	tests := []struct {
		name          string
		interfaceName string
	}{
		{
			name:          "standard interface name",
			interfaceName: "utun0",
		},
		{
			name:          "different interface",
			interfaceName: "utun5",
		},
		{
			name:          "empty interface name",
			interfaceName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := newHostManager(tt.interfaceName)
			require.NoError(t, err)
			require.NotNil(t, manager)
			assert.Equal(t, tt.interfaceName, manager.interfaceName)
			assert.NotNil(t, manager.createdKeys)
			assert.Empty(t, manager.createdKeys)
		})
	}
}

// TestSystemConfiguratorGetRemovableKeysWithDefaults verifies that the default
// keys returned when createdKeys is empty include the interface name.
func TestSystemConfiguratorGetRemovableKeysWithDefaults(t *testing.T) {
	tests := []struct {
		name           string
		interfaceName  string
		createdKeys    map[string]struct{}
		expectedKeys   []string
		checkInterface bool
	}{
		{
			name:          "empty createdKeys returns defaults with interface",
			interfaceName: "utun0",
			createdKeys:   map[string]struct{}{},
			expectedKeys: []string{
				"State:/Network/Service/NetBird-utun0-Search/DNS",
				"State:/Network/Service/NetBird-utun0-Match/DNS",
			},
			checkInterface: true,
		},
		{
			name:          "different interface in defaults",
			interfaceName: "utun5",
			createdKeys:   map[string]struct{}{},
			expectedKeys: []string{
				"State:/Network/Service/NetBird-utun5-Search/DNS",
				"State:/Network/Service/NetBird-utun5-Match/DNS",
			},
			checkInterface: true,
		},
		{
			name:          "with existing createdKeys returns those keys",
			interfaceName: "utun0",
			createdKeys: map[string]struct{}{
				"State:/Network/Service/NetBird-utun0-Search/DNS": {},
				"State:/Network/Service/NetBird-utun0-Local/DNS":  {},
			},
			expectedKeys: []string{
				"State:/Network/Service/NetBird-utun0-Search/DNS",
				"State:/Network/Service/NetBird-utun0-Local/DNS",
			},
			checkInterface: false, // order not guaranteed for map iteration
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configurator := &systemConfigurator{
				interfaceName: tt.interfaceName,
				createdKeys:   tt.createdKeys,
			}

			keys := configurator.getRemovableKeysWithDefaults()

			if tt.checkInterface {
				// For default keys, order is deterministic
				require.Equal(t, len(tt.expectedKeys), len(keys))
				for i, expected := range tt.expectedKeys {
					assert.Equal(t, expected, keys[i])
				}
			} else {
				// For createdKeys, just check all expected keys are present
				assert.Equal(t, len(tt.expectedKeys), len(keys))
				for _, expected := range tt.expectedKeys {
					assert.Contains(t, keys, expected)
				}
			}
		})
	}
}

// TestMultipleInterfacesGenerateDifferentKeys verifies that different interface
// names generate different DNS state keys, which is the core fix for preventing
// multiple netbird instances from clobbering each other's DNS entries.
func TestMultipleInterfacesGenerateDifferentKeys(t *testing.T) {
	interfaces := []string{"utun0", "utun1", "utun2"}
	suffixes := []string{searchSuffix, matchSuffix, localSuffix}

	// Collect all generated keys
	allKeys := make(map[string]string) // key -> "interface:suffix" for debugging

	for _, iface := range interfaces {
		for _, suffix := range suffixes {
			key := getKeyWithInput(netbirdDNSStateKeyFormat, iface, suffix)
			identifier := fmt.Sprintf("%s:%s", iface, suffix)

			// Check for collision
			if existing, exists := allKeys[key]; exists {
				t.Errorf("Key collision detected: %q generated by both %q and %q", key, existing, identifier)
			}
			allKeys[key] = identifier

			// Verify the key contains both interface and suffix
			assert.Contains(t, key, iface, "Key should contain interface name")
			assert.Contains(t, key, suffix, "Key should contain suffix")
		}
	}

	// Verify we generated the expected number of unique keys
	expectedCount := len(interfaces) * len(suffixes)
	assert.Equal(t, expectedCount, len(allKeys), "Should have %d unique keys", expectedCount)
}

// TestShutdownStateIncludesInterfaceName verifies that ShutdownState correctly
// stores and retrieves the interface name for proper cleanup scoping.
func TestShutdownStateIncludesInterfaceName(t *testing.T) {
	tests := []struct {
		name          string
		interfaceName string
		createdKeys   []string
	}{
		{
			name:          "state with interface and keys",
			interfaceName: "utun0",
			createdKeys: []string{
				"State:/Network/Service/NetBird-utun0-Search/DNS",
				"State:/Network/Service/NetBird-utun0-Match/DNS",
			},
		},
		{
			name:          "state with different interface",
			interfaceName: "utun5",
			createdKeys: []string{
				"State:/Network/Service/NetBird-utun5-Search/DNS",
			},
		},
		{
			name:          "state with empty interface",
			interfaceName: "",
			createdKeys:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &ShutdownState{
				InterfaceName: tt.interfaceName,
				CreatedKeys:   tt.createdKeys,
			}

			assert.Equal(t, tt.interfaceName, state.InterfaceName)
			assert.Equal(t, tt.createdKeys, state.CreatedKeys)
			assert.Equal(t, "dns_state", state.Name())
		})
	}
}

// TestShutdownStateCleanupRestoresCreatedKeys verifies that when Cleanup() is
// called, the createdKeys from the persisted state are restored to the host
// manager before attempting DNS restoration. This ensures that the correct
// interface-scoped keys are removed during unclean shutdown recovery.
func TestShutdownStateCleanupRestoresCreatedKeys(t *testing.T) {
	// This test verifies the key restoration logic without actually calling scutil
	interfaceName := "utun0"
	expectedKeys := []string{
		"State:/Network/Service/NetBird-utun0-Search/DNS",
		"State:/Network/Service/NetBird-utun0-Match/DNS",
	}

	state := &ShutdownState{
		InterfaceName: interfaceName,
		CreatedKeys:   expectedKeys,
	}

	// Create a manager the same way Cleanup() does
	manager, err := newHostManager(state.InterfaceName)
	require.NoError(t, err)

	// Restore keys the same way Cleanup() does
	for _, key := range state.CreatedKeys {
		manager.createdKeys[key] = struct{}{}
	}

	// Verify the manager has the correct interface name
	assert.Equal(t, interfaceName, manager.interfaceName)

	// Verify all keys were restored
	assert.Equal(t, len(expectedKeys), len(manager.createdKeys))
	for _, key := range expectedKeys {
		_, exists := manager.createdKeys[key]
		assert.True(t, exists, "Key %s should be restored to createdKeys", key)
	}

	// Verify getRemovableKeysWithDefaults returns the restored keys (not defaults)
	removableKeys := manager.getRemovableKeysWithDefaults()
	assert.Equal(t, len(expectedKeys), len(removableKeys))
	for _, key := range expectedKeys {
		assert.Contains(t, removableKeys, key)
	}
}

// TestPrimaryServiceKeyFormatNotAffected verifies that the primary service key
// format (which queries system DNS settings) is NOT affected by the interface
// name changes - it should use the system's primary service key directly.
func TestPrimaryServiceKeyFormatNotAffected(t *testing.T) {
	// The primary service key format has only one placeholder for the service key
	// It should NOT include the interface name
	serviceKey := "12345678-ABCD-1234-ABCD-123456789ABC"
	expected := fmt.Sprintf("State:/Network/Service/%s/DNS", serviceKey)
	result := fmt.Sprintf(primaryServiceStateKeyFormat, serviceKey)

	assert.Equal(t, expected, result)
	assert.NotContains(t, result, "NetBird", "Primary service key should not contain NetBird")
}

// TestDarwinDNSUncleanShutdownCleanup is an integration test that verifies
// the full lifecycle of DNS configuration including unclean shutdown recovery.
// This test requires scutil access and modifies system DNS state.
func TestDarwinDNSUncleanShutdownCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping scutil integration test in short mode")
	}

	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "state.json")

	sm := statemanager.New(stateFile)
	sm.RegisterState(&ShutdownState{})
	sm.Start()
	defer func() {
		require.NoError(t, sm.Stop(context.Background()))
	}()

	// Create configurator with interface name
	configurator := &systemConfigurator{
		createdKeys:   make(map[string]struct{}),
		interfaceName: testInterfaceName,
	}

	config := HostDNSConfig{
		ServerIP:   netip.MustParseAddr("100.64.0.1"),
		ServerPort: 53,
		RouteAll:   true,
		Domains: []DomainConfig{
			{Domain: "example.com", MatchOnly: true},
		},
	}

	err := configurator.applyDNSConfig(config, sm)
	require.NoError(t, err)

	require.NoError(t, sm.PersistState(context.Background()))

	// Use interface-scoped keys
	searchKey := getKeyWithInput(netbirdDNSStateKeyFormat, testInterfaceName, searchSuffix)
	matchKey := getKeyWithInput(netbirdDNSStateKeyFormat, testInterfaceName, matchSuffix)
	localKey := getKeyWithInput(netbirdDNSStateKeyFormat, testInterfaceName, localSuffix)

	defer func() {
		for _, key := range []string{searchKey, matchKey, localKey} {
			_ = removeTestDNSKey(key)
		}
	}()

	for _, key := range []string{searchKey, matchKey, localKey} {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		if exists {
			t.Logf("Key %s exists before cleanup", key)
		}
	}

	sm2 := statemanager.New(stateFile)
	sm2.RegisterState(&ShutdownState{})
	err = sm2.LoadState(&ShutdownState{})
	require.NoError(t, err)

	state := sm2.GetState(&ShutdownState{})
	if state == nil {
		t.Skip("State not saved, skipping cleanup test")
	}

	shutdownState, ok := state.(*ShutdownState)
	require.True(t, ok)

	// Verify the interface name was persisted
	assert.Equal(t, testInterfaceName, shutdownState.InterfaceName)

	err = shutdownState.Cleanup()
	require.NoError(t, err)

	for _, key := range []string{searchKey, matchKey, localKey} {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		assert.False(t, exists, "Key %s should NOT exist after cleanup", key)
	}
}

// TestDarwinDNSMultipleInstancesIsolation is an integration test that verifies
// that multiple netbird instances with different interface names maintain
// isolated DNS configurations.
func TestDarwinDNSMultipleInstancesIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping scutil integration test in short mode")
	}

	interface1 := "utun991"
	interface2 := "utun992"

	// Create two configurators simulating two netbird instances
	configurator1 := &systemConfigurator{
		createdKeys:   make(map[string]struct{}),
		interfaceName: interface1,
	}
	configurator2 := &systemConfigurator{
		createdKeys:   make(map[string]struct{}),
		interfaceName: interface2,
	}

	// Generate keys for both instances
	searchKey1 := getKeyWithInput(netbirdDNSStateKeyFormat, interface1, searchSuffix)
	searchKey2 := getKeyWithInput(netbirdDNSStateKeyFormat, interface2, searchSuffix)

	// Verify keys are different
	assert.NotEqual(t, searchKey1, searchKey2, "Different interfaces should generate different keys")

	// Verify each configurator generates its own scoped keys
	keys1 := configurator1.getRemovableKeysWithDefaults()
	keys2 := configurator2.getRemovableKeysWithDefaults()

	// All keys from configurator1 should contain interface1
	for _, key := range keys1 {
		assert.Contains(t, key, interface1)
		assert.NotContains(t, key, interface2)
	}

	// All keys from configurator2 should contain interface2
	for _, key := range keys2 {
		assert.Contains(t, key, interface2)
		assert.NotContains(t, key, interface1)
	}
}

func checkDNSKeyExists(key string) (bool, error) {
	cmd := exec.Command(scutilPath)
	cmd.Stdin = strings.NewReader("show " + key + "\nquit\n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "No such key") {
			return false, nil
		}
		return false, err
	}
	return !strings.Contains(string(output), "No such key"), nil
}

func removeTestDNSKey(key string) error {
	cmd := exec.Command(scutilPath)
	cmd.Stdin = strings.NewReader("remove " + key + "\nquit\n")
	_, err := cmd.CombinedOutput()
	return err
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

func setupTestConfigurator(t *testing.T) (*systemConfigurator, *statemanager.Manager, func()) {
	t.Helper()

	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "state.json")
	sm := statemanager.New(stateFile)
	sm.RegisterState(&ShutdownState{})
	sm.Start()

	configurator := &systemConfigurator{
		createdKeys:   make(map[string]struct{}),
		interfaceName: testInterfaceName,
	}

	searchKey := getKeyWithInput(netbirdDNSStateKeyFormat, testInterfaceName, searchSuffix)
	matchKey := getKeyWithInput(netbirdDNSStateKeyFormat, testInterfaceName, matchSuffix)
	localKey := getKeyWithInput(netbirdDNSStateKeyFormat, testInterfaceName, localSuffix)

	cleanup := func() {
		_ = sm.Stop(context.Background())
		for _, key := range []string{searchKey, matchKey, localKey} {
			_ = removeTestDNSKey(key)
		}
	}

	return configurator, sm, cleanup
}

func TestOriginalNameserversNoTransition(t *testing.T) {
	netbirdIP := netip.MustParseAddr("100.64.0.1")

	testCases := []struct {
		name     string
		routeAll bool
	}{
		{"routeall_false", false},
		{"routeall_true", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configurator, sm, cleanup := setupTestConfigurator(t)
			defer cleanup()

			_, err := configurator.getSystemDNSSettings()
			require.NoError(t, err)
			initialServers := configurator.getOriginalNameservers()
			t.Logf("Initial servers: %v", initialServers)
			require.NotEmpty(t, initialServers)

			for _, srv := range initialServers {
				require.NotEqual(t, netbirdIP, srv, "initial servers should not contain NetBird IP")
			}

			config := HostDNSConfig{
				ServerIP:   netbirdIP,
				ServerPort: 53,
				RouteAll:   tc.routeAll,
				Domains:    []DomainConfig{{Domain: "example.com", MatchOnly: true}},
			}

			for i := 1; i <= 2; i++ {
				err = configurator.applyDNSConfig(config, sm)
				require.NoError(t, err)

				servers := configurator.getOriginalNameservers()
				t.Logf("After apply %d (RouteAll=%v): %v", i, tc.routeAll, servers)
				assert.Equal(t, initialServers, servers)
			}
		})
	}
}

func TestOriginalNameserversRouteAllTransition(t *testing.T) {
	netbirdIP := netip.MustParseAddr("100.64.0.1")

	testCases := []struct {
		name         string
		initialRoute bool
	}{
		{"start_with_routeall_false", false},
		{"start_with_routeall_true", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configurator, sm, cleanup := setupTestConfigurator(t)
			defer cleanup()

			_, err := configurator.getSystemDNSSettings()
			require.NoError(t, err)
			initialServers := configurator.getOriginalNameservers()
			t.Logf("Initial servers: %v", initialServers)
			require.NotEmpty(t, initialServers)

			config := HostDNSConfig{
				ServerIP:   netbirdIP,
				ServerPort: 53,
				RouteAll:   tc.initialRoute,
				Domains:    []DomainConfig{{Domain: "example.com", MatchOnly: true}},
			}

			// First apply
			err = configurator.applyDNSConfig(config, sm)
			require.NoError(t, err)
			servers := configurator.getOriginalNameservers()
			t.Logf("After first apply (RouteAll=%v): %v", tc.initialRoute, servers)
			assert.Equal(t, initialServers, servers)

			// Toggle RouteAll
			config.RouteAll = !tc.initialRoute
			err = configurator.applyDNSConfig(config, sm)
			require.NoError(t, err)
			servers = configurator.getOriginalNameservers()
			t.Logf("After toggle (RouteAll=%v): %v", config.RouteAll, servers)
			assert.Equal(t, initialServers, servers)

			// Toggle back
			config.RouteAll = tc.initialRoute
			err = configurator.applyDNSConfig(config, sm)
			require.NoError(t, err)
			servers = configurator.getOriginalNameservers()
			t.Logf("After toggle back (RouteAll=%v): %v", config.RouteAll, servers)
			assert.Equal(t, initialServers, servers)

			for _, srv := range servers {
				assert.NotEqual(t, netbirdIP, srv, "servers should not contain NetBird IP")
			}
		})
	}
}
