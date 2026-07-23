//go:build darwin && privileged && !ios

package dns

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// Closed set: unknown interfaces are rejected so typos cannot sweep real state.
var reservedTestInterfaces = map[string]struct{}{
	"utun990": {},
	"utun991": {}, "utun992": {}, "utun993": {},
	"utun994": {}, "utun995": {}, "utun996": {},
	"utun997": {}, "utun998": {}, testInterfaceName: {},
}

// Four covers the test keys without sweeping arbitrary real legacy state.
const maxReservedLegacyIndexedBatches = 4

func listDNSKeys(t *testing.T) []string {
	t.Helper()
	output, err := getSystemDNSKeys()
	require.NoError(t, err)

	var keys []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		const sep = " = "
		i := strings.Index(scanner.Text(), sep)
		if i < 0 {
			continue
		}
		key := strings.TrimSpace(scanner.Text()[i+len(sep):])
		if strings.HasPrefix(key, "State:/Network/Service/NetBird") {
			keys = append(keys, key)
		}
	}
	require.NoError(t, scanner.Err())
	return keys
}

// cleanReservedInterface lists once and removes only present keys, avoiding thousands of speculative calls.
// Unknown interfaces fail loudly rather than sweeping real state.
func cleanReservedInterface(t *testing.T, ifaces ...string) {
	t.Helper()
	if len(ifaces) == 0 {
		return
	}
	for _, iface := range ifaces {
		if _, ok := reservedTestInterfaces[iface]; !ok {
			t.Fatalf("cleanReservedInterface: %q is not in reservedTestInterfaces; refusing to sweep unknown interface state", iface)
		}
	}
	keys := listDNSKeys(t)
	for _, key := range keys {
		if matchesReservedInterface(key, ifaces) {
			require.NoError(t, removeTestDNSKey(key), "remove reserved interface key %s", key)
		}
	}
}

func matchesReservedInterface(key string, ifaces []string) bool {
	const prefix = "State:/Network/Service/NetBird-"
	if !strings.HasPrefix(key, prefix) {
		return false
	}
	body := strings.TrimPrefix(key, prefix)
	for _, iface := range ifaces {
		if strings.HasPrefix(body, iface+"-") {
			return true
		}
	}
	return false
}

// cleanReservedLegacyTestKeys removes reserved keys from the host's global Dynamic Store.
// WARNING: Stop NetBird before running tests that create them.
func cleanReservedLegacyTestKeys(t *testing.T) {
	t.Helper()
	keys := listDNSKeys(t)
	for _, key := range keys {
		if isReservedLegacyTestKey(key) {
			require.NoError(t, removeTestDNSKey(key), "remove reserved legacy key %s", key)
		}
	}
}

func isReservedLegacyTestKey(key string) bool {
	const prefix = "State:/Network/Service/NetBird-"
	if !strings.HasPrefix(key, prefix) {
		return false
	}
	body := strings.TrimPrefix(key, prefix)
	if !strings.HasSuffix(body, "/DNS") {
		return false
	}
	body = strings.TrimSuffix(body, "/DNS")
	switch body {
	case searchSuffix, matchSuffix, localSuffix:
		return true
	}
	parts := strings.SplitN(body, "-", 2)
	if len(parts) != 2 {
		return false
	}
	switch parts[0] {
	case searchSuffix, matchSuffix:
		idx, err := strconv.Atoi(parts[1])
		if err == nil && idx >= 0 && idx < maxReservedLegacyIndexedBatches {
			return true
		}
	}
	return false
}

func checkDNSKeyExists(key string) (bool, error) {
	output, err := runSystemConfigCommand("show " + key + "\nquit\n")
	if err != nil {
		return false, err
	}
	return !strings.Contains(string(output), "No such key"), nil
}

// removeTestDNSKey uses the production command path so silent exit-0 failures are surfaced.
func removeTestDNSKey(key string) error {
	_, err := runSystemConfigCommand(wrapCommand(buildRemoveKeyOperation(key)))
	return err
}

// readDomainsFromKey reads the SupplementalMatchDomains array back from scutil for a given key.
func readDomainsFromKey(t *testing.T, key string) []string {
	t.Helper()

	out, err := runSystemConfigCommand(fmt.Sprintf("open\nshow %s\nquit\n", key))
	require.NoError(t, err, "show should succeed")

	var domains []string
	inArray := false
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "SupplementalMatchDomains") && strings.Contains(line, "<array>") {
			inArray = true
			continue
		}
		if inArray {
			if line == "}" {
				break
			}
			// lines look like: "0 : a.com"
			parts := strings.SplitN(line, " : ", 2)
			if len(parts) == 2 {
				domains = append(domains, parts[1])
			}
		}
	}
	require.NoError(t, scanner.Err())
	return domains
}

func setupTestConfigurator(t *testing.T) (*systemConfigurator, *statemanager.Manager, func()) {
	t.Helper()

	cleanReservedInterface(t, testInterfaceName)

	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "state.json")
	sm := statemanager.New(stateFile)
	sm.RegisterState(&ShutdownState{})
	sm.Start()

	configurator := &systemConfigurator{
		createdKeys:   make(map[string]struct{}),
		interfaceName: testInterfaceName,
	}

	cleanup := func() {
		_ = sm.Stop(context.Background())
		for key := range configurator.createdKeys {
			_ = removeTestDNSKey(key)
		}
		cleanReservedInterface(t, testInterfaceName)
	}

	return configurator, sm, cleanup
}

func TestDarwinDNSUncleanShutdownCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping privileged integration test in short mode")
	}

	cleanReservedInterface(t, testInterfaceName)
	t.Cleanup(func() { cleanReservedInterface(t, testInterfaceName) })

	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "state.json")

	sm := statemanager.New(stateFile)
	sm.RegisterState(&ShutdownState{})
	sm.Start()
	defer func() {
		require.NoError(t, sm.Stop(context.Background()))
	}()

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

	// Collect all created keys for cleanup verification
	createdKeys := make([]string, 0, len(configurator.createdKeys))
	for key := range configurator.createdKeys {
		createdKeys = append(createdKeys, key)
	}
	require.NotEmpty(t, createdKeys, "applying a DNS config with RouteAll and a match domain must create keys")

	defer func() {
		for _, key := range createdKeys {
			_ = removeTestDNSKey(key)
		}
	}()

	for _, key := range createdKeys {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		require.True(t, exists, "key %s must exist before cleanup, otherwise removal is not demonstrated", key)
	}

	sm2 := statemanager.New(stateFile)
	sm2.RegisterState(&ShutdownState{})
	require.NoError(t, sm2.LoadState(&ShutdownState{}))

	state := sm2.GetState(&ShutdownState{})
	require.NotNil(t, state, "state must load from the persisted state file")

	shutdownState, ok := state.(*ShutdownState)
	require.True(t, ok)

	assert.Equal(t, testInterfaceName, shutdownState.InterfaceName)
	assert.ElementsMatch(t, createdKeys, shutdownState.CreatedKeys)

	err = shutdownState.Cleanup()
	require.NoError(t, err)

	for _, key := range createdKeys {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		assert.False(t, exists, "key %s should NOT exist after cleanup", key)
	}
}

func TestApplyPersistsInterfaceBeforeScopedKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping privileged integration test in short mode")
	}

	iface := "utun990"
	cleanReservedInterface(t, iface)
	t.Cleanup(func() { cleanReservedInterface(t, iface) })

	stateFile := filepath.Join(t.TempDir(), "state.json")
	stateManager := statemanager.New(stateFile)
	stateManager.RegisterState(&ShutdownState{})
	configurator := &systemConfigurator{
		createdKeys:   make(map[string]struct{}),
		interfaceName: iface,
	}
	config := HostDNSConfig{
		ServerIP:   netip.MustParseAddr("100.64.0.1"),
		ServerPort: 53,
		Domains: []DomainConfig{
			{Domain: "persist-before-key.example.com", MatchOnly: true},
		},
	}

	require.NoError(t, configurator.applyDNSConfig(config, stateManager))
	key := fmt.Sprintf(netbirdDNSStateKeyIndexedFormat, iface, matchSuffix, 0)
	exists, err := checkDNSKeyExists(key)
	require.NoError(t, err)
	require.True(t, exists, "scoped key must exist before recovery")

	loadedStateManager := statemanager.New(stateFile)
	loadedStateManager.RegisterState(&ShutdownState{})
	require.NoError(t, loadedStateManager.LoadState(&ShutdownState{}))
	state, ok := loadedStateManager.GetState(&ShutdownState{}).(*ShutdownState)
	require.True(t, ok)
	assert.Equal(t, iface, state.InterfaceName)
	assert.Empty(t, state.CreatedKeys, "later in-memory updates must not mask the pre-apply persist")

	require.NoError(t, state.Cleanup())
	exists, err = checkDNSKeyExists(key)
	require.NoError(t, err)
	assert.False(t, exists, "cleanup must discover the scoped key from the persisted interface")
}

func TestApplyDNSConfigAbortsOnPersistFailure(t *testing.T) {
	blocker, err := os.CreateTemp(t.TempDir(), "blocker")
	require.NoError(t, err)
	require.NoError(t, blocker.Close())

	stateManager := statemanager.New(filepath.Join(blocker.Name(), "state.json"))
	stateManager.RegisterState(&ShutdownState{})
	configurator := &systemConfigurator{
		createdKeys:   make(map[string]struct{}),
		interfaceName: testInterfaceName,
	}

	err = configurator.applyDNSConfig(HostDNSConfig{}, stateManager)
	require.ErrorContains(t, err, "persist shutdown state before applying dns config")
	assert.Empty(t, configurator.createdKeys)
}

// TestMatchDomainBatching writes increasing numbers of domains via the batching mechanism
// and verifies all domains are readable across multiple scutil keys.
func TestMatchDomainBatching(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping privileged integration test in short mode")
	}

	cleanReservedInterface(t, testInterfaceName)
	t.Cleanup(func() { cleanReservedInterface(t, testInterfaceName) })

	testCases := []struct {
		name      string
		count     int
		generator func(int) []string
	}{
		{"short_10", 10, generateShortDomains},
		{"short_50", 50, generateShortDomains},
		{"short_100", 100, generateShortDomains},
		{"short_200", 200, generateShortDomains},
		{"short_500", 500, generateShortDomains},
		{"long_10", 10, generateLongDomains},
		{"long_50", 50, generateLongDomains},
		{"long_100", 100, generateLongDomains},
		{"long_200", 200, generateLongDomains},
		{"long_500", 500, generateLongDomains},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configurator := &systemConfigurator{
				createdKeys:   make(map[string]struct{}),
				interfaceName: testInterfaceName,
			}

			defer func() {
				for key := range configurator.createdKeys {
					_ = removeTestDNSKey(key)
				}
			}()

			domains := tc.generator(tc.count)
			err := configurator.addBatchedDomains(matchSuffix, domains, netip.MustParseAddr("100.64.0.1"), 53, false)
			require.NoError(t, err)

			batches := splitDomainsIntoBatches(domains)
			t.Logf("wrote %d domains across %d batched keys", tc.count, len(batches))

			// Read back all domains from all batched keys
			var got []string
			for i := range batches {
				key := fmt.Sprintf(netbirdDNSStateKeyIndexedFormat, testInterfaceName, matchSuffix, i)
				exists, err := checkDNSKeyExists(key)
				require.NoError(t, err)
				require.True(t, exists, "key %s should exist", key)

				got = append(got, readDomainsFromKey(t, key)...)
			}

			t.Logf("read back %d/%d domains from %d keys", len(got), tc.count, len(batches))
			assert.Equal(t, tc.count, len(got), "all domains should be readable")
			assert.Equal(t, domains, got, "domains should match in order")
		})
	}
}

func TestOriginalNameserversNoTransition(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping privileged integration test in short mode")
	}

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
	if testing.Short() {
		t.Skip("skipping privileged integration test in short mode")
	}

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

func TestMultipleInstancesBatchedIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping privileged integration test in short mode")
	}

	iface1 := "utun991"
	iface2 := "utun992"
	cleanReservedInterface(t, iface1, iface2)
	t.Cleanup(func() { cleanReservedInterface(t, iface1, iface2) })

	cfg1 := &systemConfigurator{
		createdKeys:   make(map[string]struct{}),
		interfaceName: iface1,
	}
	cfg2 := &systemConfigurator{
		createdKeys:   make(map[string]struct{}),
		interfaceName: iface2,
	}

	defer func() {
		for key := range cfg1.createdKeys {
			_ = removeTestDNSKey(key)
		}
		for key := range cfg2.createdKeys {
			_ = removeTestDNSKey(key)
		}
	}()

	domains1 := generateShortDomains(60) // Exceeds the 50-domain batch limit.
	// Distinct content proves readback independence, not merely distinct key names.
	domains2 := make([]string, len(domains1))
	for i, d := range domains1 {
		domains2[i] = "iface2-" + d
	}

	require.NoError(t, cfg1.addBatchedDomains(matchSuffix, domains1, netip.MustParseAddr("100.64.0.1"), 53, false))
	require.NoError(t, cfg2.addBatchedDomains(matchSuffix, domains2, netip.MustParseAddr("100.64.0.2"), 53, false))

	for key := range cfg1.createdKeys {
		assert.Contains(t, key, iface1)
		assert.NotContains(t, key, iface2)
	}

	for key := range cfg2.createdKeys {
		assert.Contains(t, key, iface2)
		assert.NotContains(t, key, iface1)
	}

	for key := range cfg1.createdKeys {
		_, exists := cfg2.createdKeys[key]
		assert.False(t, exists, "key %s should not exist in both instances", key)
	}

	var got1, got2 []string
	for key := range cfg1.createdKeys {
		got1 = append(got1, readDomainsFromKey(t, key)...)
	}
	for key := range cfg2.createdKeys {
		got2 = append(got2, readDomainsFromKey(t, key)...)
	}
	assert.ElementsMatch(t, domains1, got1, "instance 1 domains should be readable with their original content")
	assert.ElementsMatch(t, domains2, got2, "instance 2 domains should be readable with their original, distinct content")
	for _, d := range got1 {
		assert.NotContains(t, d, "iface2-", "instance 1 readback must not contain instance 2 content")
	}
	for _, d := range got2 {
		assert.Contains(t, d, "iface2-", "instance 2 readback must retain its distinct content")
	}
}

func TestShutdownStateLegacyCleanupWithKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping privileged integration test in short mode")
	}

	cleanReservedLegacyTestKeys(t)
	t.Cleanup(func() { cleanReservedLegacyTestKeys(t) })

	legacyKey := fmt.Sprintf("State:/Network/Service/NetBird-%s/DNS", matchSuffix)

	configurator := &systemConfigurator{
		createdKeys: make(map[string]struct{}),
	}
	err := configurator.addDNSState(legacyKey, "legacy.example.com", netip.MustParseAddr("100.64.0.1"), 53, false)
	require.NoError(t, err)

	defer func() {
		_ = removeTestDNSKey(legacyKey)
	}()

	exists, err := checkDNSKeyExists(legacyKey)
	require.NoError(t, err)
	require.True(t, exists, "legacy key should exist before cleanup")

	legacyJSON := []byte(`{"CreatedKeys":["` + legacyKey + `"]}`)
	var state ShutdownState
	require.NoError(t, json.Unmarshal(legacyJSON, &state))
	require.Empty(t, state.InterfaceName, "legacy state should have no interface name")
	require.Contains(t, state.CreatedKeys, legacyKey, "legacy key should be deserialized from PascalCase JSON")

	err = state.Cleanup()
	require.NoError(t, err)

	exists, err = checkDNSKeyExists(legacyKey)
	require.NoError(t, err)
	assert.False(t, exists, "legacy key should be removed after cleanup")
}

func TestEmptyStateLegacyDiscoveryCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping privileged integration test in short mode")
	}

	sentinelIface := "utun996"
	cleanReservedInterface(t, sentinelIface)
	cleanReservedLegacyTestKeys(t)
	t.Cleanup(func() {
		cleanReservedInterface(t, sentinelIface)
		cleanReservedLegacyTestKeys(t)
	})

	legacyWriter := &systemConfigurator{createdKeys: make(map[string]struct{})}

	namedSearch := fmt.Sprintf("State:/Network/Service/NetBird-%s/DNS", searchSuffix)
	namedMatch := fmt.Sprintf("State:/Network/Service/NetBird-%s/DNS", matchSuffix)
	namedLocal := fmt.Sprintf("State:/Network/Service/NetBird-%s/DNS", localSuffix)
	indexedSearch0 := fmt.Sprintf("State:/Network/Service/NetBird-%s-%d/DNS", searchSuffix, 0)
	indexedMatch0 := fmt.Sprintf("State:/Network/Service/NetBird-%s-%d/DNS", matchSuffix, 0)
	indexedMatch1 := fmt.Sprintf("State:/Network/Service/NetBird-%s-%d/DNS", matchSuffix, 1)
	legacyKeys := []string{namedSearch, namedMatch, namedLocal, indexedSearch0, indexedMatch0, indexedMatch1}

	for _, key := range legacyKeys {
		require.NoError(t, legacyWriter.addDNSState(key, "legacy.example.com", netip.MustParseAddr("100.64.0.1"), 53, false))
	}

	// Legacy discovery must not touch interface-scoped keys.
	sentinelKey := fmt.Sprintf(netbirdDNSStateKeyIndexedFormat, sentinelIface, matchSuffix, 0)
	sentinelWriter := &systemConfigurator{createdKeys: make(map[string]struct{}), interfaceName: sentinelIface}
	require.NoError(t, sentinelWriter.addBatchedDomains(matchSuffix, []string{"sentinel-preserve.example.com"}, netip.MustParseAddr("100.64.0.2"), 53, false))

	defer func() {
		for _, key := range legacyKeys {
			_ = removeTestDNSKey(key)
		}
		_ = removeTestDNSKey(sentinelKey)
	}()

	for _, key := range legacyKeys {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		require.True(t, exists, "legacy key %s must exist before cleanup, otherwise removal is not demonstrated", key)
	}
	sentinelExists, err := checkDNSKeyExists(sentinelKey)
	require.NoError(t, err)
	require.True(t, sentinelExists, "sentinel scoped key %s must exist before cleanup, otherwise preservation is not demonstrated", sentinelKey)

	state := &ShutdownState{}
	require.NoError(t, state.Cleanup())

	for _, key := range legacyKeys {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		assert.False(t, exists, "legacy key %s should be removed after cleanup", key)
	}
	sentinelExists, err = checkDNSKeyExists(sentinelKey)
	require.NoError(t, err)
	assert.True(t, sentinelExists, "scoped sentinel key %s should be preserved by legacy Cleanup", sentinelKey)
}

func TestPartialStateUnionScopedDiscovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping privileged integration test in short mode")
	}

	iface := "utun993"
	cleanReservedInterface(t, iface)
	t.Cleanup(func() { cleanReservedInterface(t, iface) })
	configurator := &systemConfigurator{createdKeys: make(map[string]struct{}), interfaceName: iface}

	domains := generateShortDomains(60) // Exceeds the 50-domain batch limit.
	require.NoError(t, configurator.addBatchedDomains(matchSuffix, domains, netip.MustParseAddr("100.64.0.1"), 53, false))

	allKeys := make([]string, 0, len(configurator.createdKeys))
	for key := range configurator.createdKeys {
		allKeys = append(allKeys, key)
	}
	require.Len(t, allKeys, 2, "60 short domains should produce 2 batch keys")

	defer func() {
		for _, key := range allKeys {
			_ = removeTestDNSKey(key)
		}
	}()

	for _, key := range allKeys {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		require.True(t, exists, "key %s must exist before cleanup, otherwise removal is not demonstrated", key)
	}

	partialKey := fmt.Sprintf(netbirdDNSStateKeyIndexedFormat, iface, matchSuffix, 0)
	state := &ShutdownState{
		InterfaceName: iface,
		CreatedKeys:   []string{partialKey},
	}
	require.NoError(t, state.Cleanup())

	for _, key := range allKeys {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		assert.False(t, exists, "key %s should be removed after cleanup via union with discovery", key)
	}
}

func TestCleanupOneInterfacePreservesAnother(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping privileged integration test in short mode")
	}

	iface1 := "utun994"
	iface2 := "utun995"
	cleanReservedInterface(t, iface1, iface2)
	t.Cleanup(func() { cleanReservedInterface(t, iface1, iface2) })

	cfg1 := &systemConfigurator{createdKeys: make(map[string]struct{}), interfaceName: iface1}
	cfg2 := &systemConfigurator{createdKeys: make(map[string]struct{}), interfaceName: iface2}

	require.NoError(t, cfg1.addBatchedDomains(matchSuffix, []string{"iface1-only.example.com"}, netip.MustParseAddr("100.64.0.1"), 53, false))
	require.NoError(t, cfg2.addBatchedDomains(matchSuffix, []string{"iface2-only.example.com"}, netip.MustParseAddr("100.64.0.2"), 53, false))

	keys1 := make([]string, 0, len(cfg1.createdKeys))
	for key := range cfg1.createdKeys {
		keys1 = append(keys1, key)
	}
	keys2 := make([]string, 0, len(cfg2.createdKeys))
	for key := range cfg2.createdKeys {
		keys2 = append(keys2, key)
	}
	require.NotEmpty(t, keys1)
	require.NotEmpty(t, keys2)

	defer func() {
		for _, key := range keys1 {
			_ = removeTestDNSKey(key)
		}
		for _, key := range keys2 {
			_ = removeTestDNSKey(key)
		}
	}()

	for _, key := range keys1 {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		require.True(t, exists, "iface1 key %s must exist before cleanup", key)
	}
	for _, key := range keys2 {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		require.True(t, exists, "iface2 key %s must exist before cleanup", key)
	}

	state1 := &ShutdownState{InterfaceName: iface1, CreatedKeys: keys1}
	require.NoError(t, state1.Cleanup())

	for _, key := range keys1 {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		assert.False(t, exists, "iface1 key %s should be removed", key)
	}
	for _, key := range keys2 {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		assert.True(t, exists, "iface2 key %s should be preserved", key)
	}
}

func TestDiscoverLegacyDNSKeysIsolated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping privileged integration test in short mode")
	}

	iface := "utun996"
	cleanReservedInterface(t, iface)
	cleanReservedLegacyTestKeys(t)
	t.Cleanup(func() {
		cleanReservedInterface(t, iface)
		cleanReservedLegacyTestKeys(t)
	})
	scopedCfg := &systemConfigurator{createdKeys: make(map[string]struct{}), interfaceName: iface}
	require.NoError(t, scopedCfg.addBatchedDomains(matchSuffix, []string{"scoped-only.example.com"}, netip.MustParseAddr("100.64.0.1"), 53, false))

	scopedKeys := make([]string, 0, len(scopedCfg.createdKeys))
	for key := range scopedCfg.createdKeys {
		scopedKeys = append(scopedKeys, key)
	}
	require.NotEmpty(t, scopedKeys)

	legacyKey := fmt.Sprintf("State:/Network/Service/NetBird-%s/DNS", searchSuffix)
	bare := &systemConfigurator{createdKeys: make(map[string]struct{})}
	require.NoError(t, bare.addDNSState(legacyKey, "legacy-isolated.example.com", netip.MustParseAddr("100.64.0.2"), 53, false))

	defer func() {
		for _, key := range scopedKeys {
			_ = removeTestDNSKey(key)
		}
		_ = removeTestDNSKey(legacyKey)
	}()

	for _, key := range append(append([]string{}, scopedKeys...), legacyKey) {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		require.True(t, exists, "key %s must exist before discovery", key)
	}

	legacyFound, err := discoverLegacyDNSKeys()
	require.NoError(t, err)
	assert.Contains(t, legacyFound, legacyKey, "legacy discovery must find the actual legacy key")
	for _, scopedKey := range scopedKeys {
		assert.NotContains(t, legacyFound, scopedKey, "legacy discovery must not return interface-scoped keys")
	}
}

func TestDiscoverExistingKeysScoped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping privileged integration test in short mode")
	}

	iface := "utun998"
	cleanReservedInterface(t, iface)
	cleanReservedLegacyTestKeys(t)
	t.Cleanup(func() {
		cleanReservedInterface(t, iface)
		cleanReservedLegacyTestKeys(t)
	})
	scopedCfg := &systemConfigurator{createdKeys: make(map[string]struct{}), interfaceName: iface}
	require.NoError(t, scopedCfg.addBatchedDomains(matchSuffix, []string{"scoped-real.example.com"}, netip.MustParseAddr("100.64.0.1"), 53, false))

	scopedKeys := make([]string, 0, len(scopedCfg.createdKeys))
	for key := range scopedCfg.createdKeys {
		scopedKeys = append(scopedKeys, key)
	}
	require.NotEmpty(t, scopedKeys)

	legacyKey := fmt.Sprintf("State:/Network/Service/NetBird-%s/DNS", matchSuffix)
	bare := &systemConfigurator{createdKeys: make(map[string]struct{})}
	require.NoError(t, bare.addDNSState(legacyKey, "legacy-global.example.com", netip.MustParseAddr("100.64.0.2"), 53, false))

	defer func() {
		for _, key := range scopedKeys {
			_ = removeTestDNSKey(key)
		}
		_ = removeTestDNSKey(legacyKey)
	}()

	for _, key := range append(append([]string{}, scopedKeys...), legacyKey) {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		require.True(t, exists, "key %s must exist before discovery", key)
	}

	cfg := &systemConfigurator{createdKeys: make(map[string]struct{}), interfaceName: iface}
	scoped, err := cfg.discoverExistingKeys()
	require.NoError(t, err)
	for _, scopedKey := range scopedKeys {
		assert.Contains(t, scoped, scopedKey, "scoped discovery must find the actual scoped key")
	}
	assert.NotContains(t, scoped, legacyKey, "scoped discovery must not return legacy global keys")
}

func TestGetRemovableKeysWithDefaultsUnion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping privileged integration test in short mode")
	}

	iface := "utun997"
	cleanReservedInterface(t, iface)
	t.Cleanup(func() { cleanReservedInterface(t, iface) })

	// A separate writer simulates a prior process instance.
	writer := &systemConfigurator{createdKeys: make(map[string]struct{}), interfaceName: iface}
	domains := generateShortDomains(60) // Exceeds the 50-domain batch limit.
	require.NoError(t, writer.addBatchedDomains(matchSuffix, domains, netip.MustParseAddr("100.64.0.1"), 53, false))

	systemKeys := make([]string, 0, len(writer.createdKeys))
	for key := range writer.createdKeys {
		systemKeys = append(systemKeys, key)
	}
	require.Len(t, systemKeys, 2, "60 short domains should produce 2 batch keys")

	defer func() {
		for _, key := range systemKeys {
			_ = removeTestDNSKey(key)
		}
	}()

	// Sort for deterministic assignment despite randomized map iteration.
	sort.Strings(systemKeys)
	for _, key := range systemKeys {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		require.True(t, exists, "key %s must exist on the system before checking union", key)
	}

	recordedAndDiscovered := systemKeys[0]
	unrecordedOnSystem := systemKeys[1]
	// Outside the pre-cleaned range, so discovery cannot find it.
	recordedOnly := fmt.Sprintf(netbirdDNSStateKeyIndexedFormat, iface, matchSuffix, 99)

	if exists, err := checkDNSKeyExists(recordedOnly); err == nil && exists {
		t.Fatalf("recordedOnly key %s already exists on the system; pre-clean did not remove it", recordedOnly)
	}

	underTest := &systemConfigurator{
		createdKeys: map[string]struct{}{
			recordedAndDiscovered: {},
			recordedOnly:          {},
		},
		interfaceName: iface,
	}

	removable, err := underTest.getRemovableKeysWithDefaults()
	require.NoError(t, err)

	assert.Contains(t, removable, unrecordedOnSystem, "unrecorded system key must be discovered")
	assert.Contains(t, removable, recordedOnly, "recorded-only key must remain even though discovery cannot find it")
	assert.Contains(t, removable, recordedAndDiscovered, "overlapping key must still be present")

	seen := make(map[string]int)
	for _, key := range removable {
		seen[key]++
	}
	for key, count := range seen {
		assert.Equal(t, 1, count, "key %s should appear exactly once (deduplicated)", key)
	}
	assert.Len(t, removable, 3, "result should be exactly {recordedAndDiscovered, unrecordedOnSystem, recordedOnly}")
}

func TestSparseIndexedScopedCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping privileged integration test in short mode")
	}

	iface := "utun993"
	cleanReservedInterface(t, iface)
	t.Cleanup(func() { cleanReservedInterface(t, iface) })

	configurator := &systemConfigurator{createdKeys: make(map[string]struct{}), interfaceName: iface}
	require.NoError(t, configurator.addBatchedDomains(matchSuffix, generateShortDomains(150), netip.MustParseAddr("100.64.0.1"), 53, false))

	keys := make([]string, 3)
	for i := range keys {
		keys[i] = fmt.Sprintf(netbirdDNSStateKeyIndexedFormat, iface, matchSuffix, i)
		exists, err := checkDNSKeyExists(keys[i])
		require.NoError(t, err)
		require.True(t, exists, "key %s must exist before sparse cleanup", keys[i])
	}

	require.NoError(t, removeTestDNSKey(keys[0]))
	require.NoError(t, (&ShutdownState{InterfaceName: iface}).Cleanup())

	for _, key := range keys[1:] {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		assert.False(t, exists, "key %s should be removed after sparse cleanup", key)
	}
}
