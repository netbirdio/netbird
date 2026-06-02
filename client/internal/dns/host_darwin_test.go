//go:build !ios

package dns

import (
	"bufio"
	"bytes"
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

	configurator := &systemConfigurator{
		createdKeys: make(map[string]struct{}),
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

	localKey := getKeyWithInput(netbirdDNSStateKeyFormat, localSuffix)

	// Collect all created keys for cleanup verification
	createdKeys := make([]string, 0, len(configurator.createdKeys))
	for key := range configurator.createdKeys {
		createdKeys = append(createdKeys, key)
	}

	defer func() {
		for _, key := range createdKeys {
			_ = removeTestDNSKey(key)
		}
		_ = removeTestDNSKey(localKey)
	}()

	for _, key := range createdKeys {
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

	err = shutdownState.Cleanup()
	require.NoError(t, err)

	for _, key := range createdKeys {
		exists, err := checkDNSKeyExists(key)
		require.NoError(t, err)
		assert.False(t, exists, "Key %s should NOT exist after cleanup", key)
	}
}

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

// readDomainsFromKey reads the SupplementalMatchDomains array back from scutil for a given key.
func readDomainsFromKey(t *testing.T, key string) []string {
	t.Helper()

	cmd := exec.Command(scutilPath)
	cmd.Stdin = strings.NewReader(fmt.Sprintf("open\nshow %s\nquit\n", key))
	out, err := cmd.Output()
	require.NoError(t, err, "scutil show should succeed")

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

// TestMatchDomainBatching writes increasing numbers of domains via the batching mechanism
// and verifies all domains are readable across multiple scutil keys.
func TestMatchDomainBatching(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping scutil integration test in short mode")
	}

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
				createdKeys: make(map[string]struct{}),
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
				key := fmt.Sprintf(netbirdDNSStateKeyIndexedFormat, matchSuffix, i)
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
		createdKeys: make(map[string]struct{}),
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
		createdKeys: make(map[string]struct{}),
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
		createdKeys: make(map[string]struct{}),
	}

	cleanup := func() {
		_ = sm.Stop(context.Background())
		for key := range configurator.createdKeys {
			_ = removeTestDNSKey(key)
		}
		// Also clean up old-format keys and local key in case they exist
		_ = removeTestDNSKey(getKeyWithInput(netbirdDNSStateKeyFormat, searchSuffix))
		_ = removeTestDNSKey(getKeyWithInput(netbirdDNSStateKeyFormat, matchSuffix))
		_ = removeTestDNSKey(getKeyWithInput(netbirdDNSStateKeyFormat, localSuffix))
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
