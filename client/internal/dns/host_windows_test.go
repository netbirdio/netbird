package dns

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"
)

// TestNRPTEntriesCleanupOnConfigChange tests that old NRPT entries are properly cleaned up
// when the number of match domains decreases between configuration changes.
func TestNRPTEntriesCleanupOnConfigChange(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping registry integration test in short mode")
	}

	defer cleanupRegistryKeys(t)
	cleanupRegistryKeys(t)

	testIP := netip.MustParseAddr("100.64.0.1")

	// Create a test interface registry key so updateSearchDomains doesn't fail
	testGUID := "{12345678-1234-1234-1234-123456789ABC}"
	interfacePath := `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\` + testGUID
	testKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, interfacePath, registry.SET_VALUE)
	require.NoError(t, err, "Should create test interface registry key")
	testKey.Close()
	defer func() {
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, interfacePath)
	}()

	cfg := &registryConfigurator{
		guid: testGUID,
		gpo:  false,
	}

	config5 := HostDNSConfig{
		ServerIP: testIP,
		Domains: []DomainConfig{
			{Domain: "domain1.com", MatchOnly: true},
			{Domain: "domain2.com", MatchOnly: true},
			{Domain: "domain3.com", MatchOnly: true},
			{Domain: "domain4.com", MatchOnly: true},
			{Domain: "domain5.com", MatchOnly: true},
		},
	}

	err = cfg.applyDNSConfig(config5, nil)
	require.NoError(t, err)

	// Verify all 5 entries exist
	for i := 0; i < 5; i++ {
		exists, err := registryKeyExists(fmt.Sprintf("%s-%d", dnsPolicyConfigMatchPath, i))
		require.NoError(t, err)
		assert.True(t, exists, "Entry %d should exist after first config", i)
	}

	config2 := HostDNSConfig{
		ServerIP: testIP,
		Domains: []DomainConfig{
			{Domain: "domain1.com", MatchOnly: true},
			{Domain: "domain2.com", MatchOnly: true},
		},
	}

	err = cfg.applyDNSConfig(config2, nil)
	require.NoError(t, err)

	// Verify first 2 entries exist
	for i := 0; i < 2; i++ {
		exists, err := registryKeyExists(fmt.Sprintf("%s-%d", dnsPolicyConfigMatchPath, i))
		require.NoError(t, err)
		assert.True(t, exists, "Entry %d should exist after second config", i)
	}

	// Verify entries 2-4 are cleaned up
	for i := 2; i < 5; i++ {
		exists, err := registryKeyExists(fmt.Sprintf("%s-%d", dnsPolicyConfigMatchPath, i))
		require.NoError(t, err)
		assert.False(t, exists, "Entry %d should NOT exist after reducing to 2 domains", i)
	}
}

func registryKeyExists(path string) (bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return false, nil
		}
		return false, err
	}
	k.Close()
	return true, nil
}

func cleanupRegistryKeys(*testing.T) {
	// Clean up more entries to account for batching tests with many domains
	cfg := &registryConfigurator{nrptEntryCount: 20}
	_ = cfg.removeDNSMatchPolicies()
}

// TestNRPTDomainBatching verifies that domains are correctly batched into NRPT rules
// with a maximum of 50 domains per rule (Windows limitation).
func TestNRPTDomainBatching(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping registry integration test in short mode")
	}

	defer cleanupRegistryKeys(t)
	cleanupRegistryKeys(t)

	testIP := netip.MustParseAddr("100.64.0.1")

	// Create a test interface registry key so updateSearchDomains doesn't fail
	testGUID := "{12345678-1234-1234-1234-123456789ABC}"
	interfacePath := `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\` + testGUID
	testKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, interfacePath, registry.SET_VALUE)
	require.NoError(t, err, "Should create test interface registry key")
	testKey.Close()
	defer func() {
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, interfacePath)
	}()

	cfg := &registryConfigurator{
		guid: testGUID,
		gpo:  false,
	}

	testCases := []struct {
		name              string
		domainCount       int
		expectedRuleCount int
	}{
		{
			name:              "Less than 50 domains (single rule)",
			domainCount:       30,
			expectedRuleCount: 1,
		},
		{
			name:              "Exactly 50 domains (single rule)",
			domainCount:       50,
			expectedRuleCount: 1,
		},
		{
			name:              "51 domains (two rules)",
			domainCount:       51,
			expectedRuleCount: 2,
		},
		{
			name:              "100 domains (two rules)",
			domainCount:       100,
			expectedRuleCount: 2,
		},
		{
			name:              "125 domains (three rules: 50+50+25)",
			domainCount:       125,
			expectedRuleCount: 3,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clean up before each subtest
			cleanupRegistryKeys(t)

			// Generate domains
			domains := make([]DomainConfig, tc.domainCount)
			for i := 0; i < tc.domainCount; i++ {
				domains[i] = DomainConfig{
					Domain:    fmt.Sprintf("domain%d.com", i+1),
					MatchOnly: true,
				}
			}

			config := HostDNSConfig{
				ServerIP: testIP,
				Domains:  domains,
			}

			err := cfg.applyDNSConfig(config, nil)
			require.NoError(t, err)

			// Verify that exactly expectedRuleCount rules were created
			assert.Equal(t, tc.expectedRuleCount, cfg.nrptEntryCount,
				"Should create %d NRPT rules for %d domains", tc.expectedRuleCount, tc.domainCount)

			// Verify all expected rules exist
			for i := 0; i < tc.expectedRuleCount; i++ {
				exists, err := registryKeyExists(fmt.Sprintf("%s-%d", dnsPolicyConfigMatchPath, i))
				require.NoError(t, err)
				assert.True(t, exists, "NRPT rule %d should exist", i)
			}

			// Verify no extra rules were created
			exists, err := registryKeyExists(fmt.Sprintf("%s-%d", dnsPolicyConfigMatchPath, tc.expectedRuleCount))
			require.NoError(t, err)
			assert.False(t, exists, "No NRPT rule should exist at index %d", tc.expectedRuleCount)
		})
	}
}
