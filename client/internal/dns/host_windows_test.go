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
// With batching enabled (50 domains per rule), we need enough domains to create multiple rules.
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

	// Create 125 domains which will result in 3 NRPT rules (50+50+25)
	domains125 := make([]DomainConfig, 125)
	for i := 0; i < 125; i++ {
		domains125[i] = DomainConfig{
			Domain:    fmt.Sprintf("domain%d.com", i+1),
			MatchOnly: true,
		}
	}

	config125 := HostDNSConfig{
		ServerIP: testIP,
		Domains:  domains125,
	}

	err = cfg.applyDNSConfig(config125, nil)
	require.NoError(t, err)

	// Verify 3 NRPT rules exist
	assert.Equal(t, 3, cfg.nrptEntryCount, "Should create 3 NRPT rules for 125 domains")
	for i := 0; i < 3; i++ {
		exists, err := registryKeyExists(fmt.Sprintf("%s-%d", dnsPolicyConfigMatchPath, i))
		require.NoError(t, err)
		assert.True(t, exists, "NRPT rule %d should exist after first config", i)
	}

	// Reduce to 75 domains which will result in 2 NRPT rules (50+25)
	domains75 := make([]DomainConfig, 75)
	for i := 0; i < 75; i++ {
		domains75[i] = DomainConfig{
			Domain:    fmt.Sprintf("domain%d.com", i+1),
			MatchOnly: true,
		}
	}

	config75 := HostDNSConfig{
		ServerIP: testIP,
		Domains:  domains75,
	}

	err = cfg.applyDNSConfig(config75, nil)
	require.NoError(t, err)

	// Verify first 2 NRPT rules exist
	assert.Equal(t, 2, cfg.nrptEntryCount, "Should create 2 NRPT rules for 75 domains")
	for i := 0; i < 2; i++ {
		exists, err := registryKeyExists(fmt.Sprintf("%s-%d", dnsPolicyConfigMatchPath, i))
		require.NoError(t, err)
		assert.True(t, exists, "NRPT rule %d should exist after second config", i)
	}

	// Verify rule 2 is cleaned up
	exists, err := registryKeyExists(fmt.Sprintf("%s-%d", dnsPolicyConfigMatchPath, 2))
	require.NoError(t, err)
	assert.False(t, exists, "NRPT rule 2 should NOT exist after reducing to 75 domains")
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

// TestNRPTDomainBatching verifies that domains are correctly batched into NRPT rules.
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
