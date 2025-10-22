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
	cfg := &registryConfigurator{nrptEntryCount: 10}
	_ = cfg.removeDNSMatchPolicies()
}
