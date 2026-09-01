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
	interfacePath := InterfaceConfigPath + `\` + testGUID
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
	assert.Equal(t, 3, countNRPTRuleKeys(t), "Should create 3 NRPT rules for 125 domains")
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
	assert.Equal(t, 2, countNRPTRuleKeys(t), "Should create 2 NRPT rules for 75 domains")
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

// TestNRPTCatchAllRule verifies that RouteAll adds the root namespace to the
// match rule instead of a rule of its own, that .local is carved back out with
// an empty server list, and that both go away when RouteAll is cleared or the
// host DNS is restored.
func TestNRPTCatchAllRule(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping registry integration test in short mode")
	}

	defer cleanupRegistryKeys(t)
	cleanupRegistryKeys(t)

	testIP := netip.MustParseAddr("100.64.0.1")
	testGUID := "{12345678-1234-1234-1234-123456789ABC}"
	interfacePath := InterfaceConfigPath + `\` + testGUID
	testKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, interfacePath, registry.SET_VALUE)
	require.NoError(t, err, "Should create test interface registry key")
	require.NoError(t, testKey.Close(), "close test interface registry key")
	defer func() {
		assert.NoError(t, registry.DeleteKey(registry.LOCAL_MACHINE, interfacePath), "delete test interface registry key")
	}()

	cfg := &registryConfigurator{guid: testGUID}

	matchOnly := HostDNSConfig{
		ServerIP: testIP,
		Domains:  []DomainConfig{{Domain: "example.com", MatchOnly: true}},
	}
	primary := HostDNSConfig{
		ServerIP: testIP,
		RouteAll: true,
		Domains:  []DomainConfig{{Domain: "example.com", MatchOnly: true}},
	}
	firstRule := fmt.Sprintf("%s-0", dnsPolicyConfigMatchPath)

	// The root namespace is not a rule of its own: it rides in the match rule,
	// which is the point of it not being a special case.
	require.NoError(t, cfg.applyDNSConfig(matchOnly, nil))
	names := ruleNamespaces(t, firstRule)
	assert.Contains(t, names, ".example.com")
	assert.NotContains(t, names, nrptCatchAllNamespace, "a match-only config must not claim every namespace")

	require.NoError(t, cfg.applyDNSConfig(primary, nil))
	names = ruleNamespaces(t, firstRule)
	assert.Contains(t, names, ".example.com")
	assert.Contains(t, names, nrptCatchAllNamespace, "RouteAll should add the root namespace to the match rule")

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, firstRule, registry.QUERY_VALUE)
	require.NoError(t, err)
	servers, _, err := k.GetStringValue(dnsPolicyConfigGenericDNSServersKey)
	require.NoError(t, err)
	assert.Equal(t, testIP.String(), servers, "every namespace in the rule resolves through our resolver")
	require.NoError(t, k.Close(), "close match rule key")

	// .local is carved back out: RFC 6762 reserves it for mDNS, so it needs a
	// rule of its own — it is the one rule with a different server list.
	ek, err := registry.OpenKey(registry.LOCAL_MACHINE, dnsPolicyConfigExemptLocalPath, registry.QUERY_VALUE)
	require.NoError(t, err, "exemption rule should exist once the root namespace is claimed")

	exemptNames, _, err := ek.GetStringsValue(dnsPolicyConfigNameKey)
	require.NoError(t, err)
	assert.Equal(t, []string{nrptLocalNamespace}, exemptNames, "the exemption should name only the mDNS namespace")

	exemptServers, _, err := ek.GetStringValue(dnsPolicyConfigGenericDNSServersKey)
	require.NoError(t, err, "the value has to be present, empty: without it Windows drops the rule")
	assert.Empty(t, exemptServers, "an exemption rule lists no servers")

	exemptOpts, _, err := ek.GetIntegerValue(dnsPolicyConfigConfigOptionsKey)
	require.NoError(t, err)
	assert.EqualValues(t, dnsPolicyConfigConfigOptionsValue, exemptOpts, "same options as a normal rule; the empty server list is what makes it an exemption")
	require.NoError(t, ek.Close(), "close exemption rule key")

	require.NoError(t, cfg.applyDNSConfig(matchOnly, nil))
	names = ruleNamespaces(t, firstRule)
	assert.NotContains(t, names, nrptCatchAllNamespace, "clearing RouteAll should drop the root namespace")

	exists, err := registryKeyExists(dnsPolicyConfigExemptLocalPath)
	require.NoError(t, err)
	assert.False(t, exists, "exemption rule should go with the namespace it carves out of")

	require.NoError(t, cfg.applyDNSConfig(primary, nil))
	require.NoError(t, cfg.restoreHostDNS())
	exists, err = registryKeyExists(firstRule)
	require.NoError(t, err)
	assert.False(t, exists, "restore should leave no rule behind")
}

// ruleNamespaces returns the namespaces an NRPT rule key claims.
func ruleNamespaces(t *testing.T, path string) []string {
	t.Helper()
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	require.NoError(t, err, "rule key %s should exist", path)
	defer k.Close()

	names, _, err := k.GetStringsValue(dnsPolicyConfigNameKey)
	require.NoError(t, err)
	return names
}

// TestNRPTCatchAllRuleLegacyEnv verifies that NB_USE_LEGACY_DNS_RESOLUTION
// leaves the root namespace unclaimed, so no rule is written for a RouteAll
// config that carries no match domains.
func TestNRPTCatchAllRuleLegacyEnv(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping registry integration test in short mode")
	}

	defer cleanupRegistryKeys(t)
	cleanupRegistryKeys(t)

	t.Setenv(envLegacyDNSResolution, "true")

	testGUID := "{12345678-1234-1234-1234-123456789ABC}"
	interfacePath := InterfaceConfigPath + `\` + testGUID
	testKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, interfacePath, registry.SET_VALUE)
	require.NoError(t, err, "Should create test interface registry key")
	require.NoError(t, testKey.Close(), "close test interface registry key")
	defer func() {
		assert.NoError(t, registry.DeleteKey(registry.LOCAL_MACHINE, interfacePath), "delete test interface registry key")
	}()

	cfg := &registryConfigurator{guid: testGUID}
	config := HostDNSConfig{
		ServerIP: netip.MustParseAddr("100.64.0.1"),
		RouteAll: true,
	}

	require.NoError(t, cfg.applyDNSConfig(config, nil))

	// RouteAll with no match domains and the switch set leaves nothing to write.
	exists, err := registryKeyExists(fmt.Sprintf("%s-0", dnsPolicyConfigMatchPath))
	require.NoError(t, err)
	assert.False(t, exists, "no rule should be written when the legacy env var is set")

	exists, err = registryKeyExists(dnsPolicyConfigExemptLocalPath)
	require.NoError(t, err)
	assert.False(t, exists, "no exemption without a claimed root namespace")
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

// TestNRPTCleanupWithoutRuleCount verifies that rules written by a previous run
// are removed by a configurator that has no record of how many there are: an
// unclean exit loses the in-memory count and a clean disconnect deletes the
// persisted one, so cleanup cannot depend on either.
func TestNRPTCleanupWithoutRuleCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping registry integration test in short mode")
	}

	defer cleanupRegistryKeys(t)
	cleanupRegistryKeys(t)

	testIP := netip.MustParseAddr("100.64.0.1")

	// 75 domains produce two indexed rules, as the current layout does
	domains := make([]string, 75)
	for i := range domains {
		domains[i] = fmt.Sprintf(".domain%d.com", i+1)
	}

	previousRun := &registryConfigurator{}
	require.NoError(t, previousRun.addDNSMatchPolicy(domains, testIP))

	// the unsuffixed key an older version would have written
	require.NoError(t, previousRun.configureDNSPolicy(dnsPolicyConfigMatchPath, []string{".legacy.example.com"}, testIP))

	// a policy owned by someone else, which cleanup must not touch
	foreignPath := DNSPolicyConfigRoot + `\DnsPolicyConfigTestForeign`
	foreignKey, _, err := registry.CreateKey(registry.LOCAL_MACHINE, foreignPath, registry.SET_VALUE)
	require.NoError(t, err, "Should create foreign policy key")
	foreignKey.Close()
	defer func() {
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, foreignPath)
	}()

	require.Equal(t, 3, countNRPTRuleKeys(t), "Should have two indexed rules and the legacy one")

	// a configurator that never applied a DNS config, as one built after a
	// restart or from a shutdown state without a count is
	freshRun := &registryConfigurator{}
	require.NoError(t, freshRun.removeDNSMatchPolicies())

	assert.Equal(t, 0, countNRPTRuleKeys(t), "Should remove every rule left by the previous run")

	exists, err := registryKeyExists(foreignPath)
	require.NoError(t, err)
	assert.True(t, exists, "Should not remove a policy that is not ours")
}

func countNRPTRuleKeys(t *testing.T) int {
	t.Helper()

	names, err := listNRPTRuleKeys(DNSPolicyConfigRoot)
	require.NoError(t, err, "Should list NRPT rule keys")
	return len(names)
}

func cleanupRegistryKeys(*testing.T) {
	cfg := &registryConfigurator{}
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
	interfacePath := InterfaceConfigPath + `\` + testGUID
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
			assert.Equal(t, tc.expectedRuleCount, countNRPTRuleKeys(t),
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
