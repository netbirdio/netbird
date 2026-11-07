package dns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/instance"
)

// T-DNS-U1: each installation's cleanup sees only its own NRPT keys.
func TestFilterNRPTRuleKeys(t *testing.T) {
	keys := []string{
		"NetBird-Match-0", "netbird-match-1", "NetBird-ExemptLocal",
		"NetBird_acme-Match-0", "NETBIRD_ACME-ExemptLocal",
		"NetBird_acme2-Match-0",
		"{4B6A1F3E-0000-0000-0000-000000000000}", "Corp-Rule", "NetBirdish",
	}
	prefixOf := func(name string) string {
		inst, err := instance.ForPlatform("windows", name)
		require.NoError(t, err)
		return inst.NRPTKeyPrefix()
	}

	assert.Equal(t, []string{"NetBird-Match-0", "netbird-match-1", "NetBird-ExemptLocal"},
		filterNRPTRuleKeys(keys, prefixOf("")), "default installation")
	assert.Equal(t, []string{"NetBird_acme-Match-0", "NETBIRD_ACME-ExemptLocal"},
		filterNRPTRuleKeys(keys, prefixOf("acme")), "acme")
	assert.Equal(t, []string{"NetBird_acme2-Match-0"},
		filterNRPTRuleKeys(keys, prefixOf("acme2")), "acme2")
	assert.Empty(t, filterNRPTRuleKeys(keys, prefixOf("other")), "an installation without keys")
}
