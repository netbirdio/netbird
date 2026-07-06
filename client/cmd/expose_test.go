package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeIPAndCIDRFlags(t *testing.T) {
	got, err := mergeIPAndCIDRFlags("allow", []string{"35.231.147.226", "2001:db8::1"}, []string{"203.0.113.0/24"})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"35.231.147.226/32",
		"2001:db8::1/128",
		"203.0.113.0/24",
	}, got)
}

func TestMergeIPAndCIDRFlagsRejectsInvalidValues(t *testing.T) {
	_, err := mergeIPAndCIDRFlags("allow", []string{"not-an-ip"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--allow-ip")

	_, err = mergeIPAndCIDRFlags("block", nil, []string{"203.0.113.1/24"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has host bits set")
}

func TestNormalizeExposeCountryCodes(t *testing.T) {
	got, err := normalizeExposeCountryCodes("allow-country", []string{"us", " DE "})
	require.NoError(t, err)
	assert.Equal(t, []string{"US", "DE"}, got)

	_, err = normalizeExposeCountryCodes("block-country", []string{"USA"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "2-letter")

	_, err = normalizeExposeCountryCodes("allow-country", []string{"12"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "2-letter")
}

func TestBuildExposeAccessRestrictions(t *testing.T) {
	oldAllowedIPs := exposeAllowedIPs
	oldBlockedIPs := exposeBlockedIPs
	oldAllowedCIDRs := exposeAllowedCIDRs
	oldBlockedCIDRs := exposeBlockedCIDRs
	oldAllowedCodes := exposeAllowedCodes
	oldBlockedCodes := exposeBlockedCodes
	defer func() {
		exposeAllowedIPs = oldAllowedIPs
		exposeBlockedIPs = oldBlockedIPs
		exposeAllowedCIDRs = oldAllowedCIDRs
		exposeBlockedCIDRs = oldBlockedCIDRs
		exposeAllowedCodes = oldAllowedCodes
		exposeBlockedCodes = oldBlockedCodes
	}()

	exposeAllowedIPs = []string{"35.231.147.226"}
	exposeBlockedIPs = []string{"198.51.100.10"}
	exposeAllowedCIDRs = []string{"203.0.113.0/24"}
	exposeBlockedCIDRs = []string{"192.0.2.0/24"}
	exposeAllowedCodes = []string{"us"}
	exposeBlockedCodes = []string{"ru"}

	got, err := buildExposeAccessRestrictions()
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, []string{"35.231.147.226/32", "203.0.113.0/24"}, got.AllowedCidrs)
	assert.Equal(t, []string{"198.51.100.10/32", "192.0.2.0/24"}, got.BlockedCidrs)
	assert.Equal(t, []string{"US"}, got.AllowedCountries)
	assert.Equal(t, []string{"RU"}, got.BlockedCountries)
}
