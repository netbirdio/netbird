package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestToProtoExposeServiceRequestCopiesAccessRestrictions(t *testing.T) {
	got, err := toProtoExposeServiceRequest(ExposeRequest{
		Port:     8080,
		Protocol: int(proto.ExposeProtocol_EXPOSE_HTTPS),
		AccessRestrictions: &ExposeAccessRestrictions{
			AllowedCIDRs:     []string{"35.231.147.226/32"},
			BlockedCIDRs:     []string{"198.51.100.0/24"},
			AllowedCountries: []string{"US"},
			BlockedCountries: []string{"RU"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, got.AccessRestrictions)
	assert.Equal(t, []string{"35.231.147.226/32"}, got.AccessRestrictions.AllowedCidrs)
	assert.Equal(t, []string{"198.51.100.0/24"}, got.AccessRestrictions.BlockedCidrs)
	assert.Equal(t, []string{"US"}, got.AccessRestrictions.AllowedCountries)
	assert.Equal(t, []string{"RU"}, got.AccessRestrictions.BlockedCountries)
}
