//go:build integration

package networkmap_pgsql

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/stretchr/testify/assert"
)

func TestGetDnsSettings(t *testing.T) {
	ctx := context.TODO()

	settings, err := conn(t, ctx).GetDnsSettings(ctx, "account-1")
	assert.NoError(t, err)
	assert.Equal(t, settings, nmdata.DNSSettings{
		DisabledManagementGroups: []string{"disabled-group-1", "disabled-group-2"},
	})

	settings, err = conn(t, ctx).GetDnsSettings(ctx, "account-2")
	assert.NoError(t, err)
	assert.Equal(t, settings, nmdata.DNSSettings{})
}
