//go:build integration

package networkmap_pgsql

import (
	"context"
	"net/netip"
	"testing"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/stretchr/testify/assert"
)

func TestGetNetworkResources(t *testing.T) {
	ctx := context.TODO()

	execQuery(t, ctx,
		`insert into network_resources (id, account_id, network_id, public_id, name, description, type, domain, prefix, enabled)
		VALUES('net-resource-1','account-1','network-1','net-resource-public-1','network-resource-1','network-resource-1','subnet','','"10.0.0.0/16"',TRUE)`)
	execQuery(t, ctx,
		`insert into network_resources (id, account_id, network_id, public_id, name, description, type, domain, prefix, enabled)
		VALUES('net-resource-2','account-1','network-2','net-resource-public-2','network-resource-2','network-resource-2','domain','test.com','',TRUE)`)
	execQuery(t, ctx,
		`insert into network_resources (id, account_id, network_id, public_id, name, description, type, domain, prefix, enabled)
		VALUES('net-resource-3','account-1','network-3','net-resource-public-3','network-resource-3','network-resource-3','host','','"10.0.0.1/32"',TRUE)`)

	resources, err := conn(t, ctx).GetNetworkResources(ctx, "account-1")
	assert.NoError(t, err)

	assert.Contains(t, resources, nmdata.NetworkResource{
		ID:          "net-resource-1",
		AccountID:   "account-1",
		NetworkID:   "network-1",
		PublicID:    "net-resource-public-1",
		Name:        "network-resource-1",
		Description: "network-resource-1",
		Type:        "subnet",
		Domain:      "",
		Prefix:      netip.MustParsePrefix("10.0.0.0/16"),
		Enabled:     true,
	})
	assert.Contains(t, resources, nmdata.NetworkResource{
		ID:          "net-resource-2",
		AccountID:   "account-1",
		NetworkID:   "network-2",
		PublicID:    "net-resource-public-2",
		Name:        "network-resource-2",
		Description: "network-resource-2",
		Type:        "domain",
		Domain:      "test.com",
		Enabled:     true,
	})
	assert.Contains(t, resources, nmdata.NetworkResource{
		ID:          "net-resource-3",
		AccountID:   "account-1",
		NetworkID:   "network-3",
		PublicID:    "net-resource-public-3",
		Name:        "network-resource-3",
		Description: "network-resource-3",
		Type:        "host",
		Domain:      "",
		Prefix:      netip.MustParsePrefix("10.0.0.1/32"),
		Enabled:     true,
	})
}
