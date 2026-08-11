//go:build integration

package networkmap_pgsql

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetNetworks(t *testing.T) {
	ctx := context.TODO()

	execQuery(t, ctx,
		`insert into networks (id, account_id, public_id) VALUES('network-1','account-1','network-1-public')`)
	execQuery(t, ctx,
		`insert into networks (id, account_id, public_id) VALUES('network-2','account-1','network-2-public')`)

	networksIdx, err := conn(t, ctx).GetNetworkXIDToPublicIdMap(ctx, "account-1")
	assert.NoError(t, err)
	assert.Equal(t, networksIdx, map[string]string{
		"network-1": "network-1-public",
		"network-2": "network-2-public",
	})
}
