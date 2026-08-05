package networkmap_pgsql

import (
	"context"
	"testing"

	networkmap_pgsql "github.com/netbirdio/netbird/management/internals/network_map_db/pgsql"
	"github.com/stretchr/testify/assert"
)

func TestGetNetworks(t *testing.T) {
	ctx := context.TODO()

	_, err := pgstore.Pool.Query(ctx,
		`insert into networks (id, account_id, public_id) VALUES('network-1','account-1','network-1-public')`)
	assert.NoError(t, err)
	_, err = pgstore.Pool.Query(ctx,
		`insert into networks (id, account_id, public_id) VALUES('network-2','account-1','network-2-public')`)
	assert.NoError(t, err)

	networksIdx, err := networkmap_pgsql.GetNetworkXIDToPublicIdMapViaPgxConnection(ctx, conn(t, ctx), "account-1")
	assert.NoError(t, err)
	assert.Equal(t, networksIdx, map[string]string{
		"network-1": "network-1-public",
		"network-2": "network-2-public",
	})
}
