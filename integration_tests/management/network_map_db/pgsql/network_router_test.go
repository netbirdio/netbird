package networkmap_pgsql

import (
	"context"
	"testing"

	networkmap_pgsql "github.com/netbirdio/netbird/management/internals/network_map_db/pgsql"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/stretchr/testify/assert"
)

func TestGetNetworkRouters(t *testing.T) {
	ctx := context.TODO()

	s, err := networkmap_pgsql.NewPostgresqlStore(ctx, dsn)
	assert.NoError(t, err)

	_, err = s.Pool.Exec(ctx,
		`insert into network_routers (id, account_id, public_id, peer, network_id, masquerade, metric, enabled, peer_groups)
		VALUES('test-nr-id-1','account-1','public-id-1','peer-id-1','network-id-1',TRUE,999,TRUE,'["group-one-resource-id"]')`)
	assert.NoError(t, err)
	_, err = s.Pool.Exec(ctx,
		`insert into network_routers (id, account_id, public_id, peer, network_id, masquerade, metric, enabled, peer_groups)
		VALUES('test-nr-id-2','account-1','public-id-2','','network-id-2',TRUE,333,TRUE,'["group-two-resources-id","group-no-resources-id"]')`)
	assert.NoError(t, err)

	routers, err := s.GetNetworkRouters(ctx, "account-1")
	assert.NoError(t, err)
	assert.NotEmpty(t, routers)

	assert.Equal(t, routers["network-id-1"],
		map[string]*nmdata.NetworkRouter{"peer-id-1": {PublicID: "public-id-1", Masquerade: true, Metric: 999, Enabled: true, PeerGroups: []string{"group-one-resource-id"}}})
	assert.Equal(t, routers["network-id-2"],
		map[string]*nmdata.NetworkRouter{
			"peer-id-2": {PublicID: "public-id-2", Masquerade: true, Metric: 333, Enabled: true, PeerGroups: []string{"group-two-resources-id", "group-no-resources-id"}},
			"peer-id-3": {PublicID: "public-id-2", Masquerade: true, Metric: 333, Enabled: true, PeerGroups: []string{"group-two-resources-id", "group-no-resources-id"}}})
}
