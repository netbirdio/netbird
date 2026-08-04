package networkmap_pgsql

import (
	"context"
	"testing"

	networkmap_pgsql "github.com/netbirdio/netbird/management/internals/network_map_db/pgsql"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
)

func TestGetNetworkRouters(t *testing.T) {
	ctx := context.TODO()

	s, err := networkmap_pgsql.NewPostgresqlStore(ctx, dsn)
	assert.NoError(t, err)

	acctId := xid.New().String()

	_, err = s.Pool.Query(ctx,
		"insert into accounts (id) VALUES($1)", acctId)
	assert.NoError(t, err)

	_, err = s.Pool.Query(ctx,
		`insert into network_routers (id, account_id, public_id, peer, network_id, masquerade, metric, enabled, peer_groups)
		VALUES('test-nr-id-1',$1,'public-id-1','peer-id-1','network-id-1',TRUE,999,TRUE,'["nr-test-group-id-1"]')`,
		acctId)
	_, err = s.Pool.Query(ctx,
		`insert into network_routers (id, account_id, public_id, peer, network_id, masquerade, metric, enabled, peer_groups)
		VALUES('test-nr-id-2',$1,'public-id-2','','network-id-2',TRUE,333,TRUE,'["nr-test-group-id-1","nr-test-group-id-2"]')`, acctId)
	_, err = s.Pool.Query(ctx,
		"insert into groups (id, account_id, public_id) VALUES('nr-test-group-id-1',$1,'public-id-1')", acctId)
	_, err = s.Pool.Query(ctx,
		"insert into groups (id, account_id, public_id) VALUES('nr-test-group-id-2',$1,'public-id-2')", acctId)
	_, err = s.Pool.Query(ctx,
		"insert into group_peers (peer_id, group_id) VALUES('peer-id-11','nr-test-group-id-1')")
	assert.NoError(t, err)
	_, err = s.Pool.Query(ctx,
		"insert into group_peers (peer_id, group_id) VALUES('peer-id-22','nr-test-group-id-2')")
	assert.NoError(t, err)
	_, err = s.Pool.Query(ctx,
		"insert into group_peers (peer_id, group_id) VALUES('peer-id-33','nr-test-group-id-2')")
	assert.NoError(t, err)

	routers, err := s.GetNetworkRouters(ctx, acctId)
	assert.NoError(t, err)
	assert.NotEmpty(t, routers)

	assert.Equal(t, routers["network-id-1"],
		map[string]*nmdata.NetworkRouter{"peer-id-1": {PublicID: "public-id-1", Masquerade: true, Metric: 999, Enabled: true, PeerGroups: []string{"peer-id-11"}}})
	assert.Equal(t, routers["network-id-2"],
		map[string]*nmdata.NetworkRouter{
			"peer-id-11": {PublicID: "public-id-2", Masquerade: true, Metric: 333, Enabled: true, PeerGroups: []string{"peer-id-11", "peer-id-22", "peer-id-33"}},
			"peer-id-22": {PublicID: "public-id-2", Masquerade: true, Metric: 333, Enabled: true, PeerGroups: []string{"peer-id-11", "peer-id-22", "peer-id-33"}},
			"peer-id-33": {PublicID: "public-id-2", Masquerade: true, Metric: 333, Enabled: true, PeerGroups: []string{"peer-id-11", "peer-id-22", "peer-id-33"}}})
}
