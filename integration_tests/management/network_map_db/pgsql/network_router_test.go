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
		"insert into network_routers (id, account_id, public_id, peer, network_id, masquerade, metric, enabled) VALUES('test-nr-id-1',$1,'public-id-1','peer-id-1','network-id-1',TRUE,999,TRUE)", acctId)
	_, err = s.Pool.Query(ctx,
		"insert into network_routers (id, account_id, public_id, peer, network_id, masquerade, metric, enabled) VALUES('test-nr-id-2',$1,'public-id-2','peer-id-2','network-id-2',TRUE,333,TRUE)", acctId)
	_, err = s.Pool.Query(ctx,
		"insert into group_peers (peer_id, group_id) VALUES('peer-id-1','test-group-id-1')")
	assert.NoError(t, err)
	_, err = s.Pool.Query(ctx,
		"insert into group_peers (peer_id, group_id) VALUES('peer-id-2','test-group-id-2')")
	assert.NoError(t, err)
	_, err = s.Pool.Query(ctx,
		"insert into group_peers (peer_id, group_id) VALUES('peer-id-3','test-group-id-2')")
	assert.NoError(t, err)

	groups, resourceToGroupIdx, err := s.GetGroups(ctx, acctId)
	assert.NoError(t, err)
	assert.Contains(t,
		groups,
		nmdata.Group{ID: "test-group-id-1", Name: "test-group-1", PublicID: "public-id-1", Resources: []nmdata.Resource{{ID: "host-id-1", Type: "host"}}, Peers: []string{"peer-id-1"}},
	)
	assert.NotNil(t, resourceToGroupIdx["host-id-1"]["test-group-id-1"])
	assert.Contains(t,
		groups,
		nmdata.Group{ID: "test-group-id-2", Name: "test-group-2", PublicID: "public-id-2",
			Resources: []nmdata.Resource{{ID: "subnet-id-1", Type: "subnet"}, {ID: "host-id-2", Type: "host"}},
			Peers:     []string{"peer-id-2", "peer-id-3"}},
	)
	assert.NotNil(t, resourceToGroupIdx["host-id-2"]["test-group-id-2"])
	assert.NotNil(t, resourceToGroupIdx["subnet-id-1"]["test-group-id-2"])
}
