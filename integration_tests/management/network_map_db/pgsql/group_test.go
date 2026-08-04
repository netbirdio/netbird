package networkmap_pgsql

import (
	"context"
	"testing"

	networkmap_pgsql "github.com/netbirdio/netbird/management/internals/network_map_db/pgsql"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
)

func TestGetGroups(t *testing.T) {
	ctx := context.TODO()

	s, err := networkmap_pgsql.NewPostgresqlStore(ctx, dsn)
	assert.NoError(t, err)

	acctId := xid.New().String()

	_, err = s.Pool.Query(ctx,
		"insert into accounts (id) VALUES($1)", acctId)
	assert.NoError(t, err)

	_, err = s.Pool.Query(ctx,
		"insert into groups (id, account_id, name, resources, public_id) VALUES('g1-test-group-id-1',$1,'test-group-1', '[{\"ID\":\"host-id-1\",\"Type\":\"host\"}]','public-id-1')", acctId)
	assert.NoError(t, err)
	_, err = s.Pool.Query(ctx,
		"insert into groups (id, account_id, name, resources, public_id) VALUES('g1-test-group-id-2',$1,'test-group-2', '[{\"ID\":\"subnet-id-1\",\"Type\":\"subnet\"}, {\"ID\":\"host-id-2\",\"Type\":\"host\"}]','public-id-2')", acctId)
	assert.NoError(t, err)
	_, err = s.Pool.Query(ctx,
		"insert into group_peers (peer_id, group_id) VALUES('peer-id-1','g1-test-group-id-1')")
	assert.NoError(t, err)
	_, err = s.Pool.Query(ctx,
		"insert into group_peers (peer_id, group_id) VALUES('peer-id-2','g1-test-group-id-2')")
	assert.NoError(t, err)
	_, err = s.Pool.Query(ctx,
		"insert into group_peers (peer_id, group_id) VALUES('peer-id-3','g1-test-group-id-2')")
	assert.NoError(t, err)

	groups, resourceToGroupIdx, err := s.GetGroups(ctx, acctId)
	assert.NoError(t, err)
	assert.Contains(t,
		groups,
		nmdata.Group{ID: "g1-test-group-id-1", Name: "test-group-1", PublicID: "public-id-1", Resources: []nmdata.Resource{{ID: "host-id-1", Type: "host"}}, Peers: []string{"peer-id-1"}},
	)
	assert.NotNil(t, resourceToGroupIdx["host-id-1"]["g1-test-group-id-1"])
	assert.Contains(t,
		groups,
		nmdata.Group{ID: "g1-test-group-id-2", Name: "test-group-2", PublicID: "public-id-2",
			Resources: []nmdata.Resource{{ID: "subnet-id-1", Type: "subnet"}, {ID: "host-id-2", Type: "host"}},
			Peers:     []string{"peer-id-2", "peer-id-3"}},
	)
	assert.NotNil(t, resourceToGroupIdx["host-id-2"]["g1-test-group-id-2"])
	assert.NotNil(t, resourceToGroupIdx["subnet-id-1"]["g1-test-group-id-2"])
}

// Verify handling of empty fields in groups table
// Verify that group's PublicID gets populated on retrieval
// TODO (dmitri) PublicID should not be populated with delta updates,
// which require stable PublicIDs
func TestGetGroupsWithoutExpectedFields(t *testing.T) {
	ctx := context.TODO()

	s, err := networkmap_pgsql.NewPostgresqlStore(ctx, dsn)
	assert.NoError(t, err)

	acctId := xid.New().String()

	_, err = s.Pool.Query(ctx,
		"insert into accounts (id) VALUES($1)", acctId)
	assert.NoError(t, err)

	_, err = s.Pool.Query(ctx,
		"insert into groups (id, account_id) VALUES('g2-test-group-id-1',$1)", acctId)
	assert.NoError(t, err)

	groups, _, err := s.GetGroups(ctx, acctId)
	assert.NoError(t, err)
	assert.Len(t, groups, 1)
	assert.NotEmpty(t, groups[0].PublicID)
}
