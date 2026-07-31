package networkmap_pgsql

import (
	"context"
	"testing"

	networkmap_pgsql "github.com/netbirdio/netbird/management/internals/network_map_db/pgsql"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/stretchr/testify/assert"
)

func TestXXX(t *testing.T) {
	ctx := context.TODO()

	s, err := networkmap_pgsql.NewPostgresqlStore(ctx, dsn)
	assert.NoError(t, err)

	_, err = s.Pool.Query(ctx,
		"insert into accounts (id) VALUES('account-id-1')")
	assert.NoError(t, err)

	_, err = s.Pool.Query(ctx,
		"insert into groups (id, account_id, name, resources, public_id) VALUES('test-group-id-1','account-id-1','test-group-1', '[{\"ID\":\"host-id-1\",\"Type\":\"host\"}]','public-id-1')")
	assert.NoError(t, err)
	_, err = s.Pool.Query(ctx,
		"insert into groups (id, account_id, name, resources, public_id) VALUES('test-group-id-2','account-id-1','test-group-2', '[{\"ID\":\"subnet-id-1\",\"Type\":\"subnet\"}, {\"ID\":\"host-id-2\",\"Type\":\"host\"}]','public-id-2')")
	assert.NoError(t, err)

	groups, err := s.GetGroups(ctx, "account-id-1")
	assert.NoError(t, err)
	assert.Contains(t,
		groups,
		nmdata.Group{Name: "test-group-1", PublicID: "public-id-1", Resources: []nmdata.Resource{{ID: "host-id-1", Type: "host"}}},
	)
	assert.Contains(t,
		groups,
		nmdata.Group{Name: "test-group-2", PublicID: "public-id-2", Resources: []nmdata.Resource{{ID: "subnet-id-1", Type: "subnet"}, {ID: "host-id-2", Type: "host"}}},
	)
}
