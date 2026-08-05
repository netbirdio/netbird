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

	groups, resourceToGroupIdx, err := s.GetGroups(ctx, "account-1")
	assert.NoError(t, err)
	assert.Contains(t,
		groups,
		nmdata.Group{ID: "group-one-resource-id", Name: "group-1-name", PublicID: "group-one-resource-id-public", Resources: []nmdata.Resource{{ID: "host-id-1", Type: "host"}}, Peers: []string{"peer-id-1"}},
	)
	assert.NotNil(t, resourceToGroupIdx["host-id-1"]["group-one-resource-id"])
	assert.Contains(t,
		groups,
		nmdata.Group{ID: "group-two-resources-id", Name: "group-2-name", PublicID: "group-two-resources-id-public",
			Resources: []nmdata.Resource{{ID: "subnet-id-1", Type: "subnet"}, {ID: "host-id-2", Type: "host"}},
			Peers:     []string{"peer-id-2", "peer-id-3"}},
	)
	assert.NotNil(t, resourceToGroupIdx["host-id-2"]["group-two-resources-id"])
	assert.NotNil(t, resourceToGroupIdx["subnet-id-1"]["group-two-resources-id"])
	assert.Contains(t,
		groups,
		nmdata.Group{ID: "group-no-resources-id", Name: "group-3-name", PublicID: "group-no-resources-id-public"})
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

	_, err = s.Pool.Exec(ctx,
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
