//go:build integration

package networkmap_pgsql

import (
	"context"
	"database/sql"
	"testing"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/stretchr/testify/assert"
)

func TestGetDomains(t *testing.T) {
	ctx := context.TODO()

	execQuery(t, ctx,
		`insert into domains (id, account_id, domain, target_cluster)
		VALUES('domain-1','account-1','test-1.com','target-1.cluster.local')`)
	execQuery(t, ctx,
		`insert into domains (id, account_id, domain, target_cluster)
		VALUES('domain-2','account-1','test-2.com','target-2.cluster.local')`)
	execQuery(t, ctx,
		`insert into domains (id, account_id, domain, target_cluster)
		VALUES('domain-3','account-1',null,null)`)

	domains, err := conn(t, ctx).GetDomains(ctx, "account-1")
	assert.NoError(t, err)
	assert.Len(t, domains, 2)

	assert.Contains(t, domains, networkmapdb.Domain{
		Domain:        sql.NullString{String: "test-1.com", Valid: true},
		TargetCluster: sql.NullString{String: "target-1.cluster.local", Valid: true},
	})
	assert.Contains(t, domains, networkmapdb.Domain{
		Domain:        sql.NullString{String: "test-2.com", Valid: true},
		TargetCluster: sql.NullString{String: "target-2.cluster.local", Valid: true},
	})
}
