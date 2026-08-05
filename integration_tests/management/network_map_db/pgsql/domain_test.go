package networkmap_pgsql

import (
	"context"
	"database/sql"
	"testing"

	networkmap_pgsql "github.com/netbirdio/netbird/management/internals/network_map_db/pgsql"
	"github.com/stretchr/testify/assert"
)

func TestGetDomains(t *testing.T) {
	ctx := context.TODO()

	_, err := pgstore.Pool.Exec(ctx,
		`insert into domains (id, account_id, domain, target_cluster)
		VALUES('domain-1','account-1','test-1.com','target-1.cluster.local')`)
	assert.NoError(t, err)
	_, err = pgstore.Pool.Exec(ctx,
		`insert into domains (id, account_id, domain, target_cluster)
		VALUES('domain-2','account-1','test-2.com','target-2.cluster.local')`)
	assert.NoError(t, err)
	_, err = pgstore.Pool.Exec(ctx,
		`insert into domains (id, account_id, domain, target_cluster)
		VALUES('domain-3','account-1',null,null)`)
	assert.NoError(t, err)

	domains, err := pgstore.GetDomains(ctx, "account-1")
	assert.NoError(t, err)
	assert.Len(t, domains, 2)

	assert.Contains(t, domains, networkmap_pgsql.Domain{
		Domain:        sql.NullString{String: "test-1.com", Valid: true},
		TargetCluster: sql.NullString{String: "target-1.cluster.local", Valid: true},
	})
	assert.Contains(t, domains, networkmap_pgsql.Domain{
		Domain:        sql.NullString{String: "test-2.com", Valid: true},
		TargetCluster: sql.NullString{String: "target-2.cluster.local", Valid: true},
	})
}
