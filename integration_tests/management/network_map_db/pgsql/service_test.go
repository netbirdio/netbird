package networkmap_pgsql

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"

	networkmap_pgsql "github.com/netbirdio/netbird/management/internals/network_map_db/pgsql"
)

func TestGetPrivateServicesViaPgxConnection(t *testing.T) {
	ctx := context.TODO()

	_, err := pgstore.Pool.Exec(ctx,
		`insert into services (id, account_id, enabled, private, access_groups, proxy_cluster, domain)
		 values('service-1','account-1',true,true,'["group-one-resource-id"]','test-1.com','test-2.com')`)
	assert.NoError(t, err)
	_, err = pgstore.Pool.Exec(ctx,
		`insert into services (id, account_id, enabled, private, access_groups, proxy_cluster, domain)
		 values('service-2','account-1',true,true,'["group-one-resource-id","group-two-resources-id"]','test-3.com','test-4.com')`)
	assert.NoError(t, err)
	_, err = pgstore.Pool.Exec(ctx,
		`insert into services (id, account_id, enabled, private, access_groups, proxy_cluster, domain)
		 values('service-3','account-1',null,null,null,null,null)`)
	assert.NoError(t, err)

	services, err := networkmap_pgsql.GetPrivateServicesViaPgxConnection(ctx, conn(t, ctx), "account-1")
	assert.NoError(t, err)
	assert.Contains(t, services, networkmap_pgsql.Service{
		Enabled:      sql.NullBool{Bool: true, Valid: true},
		Private:      sql.NullBool{Bool: true, Valid: true},
		AccessGroups: []string{"group-one-resource-id"},
		ProxyCluster: sql.NullString{String: "test-1.com", Valid: true},
		Domain:       sql.NullString{String: "test-2.com", Valid: true},
	})
	assert.Contains(t, services, networkmap_pgsql.Service{
		Enabled:      sql.NullBool{Bool: true, Valid: true},
		Private:      sql.NullBool{Bool: true, Valid: true},
		AccessGroups: []string{"group-one-resource-id", "group-two-resources-id"},
		ProxyCluster: sql.NullString{String: "test-3.com", Valid: true},
		Domain:       sql.NullString{String: "test-4.com", Valid: true},
	})
	assert.Contains(t, services, networkmap_pgsql.Service{
		Enabled:      sql.NullBool{Bool: false, Valid: false},
		Private:      sql.NullBool{Bool: false, Valid: false},
		AccessGroups: []string{},
		ProxyCluster: sql.NullString{String: "", Valid: false},
		Domain:       sql.NullString{String: "", Valid: false},
	})
}

func TestGetProxyTargetedDomainResourceIDsViaPgxConnection(t *testing.T) {
	ctx := context.TODO()

	_, err := pgstore.Pool.Exec(ctx,
		`insert into services (id, account_id, enabled, terminated)
		 values('service-4','account-1',true,false)`)
	assert.NoError(t, err)
	_, err = pgstore.Pool.Exec(ctx,
		`insert into targets (target_id, account_id, service_id, enabled, target_type)
		 values('target-1','account-1','service-4',true,'domain')`)
	assert.NoError(t, err)
	// id shouldn't be returned as the taget_type is not "domain"
	_, err = pgstore.Pool.Exec(ctx,
		`insert into targets (target_id, account_id, service_id, enabled, target_type)
		 values('target-2','account-1','service-4',true,'cluster')`)
	assert.NoError(t, err)
	// id shouldn't be included as the target is disabled
	_, err = pgstore.Pool.Exec(ctx,
		`insert into targets (target_id, account_id, service_id, enabled, target_type)
		 values('target-3','account-1','service-4',false,'domain')`)
	assert.NoError(t, err)
	// id shouldn't be included as the service is disabled
	_, err = pgstore.Pool.Exec(ctx,
		`insert into services (id, account_id, enabled, terminated)
		 values('service-5','account-1',false,false)`)
	assert.NoError(t, err)
	_, err = pgstore.Pool.Exec(ctx,
		`insert into targets (target_id, account_id, service_id, enabled, target_type)
		 values('target-4','account-1','service-5',false,'domain')`)
	assert.NoError(t, err)
	// id shouldn't be included as the service is terminated (explicitly)
	_, err = pgstore.Pool.Exec(ctx,
		`insert into services (id, account_id, enabled, terminated)
		 values('service-6','account-1',true,true)`)
	assert.NoError(t, err)
	_, err = pgstore.Pool.Exec(ctx,
		`insert into targets (target_id, account_id, service_id, enabled, target_type)
		 values('target-5','account-1','service-6',true,'domain')`)
	assert.NoError(t, err)
	// id shouldn't be included as the service is terminated (implicitly)
	_, err = pgstore.Pool.Exec(ctx,
		`insert into services (id, account_id, enabled, terminated)
		 values('service-7','account-1',true,null)`)
	assert.NoError(t, err)
	_, err = pgstore.Pool.Exec(ctx,
		`insert into targets (target_id, account_id, service_id, enabled, target_type)
		 values('target-6','account-1','service-7',true,'domain')`)
	assert.NoError(t, err)
	_, err = pgstore.Pool.Exec(ctx,
		`insert into services (id, account_id, enabled, terminated)
		 values('service-8','account-1',true,false)`)
	assert.NoError(t, err)
	_, err = pgstore.Pool.Exec(ctx,
		`insert into targets (target_id, account_id, service_id, enabled, target_type)
		 values('target-7','account-1','service-8',true,'domain')`)
	assert.NoError(t, err)
	// id shouldn't be returned as the taget_id is null
	_, err = pgstore.Pool.Exec(ctx,
		`insert into targets (target_id, account_id, service_id, enabled, target_type)
		 values(null,'account-1','service-4',true,'cluster')`)
	assert.NoError(t, err)

	servtargetedDomains, err := networkmap_pgsql.GetProxyTargetedDomainResourceIDsViaPgxConnection(ctx, conn(t, ctx), "account-1")
	assert.NoError(t, err)
	assert.Equal(t, servtargetedDomains, map[string]struct{}{
		"target-1": {},
		"target-6": {},
		"target-7": {},
	})
}
