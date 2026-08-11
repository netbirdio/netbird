//go:build integration

package networkmap_pgsql

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
)

func TestGetPrivateServices(t *testing.T) {
	ctx := context.TODO()

	execQuery(t, ctx,
		`insert into services (id, account_id, enabled, private, access_groups, proxy_cluster, domain)
		 values('service-1','account-1',true,true,'["group-one-resource-id"]','test-1.com','test-2.com')`)
	execQuery(t, ctx,
		`insert into services (id, account_id, enabled, private, access_groups, proxy_cluster, domain)
		 values('service-2','account-1',true,true,'["group-one-resource-id","group-two-resources-id"]','test-3.com','test-4.com')`)
	execQuery(t, ctx,
		`insert into services (id, account_id, enabled, private, access_groups, proxy_cluster, domain)
		 values('service-3','account-1',null,null,null,null,null)`)

	services, err := conn(t, ctx).GetPrivateServices(ctx, "account-1")
	assert.NoError(t, err)
	assert.Contains(t, services, networkmapdb.Service{
		Enabled:      sql.NullBool{Bool: true, Valid: true},
		Private:      sql.NullBool{Bool: true, Valid: true},
		AccessGroups: []string{"group-one-resource-id"},
		ProxyCluster: sql.NullString{String: "test-1.com", Valid: true},
		Domain:       sql.NullString{String: "test-2.com", Valid: true},
	})
	assert.Contains(t, services, networkmapdb.Service{
		Enabled:      sql.NullBool{Bool: true, Valid: true},
		Private:      sql.NullBool{Bool: true, Valid: true},
		AccessGroups: []string{"group-one-resource-id", "group-two-resources-id"},
		ProxyCluster: sql.NullString{String: "test-3.com", Valid: true},
		Domain:       sql.NullString{String: "test-4.com", Valid: true},
	})
	assert.Contains(t, services, networkmapdb.Service{
		Enabled:      sql.NullBool{Bool: false, Valid: false},
		Private:      sql.NullBool{Bool: false, Valid: false},
		AccessGroups: []string{},
		ProxyCluster: sql.NullString{String: "", Valid: false},
		Domain:       sql.NullString{String: "", Valid: false},
	})
}

func TestGetProxyTargetedDomainResourceIDs(t *testing.T) {
	ctx := context.TODO()

	execQuery(t, ctx,
		`insert into services (id, account_id, enabled, terminated)
		 values('service-4','account-1',true,false)`)
	execQuery(t, ctx,
		`insert into targets (target_id, account_id, service_id, enabled, target_type)
		 values('target-1','account-1','service-4',true,'domain')`)
	// id shouldn't be returned as the taget_type is not "domain"
	execQuery(t, ctx,
		`insert into targets (target_id, account_id, service_id, enabled, target_type)
		 values('target-2','account-1','service-4',true,'cluster')`)
	// id shouldn't be included as the target is disabled
	execQuery(t, ctx,
		`insert into targets (target_id, account_id, service_id, enabled, target_type)
		 values('target-3','account-1','service-4',false,'domain')`)
	// id shouldn't be included as the service is disabled
	execQuery(t, ctx,
		`insert into services (id, account_id, enabled, terminated)
		 values('service-5','account-1',false,false)`)
	execQuery(t, ctx,
		`insert into targets (target_id, account_id, service_id, enabled, target_type)
		 values('target-4','account-1','service-5',false,'domain')`)
	// id shouldn't be included as the service is terminated (explicitly)
	execQuery(t, ctx,
		`insert into services (id, account_id, enabled, terminated)
		 values('service-6','account-1',true,true)`)
	execQuery(t, ctx,
		`insert into targets (target_id, account_id, service_id, enabled, target_type)
		 values('target-5','account-1','service-6',true,'domain')`)
	// id shouldn't be included as the service is terminated (implicitly)
	execQuery(t, ctx,
		`insert into services (id, account_id, enabled, terminated)
		 values('service-7','account-1',true,null)`)
	execQuery(t, ctx,
		`insert into targets (target_id, account_id, service_id, enabled, target_type)
		 values('target-6','account-1','service-7',true,'domain')`)
	execQuery(t, ctx,
		`insert into services (id, account_id, enabled, terminated)
		 values('service-8','account-1',true,false)`)
	execQuery(t, ctx,
		`insert into targets (target_id, account_id, service_id, enabled, target_type)
		 values('target-7','account-1','service-8',true,'domain')`)
	// id shouldn't be returned as the taget_id is null
	execQuery(t, ctx,
		`insert into targets (target_id, account_id, service_id, enabled, target_type)
		 values(null,'account-1','service-4',true,'cluster')`)

	servtargetedDomains, err := conn(t, ctx).GetProxyTargetedDomainResourceIDs(ctx, "account-1")
	assert.NoError(t, err)
	assert.Equal(t, servtargetedDomains, map[string]struct{}{
		"target-1": {},
		"target-6": {},
		"target-7": {},
	})
}
