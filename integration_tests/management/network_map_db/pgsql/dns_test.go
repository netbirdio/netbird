//go:build integration

package networkmap_pgsql

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	networkmap_pgsql "github.com/netbirdio/netbird/management/internals/network_map_db/pgsql"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/stretchr/testify/assert"
)

func TestGetAppliedZoneCandidatesViaPgxConnection(t *testing.T) {
	ctx := context.TODO()

	execQuery(t, ctx,
		`insert into zones (id, account_id, domain, enable_search_domain, distribution_groups)
		VALUES('zone-1','account-1','test-1.com',true,'["group-one-resource-id"]')`)
	execQuery(t, ctx,
		`insert into zones (id, account_id, domain, enable_search_domain, distribution_groups)
		VALUES('zone-2','account-1','test-2.com',false,'["group-two-resources-id"]')`)
	execQuery(t, ctx,
		`insert into records (id, account_id, zone_id, name, type, ttl, content)
		VALUES('record-1','account-1','zone-1','test.test-1.com','A',1800,'1.1.1.1')`)
	execQuery(t, ctx,
		`insert into records (id, account_id, zone_id, name, type, ttl, content)
		VALUES('record-2','account-1','zone-1','test2.test-1.com','A',1800,'1.1.1.2')`)
	execQuery(t, ctx,
		`insert into records (id, account_id, zone_id, name, type, ttl, content)
		VALUES('record-3','account-1','zone-1','test3.test-1.com','CNAME',1800,'test4.test-1.com')`)
	execQuery(t, ctx,
		`insert into records (id, account_id, zone_id, name, type, ttl, content)
		VALUES('record-4','account-1','zone-2','test2.test-2.com','CNAME',1800,'test3.test-2.com')`)

	zoneCandidates, err := networkmap_pgsql.GetAppliedZoneCandidatesViaPgxConnection(ctx, conn(t, ctx), "account-1")
	assert.NoError(t, err)

	assert.Contains(t, zoneCandidates, networkmap.AppliedZoneCandidate{
		DistributionGroups: []string{"group-one-resource-id"},
		Zone: nmdata.CustomZone{
			Domain:               "test-1.com",
			SearchDomainDisabled: false,
			Records: []nmdata.SimpleRecord{
				{Name: "test.test-1.com", Type: int(dns.TypeA), Class: "IN", TTL: 1800, RData: "1.1.1.1"},
				{Name: "test2.test-1.com", Type: int(dns.TypeA), Class: "IN", TTL: 1800, RData: "1.1.1.2"},
				{Name: "test3.test-1.com", Type: int(dns.TypeCNAME), Class: "IN", TTL: 1800, RData: "test4.test-1.com."},
			},
		},
	})
	assert.Contains(t, zoneCandidates, networkmap.AppliedZoneCandidate{
		DistributionGroups: []string{"group-two-resources-id"},
		Zone: nmdata.CustomZone{
			Domain:               "test-2.com",
			SearchDomainDisabled: true,
			Records: []nmdata.SimpleRecord{
				{Name: "test2.test-2.com", Type: int(dns.TypeCNAME), Class: "IN", TTL: 1800, RData: "test3.test-2.com."},
			},
		},
	})
}
