//go:build integration

package networkmap_pgsql

import (
	"context"
	"net/netip"
	"testing"

	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/stretchr/testify/assert"
)

func TestGetRoutes(t *testing.T) {
	ctx := context.TODO()

	execQuery(t, ctx,
		`insert into routes (id, account_id, public_id, network, domains, keep_route, net_id, description,
	                         peer, peer_groups, network_type, masquerade, metric, enabled, 
	                         groups, access_control_groups, skip_auto_apply)
		VALUES('route-1','account-1','route-1-public','"172.0.0.0/16"','["test-1.com"]',true,'route-1-net-id','route-1',
		        'peer-id-1','["group-one-resource-id"]',1,true,9999,true,
				'["group-one-resource-id"]','["group-one-resource-id"]',false)`)
	execQuery(t, ctx,
		`insert into routes (id, account_id, public_id, network, domains, keep_route, net_id, description,
	                         peer, peer_groups, network_type, masquerade, metric, enabled, 
	                         groups, access_control_groups, skip_auto_apply)
		VALUES('route-2','account-1','route-2-public','"172.10.0.0/16"','["test-1.com","test-2.com"]',true,'route-2-net-id','route-2',
		        'peer-id-2','["group-two-resources-id"]',1,true,9999,true,
				'["group-two-resources-id"]','["group-two-resources-id"]',false)`)
	execQuery(t, ctx,
		`insert into routes (id, account_id, public_id, network, domains, keep_route, net_id, description,
	                         peer, peer_groups, network_type, masquerade, metric, enabled, 
	                         groups, access_control_groups, skip_auto_apply)
		VALUES('route-3','account-1','route-3-public',null,null,null,null,'route-3',
		        null,null,null,null,null,null,null,null,null)`)

	routes, err := conn(t, ctx).GetRoutes(ctx, "account-1")
	assert.NoError(t, err)
	assert.Contains(t, routes, nmdata.Route{
		ID:                  "route-1",
		AccountID:           "account-1",
		PublicID:            "route-1-public",
		Network:             netip.MustParsePrefix("172.0.0.0/16"),
		Domains:             domain.List{"test-1.com"},
		KeepRoute:           true,
		NetID:               "route-1-net-id",
		Description:         "route-1",
		Peer:                "peer-id-1",
		PeerID:              "peer-id-1",
		PeerGroups:          []string{"group-one-resource-id"},
		NetworkType:         1,
		Masquerade:          true,
		Metric:              9999,
		Enabled:             true,
		Groups:              []string{"group-one-resource-id"},
		AccessControlGroups: []string{"group-one-resource-id"},
		SkipAutoApply:       false,
	})
	assert.Contains(t, routes, nmdata.Route{
		ID:                  "route-2",
		AccountID:           "account-1",
		PublicID:            "route-2-public",
		Network:             netip.MustParsePrefix("172.10.0.0/16"),
		Domains:             domain.List{"test-1.com", "test-2.com"},
		KeepRoute:           true,
		NetID:               "route-2-net-id",
		Description:         "route-2",
		Peer:                "peer-id-2",
		PeerID:              "peer-id-2",
		PeerGroups:          []string{"group-two-resources-id"},
		NetworkType:         1,
		Masquerade:          true,
		Metric:              9999,
		Enabled:             true,
		Groups:              []string{"group-two-resources-id"},
		AccessControlGroups: []string{"group-two-resources-id"},
		SkipAutoApply:       false,
	})
	assert.Contains(t, routes, nmdata.Route{
		ID:          "route-3",
		AccountID:   "account-1",
		PublicID:    "route-3-public",
		Description: "route-3",
	})
}
