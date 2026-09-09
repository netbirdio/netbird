//go:build integration

package networkmap_pgsql

import (
	"context"
	"testing"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/stretchr/testify/assert"
)

func TestGetNetworkRouters(t *testing.T) {
	ctx := context.TODO()

	execQuery(t, ctx,
		`insert into network_routers (id, account_id, public_id, peer, network_id, masquerade, metric, enabled, peer_groups)
		VALUES('test-nr-id-1','account-1','public-id-1','peer-id-1','network-id-1',TRUE,999,TRUE,'["group-one-resource-id"]')`)
	execQuery(t, ctx,
		`insert into network_routers (id, account_id, public_id, peer, network_id, masquerade, metric, enabled, peer_groups)
		VALUES('test-nr-id-2','account-1','public-id-2','','network-id-2',TRUE,333,TRUE,'["group-two-resources-id","group-no-resources-id"]')`)
	// empty peer_groups
	execQuery(t, ctx,
		`insert into network_routers (id, account_id, public_id, peer, network_id, masquerade, metric, enabled, peer_groups)
		VALUES('test-nr-id-3','account-1','public-id-3','peer-id-3','network-id-3',TRUE,999,TRUE,'[]')`)
	// nil peer_groups
	execQuery(t, ctx,
		`insert into network_routers (id, account_id, public_id, peer, network_id, masquerade, metric, enabled, peer_groups)
		VALUES('test-nr-id-4','account-1','public-id-4','peer-id-4','network-id-4',TRUE,999,TRUE,null)`)

	routers, err := conn(t, ctx).GetNetworkRouters(ctx, "account-1")
	assert.NoError(t, err)
	assert.NotEmpty(t, routers)

	assert.Equal(t, routers["network-id-1"],
		map[string]*nmdata.NetworkRouter{"peer-id-1": {PublicID: "public-id-1", Masquerade: true, Metric: 999, Enabled: true, PeerGroups: []string{"group-one-resource-id"}}})
	assert.Equal(t, routers["network-id-2"],
		map[string]*nmdata.NetworkRouter{
			"peer-id-2": {PublicID: "public-id-2", Masquerade: true, Metric: 333, Enabled: true, PeerGroups: []string{"group-two-resources-id", "group-no-resources-id"}},
			"peer-id-3": {PublicID: "public-id-2", Masquerade: true, Metric: 333, Enabled: true, PeerGroups: []string{"group-two-resources-id", "group-no-resources-id"}}})
	assert.Equal(t, routers["network-id-3"],
		map[string]*nmdata.NetworkRouter{"peer-id-3": {PublicID: "public-id-3", Masquerade: true, Metric: 999, Enabled: true, PeerGroups: []string{}}})
	assert.Equal(t, routers["network-id-4"],
		map[string]*nmdata.NetworkRouter{"peer-id-4": {PublicID: "public-id-4", Masquerade: true, Metric: 999, Enabled: true, PeerGroups: nil}})
}
