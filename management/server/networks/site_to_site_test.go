package networks

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	"github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
)

func resourceRef(id string, resourceType nbtypes.ResourceType) nbtypes.Resource {
	return nbtypes.Resource{ID: id, Type: resourceType}
}

func resourceRule(source, destination nbtypes.Resource, enabled bool) *nbtypes.PolicyRule {
	return &nbtypes.PolicyRule{
		Enabled:             enabled,
		SourceResource:      source,
		DestinationResource: destination,
	}
}

func Test_BuildSiteToSiteConnections(t *testing.T) {
	resources := []*resourceTypes.NetworkResource{
		{ID: "berlin-lan", NetworkID: "berlin"},
		{ID: "berlin-printer", NetworkID: "berlin"},
		{ID: "aws-vpc", NetworkID: "aws"},
		{ID: "aws-db", NetworkID: "aws"},
		{ID: "ny-lan", NetworkID: "ny"},
	}
	berlinLAN := resourceRef("berlin-lan", nbtypes.ResourceTypeSubnet)
	berlinPrinter := resourceRef("berlin-printer", nbtypes.ResourceTypeHost)
	awsVPC := resourceRef("aws-vpc", nbtypes.ResourceTypeSubnet)
	awsDB := resourceRef("aws-db", nbtypes.ResourceTypeHost)
	nyLAN := resourceRef("ny-lan", nbtypes.ResourceTypeSubnet)

	policies := []*nbtypes.Policy{
		// Listed out of ID order: the oldest policy decides which network comes first.
		{ID: "p3", Enabled: true, Rules: []*nbtypes.PolicyRule{resourceRule(berlinPrinter, awsDB, true)}},
		{ID: "p1", Enabled: true, Rules: []*nbtypes.PolicyRule{resourceRule(awsVPC, berlinLAN, true)}},
		{ID: "p2", Enabled: false, Rules: []*nbtypes.PolicyRule{resourceRule(nyLAN, awsVPC, true)}},
		// Peer and group rules, rules inside one network and unknown resources join nothing.
		{ID: "p4", Enabled: true, Rules: []*nbtypes.PolicyRule{resourceRule(resourceRef("peer-1", nbtypes.ResourceTypePeer), awsVPC, true)}},
		{ID: "p5", Enabled: true, Rules: []*nbtypes.PolicyRule{{Enabled: true, Sources: []string{"g1"}, DestinationResource: nyLAN}}},
		{ID: "p6", Enabled: true, Rules: []*nbtypes.PolicyRule{resourceRule(berlinLAN, berlinPrinter, true)}},
		{ID: "p7", Enabled: true, Rules: []*nbtypes.PolicyRule{resourceRule(resourceRef("gone", nbtypes.ResourceTypeHost), nyLAN, true)}},
		nil,
	}

	connections := buildSiteToSiteConnections(policies, resources)

	require.Len(t, connections, 2, "two network pairs are joined resource to resource")
	assert.Equal(t, &types.SiteToSiteConnection{NetworkIDs: [2]string{"aws", "berlin"}, PolicyIDs: []string{"p1", "p3"}, Enabled: true}, connections[0])
	assert.Equal(t, &types.SiteToSiteConnection{NetworkIDs: [2]string{"ny", "aws"}, PolicyIDs: []string{"p2"}, Enabled: false}, connections[1])
}

func Test_BuildSiteToSiteConnectionsDisabledRule(t *testing.T) {
	resources := []*resourceTypes.NetworkResource{
		{ID: "a", NetworkID: "net-a"},
		{ID: "b", NetworkID: "net-b"},
	}
	policies := []*nbtypes.Policy{{
		ID:      "p1",
		Enabled: true,
		Rules: []*nbtypes.PolicyRule{
			resourceRule(resourceRef("a", nbtypes.ResourceTypeSubnet), resourceRef("b", nbtypes.ResourceTypeSubnet), false),
		},
	}}

	connections := buildSiteToSiteConnections(policies, resources)

	require.Len(t, connections, 1)
	assert.False(t, connections[0].Enabled, "an enabled policy whose only rule is disabled leaves the connection disabled")
}

func Test_GetSiteToSiteConnections(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"

	s, cleanUp, err := store.NewTestStoreFromSQL(ctx, "../testdata/networks.sql", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanUp)

	remote := &resourceTypes.NetworkResource{
		ID:        "remoteSubnetId",
		NetworkID: "secondNetworkId",
		AccountID: accountID,
		Name:      "remote-subnet",
		Type:      resourceTypes.Subnet,
		Prefix:    netip.MustParsePrefix("10.20.0.0/16"),
		Enabled:   true,
	}
	require.NoError(t, s.SaveNetworkResource(ctx, remote))
	require.NoError(t, s.CreatePolicy(ctx, &nbtypes.Policy{
		ID:        "s2sPolicyId",
		AccountID: accountID,
		Name:      "remote to local",
		Enabled:   true,
		Rules: []*nbtypes.PolicyRule{{
			ID:                  "s2sPolicyId",
			PolicyID:            "s2sPolicyId",
			Enabled:             true,
			Action:              nbtypes.PolicyTrafficActionAccept,
			Protocol:            nbtypes.PolicyRuleProtocolALL,
			SourceResource:      resourceRef(remote.ID, nbtypes.ResourceTypeSubnet),
			DestinationResource: resourceRef("testResourceId", nbtypes.ResourceTypeHost),
		}},
	}))

	am := mock_server.MockAccountManager{}
	permissionsManager := permissions.NewManager(s)
	resourcesManager := resources.NewManager(s, permissionsManager, groups.NewManagerMock(), &am, nil)
	manager := NewManager(s, permissionsManager, resourcesManager, routers.NewManagerMock(), &am)

	connections, err := manager.GetSiteToSiteConnections(ctx, accountID, "testAdminId")
	require.NoError(t, err)
	require.Len(t, connections, 1)
	assert.Equal(t, [2]string{"secondNetworkId", "testNetworkId"}, connections[0].NetworkIDs, "the policy's source network comes first")
	assert.Equal(t, []string{"s2sPolicyId"}, connections[0].PolicyIDs)
	assert.True(t, connections[0].Enabled)

	_, err = manager.GetSiteToSiteConnections(ctx, accountID, "testUserId")
	require.Error(t, err, "a regular user cannot read networks")
}
