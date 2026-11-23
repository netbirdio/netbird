package server

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestValidateRuleNetworkResources(t *testing.T) {
	ctx := context.Background()
	accountID := "testAccountId"

	s, cleanUp, err := store.NewTestStoreFromSQL(ctx, "testdata/networks.sql", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanUp)

	// networks.sql holds the host resource testResourceId in testNetworkId; add a subnet and a
	// domain in secondNetworkId so rules can cross networks.
	require.NoError(t, s.SaveNetworkResource(ctx, &resourceTypes.NetworkResource{
		ID: "remoteSubnetId", NetworkID: "secondNetworkId", AccountID: accountID, Name: "remote-subnet",
		Type: resourceTypes.Subnet, Prefix: netip.MustParsePrefix("10.20.0.0/16"), Enabled: true,
	}))
	require.NoError(t, s.SaveNetworkResource(ctx, &resourceTypes.NetworkResource{
		ID: "remoteDomainId", NetworkID: "secondNetworkId", AccountID: accountID, Name: "remote-domain",
		Type: resourceTypes.Domain, Domain: "example.internal", Enabled: true,
	}))

	localHost := types.Resource{ID: "testResourceId", Type: types.ResourceTypeHost}
	remoteSubnet := types.Resource{ID: "remoteSubnetId", Type: types.ResourceTypeSubnet}
	remoteDomain := types.Resource{ID: "remoteDomainId", Type: types.ResourceTypeDomain}

	tests := []struct {
		name    string
		rule    *types.PolicyRule
		wantErr bool
	}{
		{
			name: "resources in two networks",
			rule: &types.PolicyRule{SourceResource: remoteSubnet, DestinationResource: localHost},
		},
		{
			name: "domain destination",
			rule: &types.PolicyRule{SourceResource: localHost, DestinationResource: remoteDomain},
		},
		{
			name: "peer source and group destination are not looked up",
			rule: &types.PolicyRule{
				SourceResource: types.Resource{ID: "unknownPeerId", Type: types.ResourceTypePeer},
				Destinations:   []string{"testGroupId"},
			},
		},
		{
			name:    "domain source",
			rule:    &types.PolicyRule{SourceResource: remoteDomain, DestinationResource: localHost},
			wantErr: true,
		},
		{
			name: "both resources in one network",
			rule: &types.PolicyRule{
				SourceResource:      localHost,
				DestinationResource: types.Resource{ID: "anotherTestResourceId", Type: types.ResourceTypeHost},
			},
			wantErr: true,
		},
		{
			name: "unknown resources are left alone",
			rule: &types.PolicyRule{
				SourceResource:      types.Resource{ID: "missingId", Type: types.ResourceTypeHost},
				DestinationResource: types.Resource{ID: "anotherMissingId", Type: types.ResourceTypeHost},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRuleNetworkResources(ctx, s, accountID, tt.rule)
			if !tt.wantErr {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			sErr, ok := status.FromError(err)
			require.True(t, ok, "the error must carry a status")
			assert.Equal(t, status.InvalidArgument, sErr.Type(), "an invalid resource reference is the caller's mistake")
		})
	}

	t.Run("validatePolicy refuses a domain source", func(t *testing.T) {
		policy := &types.Policy{
			Name:    "domain source",
			Enabled: true,
			Rules: []*types.PolicyRule{{
				Enabled:             true,
				Action:              types.PolicyTrafficActionAccept,
				Protocol:            types.PolicyRuleProtocolALL,
				SourceResource:      remoteDomain,
				DestinationResource: localHost,
			}},
		}
		_, err := validatePolicy(ctx, s, accountID, policy)
		require.Error(t, err)
	})
}
