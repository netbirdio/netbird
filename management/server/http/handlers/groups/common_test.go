package groups

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/integration_reference"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestResourcesFromInput(t *testing.T) {
	resources, err := ResourcesFromInput(nil)
	require.NoError(t, err)
	assert.NotNil(t, resources, "absent resources become an empty, non-nil slice")
	assert.Empty(t, resources)

	resources, err = ResourcesFromInput(&[]ResourceInput{{ID: "r1", Type: "host"}, {ID: "p1", Type: "peer"}})
	require.NoError(t, err)
	assert.Equal(t, []types.Resource{{ID: "r1", Type: types.ResourceTypeHost}, {ID: "p1", Type: types.ResourceTypePeer}}, resources)

	for _, bad := range []ResourceInput{{ID: "", Type: "host"}, {ID: "r1", Type: "bogus"}} {
		_, err = ResourcesFromInput(&[]ResourceInput{bad})
		s, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, status.InvalidArgument, s.Type(), "resource %+v must be rejected", bad)
	}
}

func TestNewGroupAndUpdatedGroup(t *testing.T) {
	_, err := NewGroup(GroupInput{})
	require.Error(t, err, "empty name must be rejected")

	group, err := NewGroup(GroupInput{Name: "devs"})
	require.NoError(t, err)
	assert.Equal(t, types.GroupIssuedAPI, group.Issued)
	assert.Equal(t, []string{}, group.Peers)

	existing := &types.Group{
		ID:                   "g1",
		Name:                 "old",
		Issued:               types.GroupIssuedIntegration,
		IntegrationReference: integration_reference.IntegrationReference{ID: 7, IntegrationType: "okta"},
	}
	peers := []string{"p1"}
	updated, err := UpdatedGroup(existing, GroupInput{Name: "new", Peers: &peers})
	require.NoError(t, err)
	assert.Equal(t, "g1", updated.ID)
	assert.Equal(t, "new", updated.Name)
	assert.Equal(t, peers, updated.Peers)
	assert.Equal(t, existing.Issued, updated.Issued, "issued is kept from the stored group")
	assert.Equal(t, existing.IntegrationReference, updated.IntegrationReference)

	_, err = UpdatedGroup(existing, GroupInput{})
	require.Error(t, err, "empty name must be rejected")
}

func TestGetUpdatableGroup(t *testing.T) {
	am := &mock_server.MockAccountManager{
		GetGroupFunc: func(_ context.Context, _, groupID, _ string) (*types.Group, error) {
			if groupID == "missing" {
				return nil, status.Errorf(status.NotFound, "not found")
			}
			return &types.Group{ID: groupID}, nil
		},
		GetGroupByNameFunc: func(_ context.Context, name, _, _ string) (*types.Group, error) {
			assert.Equal(t, types.GroupAllName, name)
			return &types.Group{ID: "all-id", Name: name}, nil
		},
	}

	group, err := GetUpdatableGroup(context.Background(), am, "acc", "user", "g1")
	require.NoError(t, err)
	assert.Equal(t, "g1", group.ID)

	_, err = GetUpdatableGroup(context.Background(), am, "acc", "user", "all-id")
	s, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.InvalidArgument, s.Type())

	_, err = GetUpdatableGroup(context.Background(), am, "acc", "user", "missing")
	s, ok = status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.NotFound, s.Type())
}
