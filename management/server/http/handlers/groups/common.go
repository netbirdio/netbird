package groups

import (
	"context"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// ResourceInput is a group resource as received in a request, independent of the API version.
type ResourceInput struct {
	ID   string
	Type string
}

// GroupInput is the content of a group create or update request, independent of the API version.
type GroupInput struct {
	Name      string
	Peers     *[]string
	Resources *[]ResourceInput
}

// ResourcesFromInput validates request resources and converts them to group resources.
func ResourcesFromInput(req *[]ResourceInput) ([]types.Resource, error) {
	resources := make([]types.Resource, 0)
	if req == nil {
		return resources, nil
	}

	for _, res := range *req {
		if res.ID == "" || !types.ResourceType(res.Type).Valid() {
			return nil, status.Errorf(status.InvalidArgument, "resource id shouldn't be empty and type must be one of: peer, domain, host, subnet")
		}
		resources = append(resources, types.Resource{ID: res.ID, Type: types.ResourceType(res.Type)})
	}

	return resources, nil
}

// NewGroup builds an API-issued group from a create request.
func NewGroup(in GroupInput) (*types.Group, error) {
	peers, resources, err := validatedMembers(in)
	if err != nil {
		return nil, err
	}

	return &types.Group{
		Name:      in.Name,
		Peers:     peers,
		Resources: resources,
		Issued:    types.GroupIssuedAPI,
	}, nil
}

// GetUpdatableGroup returns the stored group, refusing the All group that cannot be updated.
func GetUpdatableGroup(ctx context.Context, accountManager account.Manager, accountID, userID, groupID string) (*types.Group, error) {
	existingGroup, err := accountManager.GetGroup(ctx, accountID, groupID, userID)
	if err != nil {
		return nil, err
	}

	allGroup, err := accountManager.GetGroupByName(ctx, types.GroupAllName, accountID, userID)
	if err != nil {
		return nil, err
	}

	if allGroup.ID == groupID {
		return nil, status.Errorf(status.InvalidArgument, "updating group ALL is not allowed")
	}

	return existingGroup, nil
}

// UpdatedGroup builds the replacement for an existing group from an update request, keeping the
// fields a request cannot change.
func UpdatedGroup(existing *types.Group, in GroupInput) (*types.Group, error) {
	peers, resources, err := validatedMembers(in)
	if err != nil {
		return nil, err
	}

	return &types.Group{
		ID:                   existing.ID,
		Name:                 in.Name,
		Peers:                peers,
		Resources:            resources,
		Issued:               existing.Issued,
		IntegrationReference: existing.IntegrationReference,
	}, nil
}

func validatedMembers(in GroupInput) ([]string, []types.Resource, error) {
	if in.Name == "" {
		return nil, nil, status.Errorf(status.InvalidArgument, "group name shouldn't be empty")
	}

	peers := make([]string, 0)
	if in.Peers != nil {
		peers = *in.Peers
	}

	resources, err := ResourcesFromInput(in.Resources)
	if err != nil {
		return nil, nil, err
	}

	return peers, resources, nil
}
