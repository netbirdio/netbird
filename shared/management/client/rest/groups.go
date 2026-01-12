package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// ErrGroupNotFound is returned when a group is not found
var ErrGroupNotFound = errors.New("group not found")

// GroupsAPI APIs for Groups, do not use directly
type GroupsAPI struct {
	c *Client
}

// List list all groups
// See more: https://docs.netbird.io/api/resources/groups#list-all-groups
func (a *GroupsAPI) List(ctx context.Context) ([]api.Group, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/groups", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.Group](resp)
	return ret, err
}

// GetByName get group by name
// See more: https://docs.netbird.io/api/resources/groups#list-all-groups
func (a *GroupsAPI) GetByName(ctx context.Context, groupName string) (*api.Group, error) {
	params := map[string]string{"name": groupName}
	resp, err := a.c.NewRequest(ctx, "GET", "/api/groups", nil, params)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.Group](resp)
	if err != nil {
		return nil, err
	}
	if len(ret) == 0 {
		return nil, ErrGroupNotFound
	}
	return &ret[0], nil
}

// Get get group info
// See more: https://docs.netbird.io/api/resources/groups#retrieve-a-group
func (a *GroupsAPI) Get(ctx context.Context, groupID string) (*api.Group, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/groups/"+groupID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Group](resp)
	return &ret, err
}

// Create create new group
// See more: https://docs.netbird.io/api/resources/groups#create-a-group
func (a *GroupsAPI) Create(ctx context.Context, request api.PostApiGroupsJSONRequestBody) (*api.Group, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/groups", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Group](resp)
	return &ret, err
}

// Update update group info
// See more: https://docs.netbird.io/api/resources/groups#update-a-group
func (a *GroupsAPI) Update(ctx context.Context, groupID string, request api.PutApiGroupsGroupIdJSONRequestBody) (*api.Group, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/groups/"+groupID, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Group](resp)
	return &ret, err
}

// Delete delete group
// See more: https://docs.netbird.io/api/resources/groups#delete-a-group
func (a *GroupsAPI) Delete(ctx context.Context, groupID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/groups/"+groupID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}
