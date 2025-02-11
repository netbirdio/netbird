package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/management/server/http/api"
)

// GroupsAPI APIs for Groups, do not use directly
type GroupsAPI struct {
	c *Client
}

// List list all groups
// See more: https://docs.netbird.io/api/resources/groups#list-all-groups
func (a *GroupsAPI) List(ctx context.Context) ([]api.Group, error) {
	resp, err := a.c.newRequest(ctx, "GET", "/api/groups", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ret, err := parseResponse[[]api.Group](resp)
	return ret, err
}

// Get get group info
// See more: https://docs.netbird.io/api/resources/groups#retrieve-a-group
func (a *GroupsAPI) Get(ctx context.Context, groupID string) (*api.Group, error) {
	resp, err := a.c.newRequest(ctx, "GET", "/api/groups/"+groupID, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
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
	resp, err := a.c.newRequest(ctx, "POST", "/api/groups", bytes.NewReader(requestBytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
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
	resp, err := a.c.newRequest(ctx, "PUT", "/api/groups/"+groupID, bytes.NewReader(requestBytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ret, err := parseResponse[api.Group](resp)
	return &ret, err
}

// Delete delete group
// See more: https://docs.netbird.io/api/resources/groups#delete-a-group
func (a *GroupsAPI) Delete(ctx context.Context, groupID string) error {
	resp, err := a.c.newRequest(ctx, "DELETE", "/api/groups/"+groupID, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
