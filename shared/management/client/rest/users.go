package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// UsersAPI APIs for users, do not use directly
type UsersAPI struct {
	c *Client
}

// List list all users, only returns one user always
// See more: https://docs.netbird.io/api/resources/users#list-all-users
func (a *UsersAPI) List(ctx context.Context) ([]api.User, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/users", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.User](resp)
	return ret, err
}

// Create create user
// See more: https://docs.netbird.io/api/resources/users#create-a-user
func (a *UsersAPI) Create(ctx context.Context, request api.PostApiUsersJSONRequestBody) (*api.User, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/users", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.User](resp)
	return &ret, err
}

// Update update user settings
// See more: https://docs.netbird.io/api/resources/users#update-a-user
func (a *UsersAPI) Update(ctx context.Context, userID string, request api.PutApiUsersUserIdJSONRequestBody) (*api.User, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/users/"+userID, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.User](resp)
	return &ret, err
}

// Delete delete user
// See more: https://docs.netbird.io/api/resources/users#delete-a-user
func (a *UsersAPI) Delete(ctx context.Context, userID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/users/"+userID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}

// ResendInvitation resend user invitation
// See more: https://docs.netbird.io/api/resources/users#resend-user-invitation
func (a *UsersAPI) ResendInvitation(ctx context.Context, userID string) error {
	resp, err := a.c.NewRequest(ctx, "POST", "/api/users/"+userID+"/invite", nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}

// Current gets the current user info
// See more: https://docs.netbird.io/api/resources/users#retrieve-current-user
func (a *UsersAPI) Current(ctx context.Context) (*api.User, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/users/current", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	ret, err := parseResponse[api.User](resp)
	return &ret, err
}
