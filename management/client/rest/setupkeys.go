package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/management/server/http/api"
)

// SetupKeysAPI APIs for Setup keys, do not use directly
type SetupKeysAPI struct {
	c *Client
}

// List list all setup keys
// See more: https://docs.netbird.io/api/resources/setup-keys#list-all-setup-keys
func (a *SetupKeysAPI) List(ctx context.Context) ([]api.SetupKey, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/setup-keys", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ret, err := parseResponse[[]api.SetupKey](resp)
	return ret, err
}

// Get get setup key info
// See more: https://docs.netbird.io/api/resources/setup-keys#retrieve-a-setup-key
func (a *SetupKeysAPI) Get(ctx context.Context, setupKeyID string) (*api.SetupKey, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/setup-keys/"+setupKeyID, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ret, err := parseResponse[api.SetupKey](resp)
	return &ret, err
}

// Create generate new Setup Key
// See more: https://docs.netbird.io/api/resources/setup-keys#create-a-setup-key
func (a *SetupKeysAPI) Create(ctx context.Context, request api.PostApiSetupKeysJSONRequestBody, accountID string) (*api.SetupKeyClear, error) {
	path := "/api/setup-keys"
	if accountID != "" {
		path += "?account=" + accountID
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", path, bytes.NewReader(requestBytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ret, err := parseResponse[api.SetupKeyClear](resp)
	return &ret, err
}

// Update generate new Setup Key
// See more: https://docs.netbird.io/api/resources/setup-keys#update-a-setup-key
func (a *SetupKeysAPI) Update(ctx context.Context, setupKeyID string, request api.PutApiSetupKeysKeyIdJSONRequestBody) (*api.SetupKey, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/setup-keys/"+setupKeyID, bytes.NewReader(requestBytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ret, err := parseResponse[api.SetupKey](resp)
	return &ret, err
}

// Delete delete setup key
// See more: https://docs.netbird.io/api/resources/setup-keys#delete-a-setup-key
func (a *SetupKeysAPI) Delete(ctx context.Context, setupKeyID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/setup-keys/"+setupKeyID, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
