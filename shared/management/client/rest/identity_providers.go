package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// IdentityProvidersAPI APIs for Identity Providers, do not use directly
type IdentityProvidersAPI struct {
	c *Client
}

// List all identity providers
// See more: https://docs.netbird.io/api/resources/identity-providers#list-all-identity-providers
func (a *IdentityProvidersAPI) List(ctx context.Context) ([]api.IdentityProvider, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/identity-providers", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.IdentityProvider](resp)
	return ret, err
}

// Get identity provider info
// See more: https://docs.netbird.io/api/resources/identity-providers#retrieve-an-identity-provider
func (a *IdentityProvidersAPI) Get(ctx context.Context, idpID string) (*api.IdentityProvider, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/identity-providers/"+idpID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.IdentityProvider](resp)
	return &ret, err
}

// Create new identity provider
// See more: https://docs.netbird.io/api/resources/identity-providers#create-an-identity-provider
func (a *IdentityProvidersAPI) Create(ctx context.Context, request api.PostApiIdentityProvidersJSONRequestBody) (*api.IdentityProvider, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/identity-providers", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.IdentityProvider](resp)
	return &ret, err
}

// Update update identity provider
// See more: https://docs.netbird.io/api/resources/identity-providers#update-an-identity-provider
func (a *IdentityProvidersAPI) Update(ctx context.Context, idpID string, request api.PutApiIdentityProvidersIdpIdJSONRequestBody) (*api.IdentityProvider, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/identity-providers/"+idpID, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.IdentityProvider](resp)
	return &ret, err
}

// Delete delete identity provider
// See more: https://docs.netbird.io/api/resources/identity-providers#delete-an-identity-provider
func (a *IdentityProvidersAPI) Delete(ctx context.Context, idpID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/identity-providers/"+idpID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}
