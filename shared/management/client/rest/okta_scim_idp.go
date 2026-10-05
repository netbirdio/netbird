package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// OktaScimIDPAPI APIs for Okta SCIM IDP integrations
type OktaScimIDPAPI struct {
	c *Client
}

// List retrieves all Okta SCIM IDP integrations
func (a *OktaScimIDPAPI) List(ctx context.Context) ([]api.OktaScimIntegration, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/okta-scim-idp", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.OktaScimIntegration](resp)
	return ret, err
}

// Get retrieves a specific Okta SCIM IDP integration by ID
func (a *OktaScimIDPAPI) Get(ctx context.Context, integrationID string) (*api.OktaScimIntegration, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/okta-scim-idp/"+integrationID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.OktaScimIntegration](resp)
	return &ret, err
}

// Create creates a new Okta SCIM IDP integration
func (a *OktaScimIDPAPI) Create(ctx context.Context, request api.CreateOktaScimIntegrationRequest) (*api.OktaScimIntegration, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/integrations/okta-scim-idp", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.OktaScimIntegration](resp)
	return &ret, err
}

// Update updates an existing Okta SCIM IDP integration
func (a *OktaScimIDPAPI) Update(ctx context.Context, integrationID string, request api.UpdateOktaScimIntegrationRequest) (*api.OktaScimIntegration, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/integrations/okta-scim-idp/"+integrationID, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.OktaScimIntegration](resp)
	return &ret, err
}

// Delete deletes an Okta SCIM IDP integration
func (a *OktaScimIDPAPI) Delete(ctx context.Context, integrationID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/integrations/okta-scim-idp/"+integrationID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	return nil
}

// RegenerateToken regenerates the SCIM API token for an Okta SCIM integration
func (a *OktaScimIDPAPI) RegenerateToken(ctx context.Context, integrationID string) (*api.ScimTokenResponse, error) {
	resp, err := a.c.NewRequest(ctx, "POST", "/api/integrations/okta-scim-idp/"+integrationID+"/token", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.ScimTokenResponse](resp)
	return &ret, err
}

// GetLogs retrieves synchronization logs for an Okta SCIM IDP integration
func (a *OktaScimIDPAPI) GetLogs(ctx context.Context, integrationID string) ([]api.IdpIntegrationSyncLog, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/okta-scim-idp/"+integrationID+"/logs", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.IdpIntegrationSyncLog](resp)
	return ret, err
}
