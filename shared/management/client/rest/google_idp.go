package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// GoogleIDPAPI APIs for Google Workspace IDP integrations
type GoogleIDPAPI struct {
	c *Client
}

// List retrieves all Google Workspace IDP integrations
func (a *GoogleIDPAPI) List(ctx context.Context) ([]api.GoogleIntegration, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/google-idp", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.GoogleIntegration](resp)
	return ret, err
}

// Get retrieves a specific Google Workspace IDP integration by ID
func (a *GoogleIDPAPI) Get(ctx context.Context, integrationID string) (*api.GoogleIntegration, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/google-idp/"+integrationID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.GoogleIntegration](resp)
	return &ret, err
}

// Create creates a new Google Workspace IDP integration
func (a *GoogleIDPAPI) Create(ctx context.Context, request api.CreateGoogleIntegrationRequest) (*api.GoogleIntegration, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/integrations/google-idp", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.GoogleIntegration](resp)
	return &ret, err
}

// Update updates an existing Google Workspace IDP integration
func (a *GoogleIDPAPI) Update(ctx context.Context, integrationID string, request api.UpdateGoogleIntegrationRequest) (*api.GoogleIntegration, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/integrations/google-idp/"+integrationID, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.GoogleIntegration](resp)
	return &ret, err
}

// Delete deletes a Google Workspace IDP integration
func (a *GoogleIDPAPI) Delete(ctx context.Context, integrationID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/integrations/google-idp/"+integrationID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	return nil
}

// Sync triggers a manual sync for a Google Workspace IDP integration
func (a *GoogleIDPAPI) Sync(ctx context.Context, integrationID string) (*api.SyncResult, error) {
	resp, err := a.c.NewRequest(ctx, "POST", "/api/integrations/google-idp/"+integrationID+"/sync", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.SyncResult](resp)
	return &ret, err
}

// GetLogs retrieves synchronization logs for a Google Workspace IDP integration
func (a *GoogleIDPAPI) GetLogs(ctx context.Context, integrationID string) ([]api.IdpIntegrationSyncLog, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/google-idp/"+integrationID+"/logs", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.IdpIntegrationSyncLog](resp)
	return ret, err
}
