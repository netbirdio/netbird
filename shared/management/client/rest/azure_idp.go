package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// AzureIDPAPI APIs for Azure AD IDP integrations
type AzureIDPAPI struct {
	c *Client
}

// List retrieves all Azure AD IDP integrations
func (a *AzureIDPAPI) List(ctx context.Context) ([]api.AzureIntegration, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/azure-idp", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.AzureIntegration](resp)
	return ret, err
}

// Get retrieves a specific Azure AD IDP integration by ID
func (a *AzureIDPAPI) Get(ctx context.Context, integrationID string) (*api.AzureIntegration, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/azure-idp/"+integrationID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.AzureIntegration](resp)
	return &ret, err
}

// Create creates a new Azure AD IDP integration
func (a *AzureIDPAPI) Create(ctx context.Context, request api.CreateAzureIntegrationRequest) (*api.AzureIntegration, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/integrations/azure-idp", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.AzureIntegration](resp)
	return &ret, err
}

// Update updates an existing Azure AD IDP integration
func (a *AzureIDPAPI) Update(ctx context.Context, integrationID string, request api.UpdateAzureIntegrationRequest) (*api.AzureIntegration, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/integrations/azure-idp/"+integrationID, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.AzureIntegration](resp)
	return &ret, err
}

// Delete deletes an Azure AD IDP integration
func (a *AzureIDPAPI) Delete(ctx context.Context, integrationID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/integrations/azure-idp/"+integrationID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	return nil
}

// Sync triggers a manual sync for an Azure AD IDP integration
func (a *AzureIDPAPI) Sync(ctx context.Context, integrationID string) (*api.SyncResult, error) {
	resp, err := a.c.NewRequest(ctx, "POST", "/api/integrations/azure-idp/"+integrationID+"/sync", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.SyncResult](resp)
	return &ret, err
}

// GetLogs retrieves synchronization logs for an Azure AD IDP integration
func (a *AzureIDPAPI) GetLogs(ctx context.Context, integrationID string) ([]api.IdpIntegrationSyncLog, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/azure-idp/"+integrationID+"/logs", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.IdpIntegrationSyncLog](resp)
	return ret, err
}
