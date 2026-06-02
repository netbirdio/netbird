package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// MSPAPI APIs for MSP tenant management
type MSPAPI struct {
	c *Client
}

// ListTenants retrieves all MSP tenants
// See more: https://docs.netbird.io/api/resources/msp#list-all-tenants
func (a *MSPAPI) ListTenants(ctx context.Context) (*api.GetTenantsResponse, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/integrations/msp/tenants", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.GetTenantsResponse](resp)
	return &ret, err
}

// CreateTenant creates a new MSP tenant
// See more: https://docs.netbird.io/api/resources/msp#create-a-tenant
func (a *MSPAPI) CreateTenant(ctx context.Context, request api.CreateTenantRequest) (*api.TenantResponse, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/integrations/msp/tenants", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.TenantResponse](resp)
	return &ret, err
}

// UpdateTenant updates an existing MSP tenant
// See more: https://docs.netbird.io/api/resources/msp#update-a-tenant
func (a *MSPAPI) UpdateTenant(ctx context.Context, tenantID string, request api.UpdateTenantRequest) (*api.TenantResponse, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/integrations/msp/tenants/"+tenantID, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.TenantResponse](resp)
	return &ret, err
}

// DeleteTenant deletes an MSP tenant
// See more: https://docs.netbird.io/api/resources/msp#delete-a-tenant
func (a *MSPAPI) DeleteTenant(ctx context.Context, tenantID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/integrations/msp/tenants/"+tenantID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	return nil
}

// UnlinkTenant unlinks a tenant from the MSP account
// See more: https://docs.netbird.io/api/resources/msp#unlink-a-tenant
func (a *MSPAPI) UnlinkTenant(ctx context.Context, tenantID, owner string) error {
	params := map[string]string{"owner": owner}
	requestBytes, err := json.Marshal(params)
	if err != nil {
		return err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/integrations/msp/tenants/"+tenantID+"/unlink", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	return nil
}

// VerifyTenantDNS verifies a tenant domain DNS challenge
// See more: https://docs.netbird.io/api/resources/msp#verify-tenant-dns
func (a *MSPAPI) VerifyTenantDNS(ctx context.Context, tenantID string) error {
	resp, err := a.c.NewRequest(ctx, "POST", "/api/integrations/msp/tenants/"+tenantID+"/dns", nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	return nil
}

// InviteTenant invites an existing account as a tenant to the MSP account
// See more: https://docs.netbird.io/api/resources/msp#invite-a-tenant
func (a *MSPAPI) InviteTenant(ctx context.Context, tenantID string) (*api.TenantResponse, error) {
	resp, err := a.c.NewRequest(ctx, "POST", "/api/integrations/msp/tenants/"+tenantID+"/invite", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.TenantResponse](resp)
	return &ret, err
}
