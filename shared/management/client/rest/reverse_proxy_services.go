package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// ReverseProxyServicesAPI APIs for Reverse Proxy Services, do not use directly
type ReverseProxyServicesAPI struct {
	c *Client
}

// List lists all reverse proxy services
func (a *ReverseProxyServicesAPI) List(ctx context.Context) ([]api.Service, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/reverse-proxies/services", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.Service](resp)
	return ret, err
}

// Get retrieves a reverse proxy service by ID
func (a *ReverseProxyServicesAPI) Get(ctx context.Context, serviceID string) (*api.Service, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/reverse-proxies/services/"+url.PathEscape(serviceID), nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Service](resp)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

// Create creates a new reverse proxy service
func (a *ReverseProxyServicesAPI) Create(ctx context.Context, request api.PostApiReverseProxiesServicesJSONRequestBody) (*api.Service, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/reverse-proxies/services", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Service](resp)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

// Update updates a reverse proxy service
func (a *ReverseProxyServicesAPI) Update(ctx context.Context, serviceID string, request api.PutApiReverseProxiesServicesServiceIdJSONRequestBody) (*api.Service, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/reverse-proxies/services/"+url.PathEscape(serviceID), bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Service](resp)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

// Delete deletes a reverse proxy service
func (a *ReverseProxyServicesAPI) Delete(ctx context.Context, serviceID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/reverse-proxies/services/"+url.PathEscape(serviceID), nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}
