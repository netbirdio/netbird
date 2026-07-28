package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// ReverseProxyDomainsAPI APIs for Reverse Proxy Domains, do not use directly
type ReverseProxyDomainsAPI struct {
	c *Client
}

// List lists all reverse proxy domains
func (a *ReverseProxyDomainsAPI) List(ctx context.Context) ([]api.ReverseProxyDomain, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/reverse-proxies/domains", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.ReverseProxyDomain](resp)
	return ret, err
}

// Create creates a new custom domain
func (a *ReverseProxyDomainsAPI) Create(ctx context.Context, request api.PostApiReverseProxiesDomainsJSONRequestBody) (*api.ReverseProxyDomain, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/reverse-proxies/domains", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.ReverseProxyDomain](resp)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

// Delete deletes a custom domain
func (a *ReverseProxyDomainsAPI) Delete(ctx context.Context, domainID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/reverse-proxies/domains/"+url.PathEscape(domainID), nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	return nil
}

// Validate triggers domain ownership validation for a custom domain
func (a *ReverseProxyDomainsAPI) Validate(ctx context.Context, domainID string) error {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/reverse-proxies/domains/"+url.PathEscape(domainID)+"/validate", nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	return nil
}
