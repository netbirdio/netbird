package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/management/server/http/api"
)

// DNSAPI APIs for DNS Management, do not use directly
type DNSAPI struct {
	c *Client
}

// ListNameserverGroups list all nameserver groups
// See more: https://docs.netbird.io/api/resources/dns#list-all-nameserver-groups
func (a *DNSAPI) ListNameserverGroups(ctx context.Context) ([]api.NameserverGroup, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/dns/nameservers", nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.NameserverGroup](resp)
	return ret, err
}

// GetNameserverGroup get nameserver group info
// See more: https://docs.netbird.io/api/resources/dns#retrieve-a-nameserver-group
func (a *DNSAPI) GetNameserverGroup(ctx context.Context, nameserverGroupID string) (*api.NameserverGroup, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/dns/nameservers/"+nameserverGroupID, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.NameserverGroup](resp)
	return &ret, err
}

// CreateNameserverGroup create new nameserver group
// See more: https://docs.netbird.io/api/resources/dns#create-a-nameserver-group
func (a *DNSAPI) CreateNameserverGroup(ctx context.Context, request api.PostApiDnsNameserversJSONRequestBody) (*api.NameserverGroup, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/dns/nameservers", bytes.NewReader(requestBytes))
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.NameserverGroup](resp)
	return &ret, err
}

// UpdateNameserverGroup update nameserver group info
// See more: https://docs.netbird.io/api/resources/dns#update-a-nameserver-group
func (a *DNSAPI) UpdateNameserverGroup(ctx context.Context, nameserverGroupID string, request api.PutApiDnsNameserversNsgroupIdJSONRequestBody) (*api.NameserverGroup, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/dns/nameservers/"+nameserverGroupID, bytes.NewReader(requestBytes))
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.NameserverGroup](resp)
	return &ret, err
}

// DeleteNameserverGroup delete nameserver group
// See more: https://docs.netbird.io/api/resources/dns#delete-a-nameserver-group
func (a *DNSAPI) DeleteNameserverGroup(ctx context.Context, nameserverGroupID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/dns/nameservers/"+nameserverGroupID, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}

// GetSettings get DNS settings
// See more: https://docs.netbird.io/api/resources/dns#retrieve-dns-settings
func (a *DNSAPI) GetSettings(ctx context.Context) (*api.DNSSettings, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/dns/settings", nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.DNSSettings](resp)
	return &ret, err
}

// UpdateSettings update DNS settings
// See more: https://docs.netbird.io/api/resources/dns#update-dns-settings
func (a *DNSAPI) UpdateSettings(ctx context.Context, request api.PutApiDnsSettingsJSONRequestBody) (*api.DNSSettings, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/dns/settings", bytes.NewReader(requestBytes))
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.DNSSettings](resp)
	return &ret, err
}
