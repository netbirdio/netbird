package rest

import (
	"context"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// ReverseProxyClustersAPI APIs for Reverse Proxy Clusters, do not use directly
type ReverseProxyClustersAPI struct {
	c *Client
}

// List lists all available proxy clusters
func (a *ReverseProxyClustersAPI) List(ctx context.Context) ([]api.ProxyCluster, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/reverse-proxies/clusters", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.ProxyCluster](resp)
	return ret, err
}
