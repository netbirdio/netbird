package rest

import (
	"context"
	"errors"
	"net/url"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// ReverseProxyClustersAPI APIs for Reverse Proxy Clusters, do not use directly
type ReverseProxyClustersAPI struct {
	c *Client
}

// List lists all available proxy clusters. Each cluster is enriched with the
// capability flags reported by its connected proxies (supports_custom_ports,
// supports_crowdsec, private, etc.), so callers can render UX gates without
// a follow-up round-trip.
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

// Delete removes every self-hosted (BYOP) proxy registration for the given
// cluster address owned by the calling account. Shared clusters operated by
// NetBird cannot be deleted via this endpoint; the server returns 404 / 400
// for cluster addresses the account does not own.
func (a *ReverseProxyClustersAPI) Delete(ctx context.Context, clusterAddress string) error {
	// Guard against the empty input: url.PathEscape("") returns "" which
	// would collapse the request URL onto the collection endpoint and
	// silently delete nothing (or 405 depending on routing).
	if clusterAddress == "" {
		return errors.New("clusterAddress is required")
	}
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/reverse-proxies/clusters/"+url.PathEscape(clusterAddress), nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	return nil
}
