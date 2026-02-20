package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// NetworksAPI APIs for Networks, do not use directly
type NetworksAPI struct {
	c *Client
}

// List list all networks
// See more: https://docs.netbird.io/api/resources/networks#list-all-networks
func (a *NetworksAPI) List(ctx context.Context) ([]api.Network, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/networks", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.Network](resp)
	return ret, err
}

// Get get network info
// See more: https://docs.netbird.io/api/resources/networks#retrieve-a-network
func (a *NetworksAPI) Get(ctx context.Context, networkID string) (*api.Network, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/networks/"+networkID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Network](resp)
	return &ret, err
}

// Create create new network
// See more: https://docs.netbird.io/api/resources/networks#create-a-network
func (a *NetworksAPI) Create(ctx context.Context, request api.PostApiNetworksJSONRequestBody) (*api.Network, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/networks", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Network](resp)
	return &ret, err
}

// Update update network
// See more: https://docs.netbird.io/api/resources/networks#update-a-network
func (a *NetworksAPI) Update(ctx context.Context, networkID string, request api.PutApiNetworksNetworkIdJSONRequestBody) (*api.Network, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/networks/"+networkID, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Network](resp)
	return &ret, err
}

// Delete delete network
// See more: https://docs.netbird.io/api/resources/networks#delete-a-network
func (a *NetworksAPI) Delete(ctx context.Context, networkID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/networks/"+networkID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}

// ListAllRouters list all routers across all networks
// See more: https://docs.netbird.io/api/resources/networks#list-all-network-routers
func (a *NetworksAPI) ListAllRouters(ctx context.Context) ([]api.NetworkRouter, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/networks/routers", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.NetworkRouter](resp)
	return ret, err
}

// NetworkResourcesAPI APIs for Network Resources, do not use directly
type NetworkResourcesAPI struct {
	c         *Client
	networkID string
}

// Resources APIs for network resources
func (a *NetworksAPI) Resources(networkID string) *NetworkResourcesAPI {
	return &NetworkResourcesAPI{
		c:         a.c,
		networkID: networkID,
	}
}

// List list all resources in networks
// See more: https://docs.netbird.io/api/resources/networks#list-all-network-resources
func (a *NetworkResourcesAPI) List(ctx context.Context) ([]api.NetworkResource, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/networks/"+a.networkID+"/resources", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.NetworkResource](resp)
	return ret, err
}

// Get get network resource info
// See more: https://docs.netbird.io/api/resources/networks#retrieve-a-network-resource
func (a *NetworkResourcesAPI) Get(ctx context.Context, networkResourceID string) (*api.NetworkResource, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/networks/"+a.networkID+"/resources/"+networkResourceID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.NetworkResource](resp)
	return &ret, err
}

// Create create new network resource
// See more: https://docs.netbird.io/api/resources/networks#create-a-network-resource
func (a *NetworkResourcesAPI) Create(ctx context.Context, request api.PostApiNetworksNetworkIdResourcesJSONRequestBody) (*api.NetworkResource, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/networks/"+a.networkID+"/resources", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.NetworkResource](resp)
	return &ret, err
}

// Update update network resource
// See more: https://docs.netbird.io/api/resources/networks#update-a-network-resource
func (a *NetworkResourcesAPI) Update(ctx context.Context, networkResourceID string, request api.PutApiNetworksNetworkIdResourcesResourceIdJSONRequestBody) (*api.NetworkResource, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/networks/"+a.networkID+"/resources/"+networkResourceID, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.NetworkResource](resp)
	return &ret, err
}

// Delete delete network resource
// See more: https://docs.netbird.io/api/resources/networks#delete-a-network-resource
func (a *NetworkResourcesAPI) Delete(ctx context.Context, networkResourceID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/networks/"+a.networkID+"/resources/"+networkResourceID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}

// NetworkRoutersAPI APIs for Network Routers, do not use directly
type NetworkRoutersAPI struct {
	c         *Client
	networkID string
}

// Routers APIs for network routers
func (a *NetworksAPI) Routers(networkID string) *NetworkRoutersAPI {
	return &NetworkRoutersAPI{
		c:         a.c,
		networkID: networkID,
	}
}

// List list all routers in networks
// See more: https://docs.netbird.io/api/routers/networks#list-all-network-routers
func (a *NetworkRoutersAPI) List(ctx context.Context) ([]api.NetworkRouter, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/networks/"+a.networkID+"/routers", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.NetworkRouter](resp)
	return ret, err
}

// Get get network router info
// See more: https://docs.netbird.io/api/routers/networks#retrieve-a-network-router
func (a *NetworkRoutersAPI) Get(ctx context.Context, networkRouterID string) (*api.NetworkRouter, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/networks/"+a.networkID+"/routers/"+networkRouterID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.NetworkRouter](resp)
	return &ret, err
}

// Create create new network router
// See more: https://docs.netbird.io/api/routers/networks#create-a-network-router
func (a *NetworkRoutersAPI) Create(ctx context.Context, request api.PostApiNetworksNetworkIdRoutersJSONRequestBody) (*api.NetworkRouter, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/networks/"+a.networkID+"/routers", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.NetworkRouter](resp)
	return &ret, err
}

// Update update network router
// See more: https://docs.netbird.io/api/routers/networks#update-a-network-router
func (a *NetworkRoutersAPI) Update(ctx context.Context, networkRouterID string, request api.PutApiNetworksNetworkIdRoutersRouterIdJSONRequestBody) (*api.NetworkRouter, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/networks/"+a.networkID+"/routers/"+networkRouterID, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.NetworkRouter](resp)
	return &ret, err
}

// Delete delete network router
// See more: https://docs.netbird.io/api/routers/networks#delete-a-network-router
func (a *NetworkRoutersAPI) Delete(ctx context.Context, networkRouterID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/networks/"+a.networkID+"/routers/"+networkRouterID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}
