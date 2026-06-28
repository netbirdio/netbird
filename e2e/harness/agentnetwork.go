//go:build e2e

package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// The shared REST client doesn't (yet) expose typed agent-network methods, so
// these helpers drive the /api/agent-network/* endpoints through the client's
// NewRequest primitive — reusing its auth, error handling (rest.APIError on
// non-2xx), and transport — while still speaking the generated api types.

// anRequest issues an agent-network API call and decodes the JSON response into
// T. A non-2xx response surfaces as a *rest.APIError from the client, which
// tests inspect for negative-path status assertions.
func anRequest[T any](ctx context.Context, c *Combined, method, path string, body any) (T, error) {
	var out T
	var reader io.Reader
	if body != nil {
		bs, err := json.Marshal(body)
		if err != nil {
			return out, fmt.Errorf("marshal %s %s: %w", method, path, err)
		}
		reader = bytes.NewReader(bs)
	}

	resp, err := c.api.NewRequest(ctx, method, path, reader, nil)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, fmt.Errorf("decode %s %s response: %w", method, path, err)
	}
	return out, nil
}

// anDelete issues a DELETE and discards the (empty-object) body.
func anDelete(ctx context.Context, c *Combined, path string) error {
	resp, err := c.api.NewRequest(ctx, http.MethodDelete, path, nil, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// CreateProvider creates an agent-network provider.
func (c *Combined) CreateProvider(ctx context.Context, req api.AgentNetworkProviderRequest) (api.AgentNetworkProvider, error) {
	return anRequest[api.AgentNetworkProvider](ctx, c, http.MethodPost, "/api/agent-network/providers", req)
}

// GetProvider fetches a provider by id.
func (c *Combined) GetProvider(ctx context.Context, id string) (api.AgentNetworkProvider, error) {
	return anRequest[api.AgentNetworkProvider](ctx, c, http.MethodGet, "/api/agent-network/providers/"+id, nil)
}

// ListProviders returns all providers for the account.
func (c *Combined) ListProviders(ctx context.Context) ([]api.AgentNetworkProvider, error) {
	return anRequest[[]api.AgentNetworkProvider](ctx, c, http.MethodGet, "/api/agent-network/providers", nil)
}

// DeleteProvider removes a provider by id.
func (c *Combined) DeleteProvider(ctx context.Context, id string) error {
	return anDelete(ctx, c, "/api/agent-network/providers/"+id)
}

// CreatePolicy creates an agent-network policy.
func (c *Combined) CreatePolicy(ctx context.Context, req api.AgentNetworkPolicyRequest) (api.AgentNetworkPolicy, error) {
	return anRequest[api.AgentNetworkPolicy](ctx, c, http.MethodPost, "/api/agent-network/policies", req)
}

// DeletePolicy removes a policy by id.
func (c *Combined) DeletePolicy(ctx context.Context, id string) error {
	return anDelete(ctx, c, "/api/agent-network/policies/"+id)
}

// GetSettings returns the account's agent-network settings row. It exists only
// after the first provider create bootstraps it.
func (c *Combined) GetSettings(ctx context.Context) (api.AgentNetworkSettings, error) {
	return anRequest[api.AgentNetworkSettings](ctx, c, http.MethodGet, "/api/agent-network/settings", nil)
}

// UpdateSettings applies the mutable collection toggles.
func (c *Combined) UpdateSettings(ctx context.Context, req api.AgentNetworkSettingsRequest) (api.AgentNetworkSettings, error) {
	return anRequest[api.AgentNetworkSettings](ctx, c, http.MethodPut, "/api/agent-network/settings", req)
}

// ListConsumption returns the account's consumption rows (possibly empty).
func (c *Combined) ListConsumption(ctx context.Context) ([]api.AgentNetworkConsumption, error) {
	return anRequest[[]api.AgentNetworkConsumption](ctx, c, http.MethodGet, "/api/agent-network/consumption", nil)
}
