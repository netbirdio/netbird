package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// AgentNetworkAPI APIs for the Agent Network (AI/LLM gateway), do not use directly
// see more: https://docs.netbird.io/api/resources/agent-network
type AgentNetworkAPI struct {
	c *Client
}

// ListCatalogProviders lists the catalog of supported upstream AI providers
// (openai_api, anthropic_api, bedrock_api, ...) with their default models and
// pricing, used to prefill provider create forms.
func (a *AgentNetworkAPI) ListCatalogProviders(ctx context.Context) ([]api.AgentNetworkCatalogProvider, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/agent-network/catalog/providers", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.AgentNetworkCatalogProvider](resp)
	return ret, err
}

// ListProviders lists all Agent Network providers
func (a *AgentNetworkAPI) ListProviders(ctx context.Context) ([]api.AgentNetworkProvider, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/agent-network/providers", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.AgentNetworkProvider](resp)
	return ret, err
}

// GetProvider gets Agent Network provider info
func (a *AgentNetworkAPI) GetProvider(ctx context.Context, providerID string) (*api.AgentNetworkProvider, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/agent-network/providers/"+providerID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.AgentNetworkProvider](resp)
	return &ret, err
}

// CreateProvider creates a new Agent Network provider. Providers have no
// settings side effects — bootstrap the account's gateway endpoint separately
// via CreateSettings.
func (a *AgentNetworkAPI) CreateProvider(ctx context.Context, request api.PostApiAgentNetworkProvidersJSONRequestBody) (*api.AgentNetworkProvider, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/agent-network/providers", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.AgentNetworkProvider](resp)
	return &ret, err
}

// UpdateProvider updates an Agent Network provider. The request replaces the
// provider's mutable state; only an omitted api_key keeps the stored key
// (secrets are never required to round-trip).
func (a *AgentNetworkAPI) UpdateProvider(ctx context.Context, providerID string, request api.PutApiAgentNetworkProvidersProviderIdJSONRequestBody) (*api.AgentNetworkProvider, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/agent-network/providers/"+providerID, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.AgentNetworkProvider](resp)
	return &ret, err
}

// DeleteProvider deletes an Agent Network provider. Fails while any policy
// still references the provider — detach it first.
func (a *AgentNetworkAPI) DeleteProvider(ctx context.Context, providerID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/agent-network/providers/"+providerID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}

// ListPolicies lists all Agent Network policies
func (a *AgentNetworkAPI) ListPolicies(ctx context.Context) ([]api.AgentNetworkPolicy, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/agent-network/policies", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.AgentNetworkPolicy](resp)
	return ret, err
}

// GetPolicy gets Agent Network policy info
func (a *AgentNetworkAPI) GetPolicy(ctx context.Context, policyID string) (*api.AgentNetworkPolicy, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/agent-network/policies/"+policyID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.AgentNetworkPolicy](resp)
	return &ret, err
}

// CreatePolicy creates a new Agent Network policy
func (a *AgentNetworkAPI) CreatePolicy(ctx context.Context, request api.PostApiAgentNetworkPoliciesJSONRequestBody) (*api.AgentNetworkPolicy, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/agent-network/policies", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.AgentNetworkPolicy](resp)
	return &ret, err
}

// UpdatePolicy updates an Agent Network policy
func (a *AgentNetworkAPI) UpdatePolicy(ctx context.Context, policyID string, request api.PutApiAgentNetworkPoliciesPolicyIdJSONRequestBody) (*api.AgentNetworkPolicy, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/agent-network/policies/"+policyID, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.AgentNetworkPolicy](resp)
	return &ret, err
}

// DeletePolicy deletes an Agent Network policy
func (a *AgentNetworkAPI) DeletePolicy(ctx context.Context, policyID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/agent-network/policies/"+policyID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}

// ListGuardrails lists all Agent Network guardrails
func (a *AgentNetworkAPI) ListGuardrails(ctx context.Context) ([]api.AgentNetworkGuardrail, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/agent-network/guardrails", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.AgentNetworkGuardrail](resp)
	return ret, err
}

// GetGuardrail gets Agent Network guardrail info
func (a *AgentNetworkAPI) GetGuardrail(ctx context.Context, guardrailID string) (*api.AgentNetworkGuardrail, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/agent-network/guardrails/"+guardrailID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.AgentNetworkGuardrail](resp)
	return &ret, err
}

// CreateGuardrail creates a new Agent Network guardrail
func (a *AgentNetworkAPI) CreateGuardrail(ctx context.Context, request api.PostApiAgentNetworkGuardrailsJSONRequestBody) (*api.AgentNetworkGuardrail, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/agent-network/guardrails", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.AgentNetworkGuardrail](resp)
	return &ret, err
}

// UpdateGuardrail updates an Agent Network guardrail
func (a *AgentNetworkAPI) UpdateGuardrail(ctx context.Context, guardrailID string, request api.PutApiAgentNetworkGuardrailsGuardrailIdJSONRequestBody) (*api.AgentNetworkGuardrail, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/agent-network/guardrails/"+guardrailID, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.AgentNetworkGuardrail](resp)
	return &ret, err
}

// DeleteGuardrail deletes an Agent Network guardrail
func (a *AgentNetworkAPI) DeleteGuardrail(ctx context.Context, guardrailID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/agent-network/guardrails/"+guardrailID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}

// ListBudgetRules lists all account-level Agent Network budget rules
func (a *AgentNetworkAPI) ListBudgetRules(ctx context.Context) ([]api.AgentNetworkBudgetRule, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/agent-network/budget-rules", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.AgentNetworkBudgetRule](resp)
	return ret, err
}

// GetBudgetRule gets Agent Network budget rule info
func (a *AgentNetworkAPI) GetBudgetRule(ctx context.Context, ruleID string) (*api.AgentNetworkBudgetRule, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/agent-network/budget-rules/"+ruleID, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.AgentNetworkBudgetRule](resp)
	return &ret, err
}

// CreateBudgetRule creates a new Agent Network budget rule
func (a *AgentNetworkAPI) CreateBudgetRule(ctx context.Context, request api.PostApiAgentNetworkBudgetRulesJSONRequestBody) (*api.AgentNetworkBudgetRule, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/agent-network/budget-rules", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.AgentNetworkBudgetRule](resp)
	return &ret, err
}

// UpdateBudgetRule updates an Agent Network budget rule
func (a *AgentNetworkAPI) UpdateBudgetRule(ctx context.Context, ruleID string, request api.PutApiAgentNetworkBudgetRulesRuleIdJSONRequestBody) (*api.AgentNetworkBudgetRule, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/agent-network/budget-rules/"+ruleID, bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.AgentNetworkBudgetRule](resp)
	return &ret, err
}

// DeleteBudgetRule deletes an Agent Network budget rule
func (a *AgentNetworkAPI) DeleteBudgetRule(ctx context.Context, ruleID string) error {
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/agent-network/budget-rules/"+ruleID, nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}

// GetSettings gets the account's Agent Network gateway settings (endpoint,
// proxy address, collection toggles). An account that has not been
// bootstrapped yet — via CreateSettings — reads as the defaults with an empty
// Endpoint and ProxyAddress. Management servers prior to that contract
// answered 200 with a JSON null body instead; that legacy shape is translated
// to an APIError matchable via IsNotFound rather than fabricating defaults
// the server never stated.
func (a *AgentNetworkAPI) GetSettings(ctx context.Context) (*api.AgentNetworkSettings, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/agent-network/settings", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if trimmed := bytes.TrimSpace(body); len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, &APIError{StatusCode: http.StatusNotFound, Message: "agent network settings not found"}
	}
	var ret api.AgentNetworkSettings
	if err := json.Unmarshal(body, &ret); err != nil {
		return nil, err
	}
	return &ret, nil
}

// CreateSettings bootstraps the account's Agent Network settings row,
// assigning the immutable endpoint. Exactly one of request.ProxyAddress
// (labeled endpoint beneath that cluster; the server allocates the label) and
// request.Endpoint (self-addressed dedicated endpoint, claimed verbatim) must
// be set. Returns a conflict when the account already has a settings row.
func (a *AgentNetworkAPI) CreateSettings(ctx context.Context, request api.PostApiAgentNetworkSettingsJSONRequestBody) (*api.AgentNetworkSettings, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/agent-network/settings", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.AgentNetworkSettings](resp)
	return &ret, err
}

// UpdateSettings updates the account's Agent Network settings; the request
// replaces every mutable field (collection toggles and retention). The
// endpoint and proxy address are assigned at bootstrap (CreateSettings) and
// are not part of the update schema. Returns not-found until the account is
// bootstrapped.
func (a *AgentNetworkAPI) UpdateSettings(ctx context.Context, request api.PutApiAgentNetworkSettingsJSONRequestBody) (*api.AgentNetworkSettings, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "PUT", "/api/agent-network/settings", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.AgentNetworkSettings](resp)
	return &ret, err
}
