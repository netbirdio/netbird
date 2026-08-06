//go:build integration

package rest_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

var (
	testAgentNetworkProvider = api.AgentNetworkProvider{
		Id:          "ainp_test",
		ProviderId:  "openai_api",
		Name:        "OpenAI",
		UpstreamUrl: "https://api.openai.com",
		Models:      []api.AgentNetworkProviderModel{},
		Enabled:     true,
	}

	testAgentNetworkPolicy = api.AgentNetworkPolicy{
		Id:                     "ainpol_test",
		Name:                   "Engineering → OpenAI",
		Enabled:                true,
		SourceGroups:           []string{"grp-eng"},
		DestinationProviderIds: []string{"ainp_test"},
	}

	testAgentNetworkGuardrail = api.AgentNetworkGuardrail{
		Id:   "aingr_test",
		Name: "No secrets",
	}

	testAgentNetworkBudgetRule = api.AgentNetworkBudgetRule{
		Id:      "ainbud_test",
		Name:    "Org monthly ceiling",
		Enabled: true,
	}

	testAgentNetworkSettings = api.AgentNetworkSettings{
		Endpoint:               "violet.eu.proxy.netbird.io",
		ProxyAddress:           "eu.proxy.netbird.io",
		Dedicated:              false,
		EnableLogCollection:    true,
		AccessLogRetentionDays: ptr(30),
	}
)

func TestAgentNetwork_ListCatalogProviders_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/catalog/providers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.AgentNetworkCatalogProvider{{Id: "openai_api", Name: "OpenAI"}})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.ListCatalogProviders(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, "openai_api", ret[0].Id)
	})
}

func TestAgentNetwork_ListProviders_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/providers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.AgentNetworkProvider{testAgentNetworkProvider})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.ListProviders(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testAgentNetworkProvider, ret[0])
	})
}

func TestAgentNetwork_GetProvider_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/providers/ainp_test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal(testAgentNetworkProvider)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.GetProvider(context.Background(), "ainp_test")
		require.NoError(t, err)
		assert.Equal(t, testAgentNetworkProvider, *ret)
	})
}

func TestAgentNetwork_GetProvider_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/providers/ainp_test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		_, err := c.AgentNetwork.GetProvider(context.Background(), "ainp_test")
		require.Error(t, err)
		assert.True(t, rest.IsNotFound(err), "a 404 must be matchable via IsNotFound")
	})
}

func TestAgentNetwork_CreateProvider_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/providers", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PostApiAgentNetworkProvidersJSONRequestBody
			require.NoError(t, json.Unmarshal(reqBytes, &req))
			assert.Equal(t, "OpenAI", req.Name)
			retBytes, _ := json.Marshal(testAgentNetworkProvider)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.CreateProvider(context.Background(), api.PostApiAgentNetworkProvidersJSONRequestBody{
			ProviderId:  "openai_api",
			Name:        "OpenAI",
			UpstreamUrl: "https://api.openai.com",
			ApiKey:      ptr("sk-test"),
		})
		require.NoError(t, err)
		assert.Equal(t, testAgentNetworkProvider, *ret)
	})
}

func TestAgentNetwork_UpdateProvider_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/providers/ainp_test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			// Omitted optional fields must be absent from the wire (not
			// zero-valued) so the server-side merge preserves them.
			assert.NotContains(t, string(reqBytes), "api_key")
			assert.NotContains(t, string(reqBytes), "models")
			retBytes, _ := json.Marshal(testAgentNetworkProvider)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.UpdateProvider(context.Background(), "ainp_test", api.PutApiAgentNetworkProvidersProviderIdJSONRequestBody{
			ProviderId:  "openai_api",
			Name:        "OpenAI",
			UpstreamUrl: "https://api.openai.com",
		})
		require.NoError(t, err)
		assert.Equal(t, testAgentNetworkProvider, *ret)
	})
}

func TestAgentNetwork_DeleteProvider_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/providers/ainp_test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			_, err := w.Write([]byte("{}"))
			require.NoError(t, err)
		})
		err := c.AgentNetwork.DeleteProvider(context.Background(), "ainp_test")
		require.NoError(t, err)
	})
}

func TestAgentNetwork_ListPolicies_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/policies", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.AgentNetworkPolicy{testAgentNetworkPolicy})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.ListPolicies(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testAgentNetworkPolicy, ret[0])
	})
}

func TestAgentNetwork_GetPolicy_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/policies/ainpol_test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testAgentNetworkPolicy)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.GetPolicy(context.Background(), "ainpol_test")
		require.NoError(t, err)
		assert.Equal(t, testAgentNetworkPolicy, *ret)
	})
}

func TestAgentNetwork_CreatePolicy_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/policies", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			retBytes, _ := json.Marshal(testAgentNetworkPolicy)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.CreatePolicy(context.Background(), api.PostApiAgentNetworkPoliciesJSONRequestBody{
			Name:                   "Engineering → OpenAI",
			SourceGroups:           []string{"grp-eng"},
			DestinationProviderIds: []string{"ainp_test"},
		})
		require.NoError(t, err)
		assert.Equal(t, testAgentNetworkPolicy, *ret)
	})
}

func TestAgentNetwork_UpdatePolicy_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/policies/ainpol_test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			retBytes, _ := json.Marshal(testAgentNetworkPolicy)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.UpdatePolicy(context.Background(), "ainpol_test", api.PutApiAgentNetworkPoliciesPolicyIdJSONRequestBody{
			Name:                   "Engineering → OpenAI",
			SourceGroups:           []string{"grp-eng"},
			DestinationProviderIds: []string{"ainp_test"},
		})
		require.NoError(t, err)
		assert.Equal(t, testAgentNetworkPolicy, *ret)
	})
}

func TestAgentNetwork_DeletePolicy_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/policies/ainpol_test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			_, err := w.Write([]byte("{}"))
			require.NoError(t, err)
		})
		err := c.AgentNetwork.DeletePolicy(context.Background(), "ainpol_test")
		require.NoError(t, err)
	})
}

func TestAgentNetwork_ListGuardrails_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/guardrails", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.AgentNetworkGuardrail{testAgentNetworkGuardrail})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.ListGuardrails(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testAgentNetworkGuardrail, ret[0])
	})
}

func TestAgentNetwork_GetGuardrail_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/guardrails/aingr_test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testAgentNetworkGuardrail)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.GetGuardrail(context.Background(), "aingr_test")
		require.NoError(t, err)
		assert.Equal(t, testAgentNetworkGuardrail, *ret)
	})
}

func TestAgentNetwork_CreateGuardrail_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/guardrails", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			retBytes, _ := json.Marshal(testAgentNetworkGuardrail)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.CreateGuardrail(context.Background(), api.PostApiAgentNetworkGuardrailsJSONRequestBody{
			Name: "No secrets",
		})
		require.NoError(t, err)
		assert.Equal(t, testAgentNetworkGuardrail, *ret)
	})
}

func TestAgentNetwork_UpdateGuardrail_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/guardrails/aingr_test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			retBytes, _ := json.Marshal(testAgentNetworkGuardrail)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.UpdateGuardrail(context.Background(), "aingr_test", api.PutApiAgentNetworkGuardrailsGuardrailIdJSONRequestBody{
			Name: "No secrets",
		})
		require.NoError(t, err)
		assert.Equal(t, testAgentNetworkGuardrail, *ret)
	})
}

func TestAgentNetwork_DeleteGuardrail_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/guardrails/aingr_test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			_, err := w.Write([]byte("{}"))
			require.NoError(t, err)
		})
		err := c.AgentNetwork.DeleteGuardrail(context.Background(), "aingr_test")
		require.NoError(t, err)
	})
}

func TestAgentNetwork_ListBudgetRules_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/budget-rules", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.AgentNetworkBudgetRule{testAgentNetworkBudgetRule})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.ListBudgetRules(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testAgentNetworkBudgetRule, ret[0])
	})
}

func TestAgentNetwork_GetBudgetRule_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/budget-rules/ainbud_test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testAgentNetworkBudgetRule)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.GetBudgetRule(context.Background(), "ainbud_test")
		require.NoError(t, err)
		assert.Equal(t, testAgentNetworkBudgetRule, *ret)
	})
}

func TestAgentNetwork_CreateBudgetRule_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/budget-rules", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			retBytes, _ := json.Marshal(testAgentNetworkBudgetRule)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.CreateBudgetRule(context.Background(), api.PostApiAgentNetworkBudgetRulesJSONRequestBody{
			Name: "Org monthly ceiling",
		})
		require.NoError(t, err)
		assert.Equal(t, testAgentNetworkBudgetRule, *ret)
	})
}

func TestAgentNetwork_UpdateBudgetRule_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/budget-rules/ainbud_test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			retBytes, _ := json.Marshal(testAgentNetworkBudgetRule)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.UpdateBudgetRule(context.Background(), "ainbud_test", api.PutApiAgentNetworkBudgetRulesRuleIdJSONRequestBody{
			Name: "Org monthly ceiling",
		})
		require.NoError(t, err)
		assert.Equal(t, testAgentNetworkBudgetRule, *ret)
	})
}

func TestAgentNetwork_DeleteBudgetRule_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/budget-rules/ainbud_test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			_, err := w.Write([]byte("{}"))
			require.NoError(t, err)
		})
		err := c.AgentNetwork.DeleteBudgetRule(context.Background(), "ainbud_test")
		require.NoError(t, err)
	})
}

func TestAgentNetwork_GetSettings_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/settings", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testAgentNetworkSettings)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.GetSettings(context.Background())
		require.NoError(t, err)
		assert.Equal(t, testAgentNetworkSettings, *ret)
	})
}

// TestAgentNetwork_GetSettings_UnbootstrappedDefaults pins the settings-read
// contract: an unbootstrapped account answers 200 with the defaults and empty
// cluster/subdomain/endpoint, which the client passes through untouched.
func TestAgentNetwork_GetSettings_UnbootstrappedDefaults(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/settings", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(api.AgentNetworkSettings{
				EnableLogCollection:    true,
				AccessLogRetentionDays: ptr(30),
			})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.GetSettings(context.Background())
		require.NoError(t, err)
		assert.Empty(t, ret.Endpoint, "empty endpoint is the not-bootstrapped signal")
		assert.True(t, ret.EnableLogCollection, "defaults must pass through")
	})
}

func TestAgentNetwork_GetSettings_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/settings", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "no", Code: 403})
			w.WriteHeader(403)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		_, err := c.AgentNetwork.GetSettings(context.Background())
		require.Error(t, err)
		assert.Equal(t, "no", err.Error())
	})
}

// TestAgentNetwork_GetSettings_LegacyNullBody pins the compatibility shim for
// management servers that answered 200 with a JSON null body before the
// defaults contract: the client translates that shape into an IsNotFound
// error instead of returning a bogus zero-valued settings object or
// fabricating defaults the server never stated.
func TestAgentNetwork_GetSettings_LegacyNullBody(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/settings", func(w http.ResponseWriter, r *http.Request) {
			_, err := w.Write([]byte("null"))
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.GetSettings(context.Background())
		require.Error(t, err)
		assert.Nil(t, ret)
		assert.True(t, rest.IsNotFound(err), "the legacy 200+null shape must surface as IsNotFound")
	})
}

func TestAgentNetwork_CreateSettings_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/settings", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PostApiAgentNetworkSettingsJSONRequestBody
			require.NoError(t, json.Unmarshal(reqBytes, &req))
			require.NotNil(t, req.ProxyAddress, "proxy address must be on the wire")
			assert.Equal(t, "eu.proxy.netbird.io", *req.ProxyAddress)
			assert.Nil(t, req.Endpoint, "endpoint must stay off the wire for a labeled bootstrap")
			retBytes, _ := json.Marshal(testAgentNetworkSettings)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.CreateSettings(context.Background(), api.PostApiAgentNetworkSettingsJSONRequestBody{
			ProxyAddress: ptr("eu.proxy.netbird.io"),
		})
		require.NoError(t, err)
		assert.Equal(t, testAgentNetworkSettings, *ret)
	})
}

func TestAgentNetwork_CreateSettings_Conflict(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/settings", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "agent network settings already bootstrapped for account acct1", Code: 409})
			w.WriteHeader(409)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		_, err := c.AgentNetwork.CreateSettings(context.Background(), api.PostApiAgentNetworkSettingsJSONRequestBody{
			Endpoint: ptr("gw.example.com"),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already bootstrapped")
	})
}

func TestAgentNetwork_UpdateSettings_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/settings", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PutApiAgentNetworkSettingsJSONRequestBody
			require.NoError(t, json.Unmarshal(reqBytes, &req))
			assert.True(t, req.EnableLogCollection)
			retBytes, _ := json.Marshal(testAgentNetworkSettings)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AgentNetwork.UpdateSettings(context.Background(), api.PutApiAgentNetworkSettingsJSONRequestBody{
			EnableLogCollection: true,
		})
		require.NoError(t, err)
		assert.Equal(t, testAgentNetworkSettings, *ret)
	})
}

func TestAgentNetwork_UpdateSettings_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/agent-network/settings", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "agent network settings have not been bootstrapped yet; POST /api/agent-network/settings to bootstrap them", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		_, err := c.AgentNetwork.UpdateSettings(context.Background(), api.PutApiAgentNetworkSettingsJSONRequestBody{
			EnableLogCollection: true,
		})
		require.Error(t, err)
		assert.True(t, rest.IsNotFound(err), "an unbootstrapped account must surface as IsNotFound")
	})
}
