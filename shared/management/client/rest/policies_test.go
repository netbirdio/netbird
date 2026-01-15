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
	testPolicy = api.Policy{
		Name:    "wow",
		Id:      ptr("Test"),
		Enabled: false,
	}
)

func TestPolicies_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/policies", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.Policy{testPolicy})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Policies.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testPolicy, ret[0])
	})
}

func TestPolicies_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/policies", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Policies.List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestPolicies_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/policies/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testPolicy)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Policies.Get(context.Background(), "Test")
		require.NoError(t, err)
		assert.Equal(t, testPolicy, *ret)
	})
}

func TestPolicies_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/policies/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Policies.Get(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestPolicies_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/policies", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PutApiPoliciesPolicyIdJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "weaw", req.Name)
			retBytes, _ := json.Marshal(testPolicy)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Policies.Create(context.Background(), api.PostApiPoliciesJSONRequestBody{
			Name: "weaw",
		})
		require.NoError(t, err)
		assert.Equal(t, testPolicy, *ret)
	})
}

func TestPolicies_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/policies", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Policies.Create(context.Background(), api.PostApiPoliciesJSONRequestBody{
			Name: "weaw",
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestPolicies_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/policies/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PutApiPoliciesPolicyIdJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "weaw", req.Name)
			retBytes, _ := json.Marshal(testPolicy)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Policies.Update(context.Background(), "Test", api.PutApiPoliciesPolicyIdJSONRequestBody{
			Name: "weaw",
		})
		require.NoError(t, err)
		assert.Equal(t, testPolicy, *ret)
	})
}

func TestPolicies_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/policies/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Policies.Update(context.Background(), "Test", api.PutApiPoliciesPolicyIdJSONRequestBody{
			Name: "weaw",
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestPolicies_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/policies/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.Policies.Delete(context.Background(), "Test")
		require.NoError(t, err)
	})
}

func TestPolicies_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/policies/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.Policies.Delete(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestPolicies_Integration(t *testing.T) {
	withBlackBoxServer(t, func(c *rest.Client) {
		policies, err := c.Policies.List(context.Background())
		require.NoError(t, err)
		require.NotEmpty(t, policies)

		policy, err := c.Policies.Get(context.Background(), *policies[0].Id)
		require.NoError(t, err)
		assert.Equal(t, *policies[0].Id, *policy.Id)

		policy, err = c.Policies.Update(context.Background(), *policy.Id, api.PolicyCreate{
			Description: ptr("Test Policy"),
			Enabled:     false,
			Name:        "Test",
			Rules: []api.PolicyRuleUpdate{
				{
					Action:        api.PolicyRuleUpdateAction(policy.Rules[0].Action),
					Bidirectional: true,
					Description:   ptr("Test Policy"),
					Sources:       ptr([]string{(*policy.Rules[0].Sources)[0].Id}),
					Destinations:  ptr([]string{(*policy.Rules[0].Destinations)[0].Id}),
					Enabled:       false,
					Protocol:      api.PolicyRuleUpdateProtocolAll,
				},
			},
			SourcePostureChecks: nil,
		})
		require.NoError(t, err)
		assert.Equal(t, "Test Policy", *policy.Rules[0].Description)

		policy, err = c.Policies.Create(context.Background(), api.PolicyUpdate{
			Description: ptr("Test Policy 2"),
			Enabled:     false,
			Name:        "Test",
			Rules: []api.PolicyRuleUpdate{
				{
					Action:        api.PolicyRuleUpdateAction(policy.Rules[0].Action),
					Bidirectional: true,
					Description:   ptr("Test Policy 2"),
					Sources:       ptr([]string{(*policy.Rules[0].Sources)[0].Id}),
					Destinations:  ptr([]string{(*policy.Rules[0].Destinations)[0].Id}),
					Enabled:       false,
					Protocol:      api.PolicyRuleUpdateProtocolAll,
				},
			},
			SourcePostureChecks: nil,
		})
		require.NoError(t, err)

		err = c.Policies.Delete(context.Background(), *policy.Id)
		require.NoError(t, err)
	})
}
