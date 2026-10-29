//go:build integration

package rest_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

var testAzureIntegration = api.AzureIntegration{
	Id:                1,
	Enabled:           true,
	ClientId:          "12345678-1234-1234-1234-123456789012",
	TenantId:          "87654321-4321-4321-4321-210987654321",
	SyncInterval:      300,
	GroupPrefixes:     []string{"eng-"},
	UserGroupPrefixes: []string{"dev-"},
	Host:              "microsoft.com",
	LastSyncedAt:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
}

func TestAzureIDP_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/azure-idp", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal([]api.AzureIntegration{testAzureIntegration})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AzureIDP.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testAzureIntegration, ret[0])
	})
}

func TestAzureIDP_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/azure-idp", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AzureIDP.List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestAzureIDP_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/azure-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal(testAzureIntegration)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AzureIDP.Get(context.Background(), "int-1")
		require.NoError(t, err)
		assert.Equal(t, testAzureIntegration, *ret)
	})
}

func TestAzureIDP_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/azure-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AzureIDP.Get(context.Background(), "int-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Nil(t, ret)
	})
}

func TestAzureIDP_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/azure-idp", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.CreateAzureIntegrationRequest
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "12345678-1234-1234-1234-123456789012", req.ClientId)
			retBytes, _ := json.Marshal(testAzureIntegration)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AzureIDP.Create(context.Background(), api.CreateAzureIntegrationRequest{
			ClientId:      "12345678-1234-1234-1234-123456789012",
			ClientSecret:  "secret",
			TenantId:      "87654321-4321-4321-4321-210987654321",
			Host:          api.CreateAzureIntegrationRequestHostMicrosoftCom,
			GroupPrefixes: &[]string{"eng-"},
		})
		require.NoError(t, err)
		assert.Equal(t, testAzureIntegration, *ret)
	})
}

func TestAzureIDP_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/azure-idp", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AzureIDP.Create(context.Background(), api.CreateAzureIntegrationRequest{})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestAzureIDP_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/azure-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.UpdateAzureIntegrationRequest
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, true, *req.Enabled)
			retBytes, _ := json.Marshal(testAzureIntegration)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AzureIDP.Update(context.Background(), "int-1", api.UpdateAzureIntegrationRequest{
			Enabled: ptr(true),
		})
		require.NoError(t, err)
		assert.Equal(t, testAzureIntegration, *ret)
	})
}

func TestAzureIDP_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/azure-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AzureIDP.Update(context.Background(), "int-1", api.UpdateAzureIntegrationRequest{})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestAzureIDP_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/azure-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.AzureIDP.Delete(context.Background(), "int-1")
		require.NoError(t, err)
	})
}

func TestAzureIDP_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/azure-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.AzureIDP.Delete(context.Background(), "int-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestAzureIDP_Sync_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/azure-idp/int-1/sync", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			retBytes, _ := json.Marshal(api.SyncResult{Result: ptr("ok")})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AzureIDP.Sync(context.Background(), "int-1")
		require.NoError(t, err)
		assert.Equal(t, "ok", *ret.Result)
	})
}

func TestAzureIDP_Sync_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/azure-idp/int-1/sync", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AzureIDP.Sync(context.Background(), "int-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Nil(t, ret)
	})
}

func TestAzureIDP_GetLogs_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/azure-idp/int-1/logs", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal([]api.IdpIntegrationSyncLog{testSyncLog})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AzureIDP.GetLogs(context.Background(), "int-1")
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testSyncLog, ret[0])
	})
}

func TestAzureIDP_GetLogs_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/azure-idp/int-1/logs", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.AzureIDP.GetLogs(context.Background(), "int-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Empty(t, ret)
	})
}
