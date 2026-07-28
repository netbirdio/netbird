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

var (
	testScimIntegration = api.ScimIntegration{
		Id:                1,
		AuthToken:         "****",
		Enabled:           true,
		GroupPrefixes:     []string{"eng-"},
		UserGroupPrefixes: []string{"dev-"},
		Provider:          "okta",
		LastSyncedAt:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	testScimToken = api.ScimTokenResponse{
		AuthToken: "new-token-123",
	}

	testSyncLog = api.IdpIntegrationSyncLog{
		Id:        1,
		Level:     "info",
		Message:   "Sync completed",
		Timestamp: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}
)

func TestSCIM_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/scim-idp", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal([]api.ScimIntegration{testScimIntegration})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SCIM.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testScimIntegration, ret[0])
	})
}

func TestSCIM_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/scim-idp", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SCIM.List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestSCIM_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/scim-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal(testScimIntegration)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SCIM.Get(context.Background(), "int-1")
		require.NoError(t, err)
		assert.Equal(t, testScimIntegration, *ret)
	})
}

func TestSCIM_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/scim-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SCIM.Get(context.Background(), "int-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Nil(t, ret)
	})
}

func TestSCIM_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/scim-idp", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.CreateScimIntegrationRequest
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "okta", req.Provider)
			assert.Equal(t, "scim-", req.Prefix)
			retBytes, _ := json.Marshal(testScimIntegration)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SCIM.Create(context.Background(), api.CreateScimIntegrationRequest{
			Provider:      "okta",
			Prefix:        "scim-",
			GroupPrefixes: &[]string{"eng-"},
		})
		require.NoError(t, err)
		assert.Equal(t, testScimIntegration, *ret)
	})
}

func TestSCIM_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/scim-idp", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SCIM.Create(context.Background(), api.CreateScimIntegrationRequest{})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestSCIM_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/scim-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.UpdateScimIntegrationRequest
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, true, *req.Enabled)
			retBytes, _ := json.Marshal(testScimIntegration)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SCIM.Update(context.Background(), "int-1", api.UpdateScimIntegrationRequest{
			Enabled: ptr(true),
		})
		require.NoError(t, err)
		assert.Equal(t, testScimIntegration, *ret)
	})
}

func TestSCIM_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/scim-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SCIM.Update(context.Background(), "int-1", api.UpdateScimIntegrationRequest{})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestSCIM_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/scim-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.SCIM.Delete(context.Background(), "int-1")
		require.NoError(t, err)
	})
}

func TestSCIM_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/scim-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.SCIM.Delete(context.Background(), "int-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestSCIM_RegenerateToken_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/scim-idp/int-1/token", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			retBytes, _ := json.Marshal(testScimToken)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SCIM.RegenerateToken(context.Background(), "int-1")
		require.NoError(t, err)
		assert.Equal(t, testScimToken, *ret)
	})
}

func TestSCIM_RegenerateToken_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/scim-idp/int-1/token", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SCIM.RegenerateToken(context.Background(), "int-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Nil(t, ret)
	})
}

func TestSCIM_GetLogs_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/scim-idp/int-1/logs", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal([]api.IdpIntegrationSyncLog{testSyncLog})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SCIM.GetLogs(context.Background(), "int-1")
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testSyncLog, ret[0])
	})
}

func TestSCIM_GetLogs_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/scim-idp/int-1/logs", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SCIM.GetLogs(context.Background(), "int-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Empty(t, ret)
	})
}
