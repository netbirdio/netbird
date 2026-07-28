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

var testOktaScimIntegration = api.OktaScimIntegration{
	Id:                1,
	AuthToken:         "****",
	Enabled:           true,
	GroupPrefixes:     []string{"eng-"},
	UserGroupPrefixes: []string{"dev-"},
	LastSyncedAt:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
}

func TestOktaScimIDP_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/okta-scim-idp", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal([]api.OktaScimIntegration{testOktaScimIntegration})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.OktaScimIDP.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testOktaScimIntegration, ret[0])
	})
}

func TestOktaScimIDP_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/okta-scim-idp", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.OktaScimIDP.List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestOktaScimIDP_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/okta-scim-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal(testOktaScimIntegration)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.OktaScimIDP.Get(context.Background(), "int-1")
		require.NoError(t, err)
		assert.Equal(t, testOktaScimIntegration, *ret)
	})
}

func TestOktaScimIDP_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/okta-scim-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.OktaScimIDP.Get(context.Background(), "int-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Nil(t, ret)
	})
}

func TestOktaScimIDP_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/okta-scim-idp", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.CreateOktaScimIntegrationRequest
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "my-okta-connection", req.ConnectionName)
			retBytes, _ := json.Marshal(testOktaScimIntegration)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.OktaScimIDP.Create(context.Background(), api.CreateOktaScimIntegrationRequest{
			ConnectionName: "my-okta-connection",
			GroupPrefixes:  &[]string{"eng-"},
		})
		require.NoError(t, err)
		assert.Equal(t, testOktaScimIntegration, *ret)
	})
}

func TestOktaScimIDP_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/okta-scim-idp", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.OktaScimIDP.Create(context.Background(), api.CreateOktaScimIntegrationRequest{})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestOktaScimIDP_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/okta-scim-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.UpdateOktaScimIntegrationRequest
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, true, *req.Enabled)
			retBytes, _ := json.Marshal(testOktaScimIntegration)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.OktaScimIDP.Update(context.Background(), "int-1", api.UpdateOktaScimIntegrationRequest{
			Enabled: ptr(true),
		})
		require.NoError(t, err)
		assert.Equal(t, testOktaScimIntegration, *ret)
	})
}

func TestOktaScimIDP_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/okta-scim-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.OktaScimIDP.Update(context.Background(), "int-1", api.UpdateOktaScimIntegrationRequest{})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestOktaScimIDP_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/okta-scim-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.OktaScimIDP.Delete(context.Background(), "int-1")
		require.NoError(t, err)
	})
}

func TestOktaScimIDP_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/okta-scim-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.OktaScimIDP.Delete(context.Background(), "int-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestOktaScimIDP_RegenerateToken_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/okta-scim-idp/int-1/token", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			retBytes, _ := json.Marshal(testScimToken)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.OktaScimIDP.RegenerateToken(context.Background(), "int-1")
		require.NoError(t, err)
		assert.Equal(t, testScimToken, *ret)
	})
}

func TestOktaScimIDP_RegenerateToken_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/okta-scim-idp/int-1/token", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.OktaScimIDP.RegenerateToken(context.Background(), "int-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Nil(t, ret)
	})
}

func TestOktaScimIDP_GetLogs_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/okta-scim-idp/int-1/logs", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal([]api.IdpIntegrationSyncLog{testSyncLog})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.OktaScimIDP.GetLogs(context.Background(), "int-1")
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testSyncLog, ret[0])
	})
}

func TestOktaScimIDP_GetLogs_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/okta-scim-idp/int-1/logs", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.OktaScimIDP.GetLogs(context.Background(), "int-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Empty(t, ret)
	})
}
