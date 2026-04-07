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

var testGoogleIntegration = api.GoogleIntegration{
	Id:                1,
	Enabled:           true,
	CustomerId:        "C01234567",
	SyncInterval:      300,
	GroupPrefixes:     []string{"eng-"},
	UserGroupPrefixes: []string{"dev-"},
	LastSyncedAt:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
}

func TestGoogleIDP_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/google-idp", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal([]api.GoogleIntegration{testGoogleIntegration})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.GoogleIDP.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testGoogleIntegration, ret[0])
	})
}

func TestGoogleIDP_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/google-idp", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.GoogleIDP.List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestGoogleIDP_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/google-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal(testGoogleIntegration)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.GoogleIDP.Get(context.Background(), "int-1")
		require.NoError(t, err)
		assert.Equal(t, testGoogleIntegration, *ret)
	})
}

func TestGoogleIDP_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/google-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.GoogleIDP.Get(context.Background(), "int-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Nil(t, ret)
	})
}

func TestGoogleIDP_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/google-idp", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.CreateGoogleIntegrationRequest
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "C01234567", req.CustomerId)
			retBytes, _ := json.Marshal(testGoogleIntegration)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.GoogleIDP.Create(context.Background(), api.CreateGoogleIntegrationRequest{
			CustomerId:        "C01234567",
			ServiceAccountKey: "key-data",
			GroupPrefixes:     &[]string{"eng-"},
		})
		require.NoError(t, err)
		assert.Equal(t, testGoogleIntegration, *ret)
	})
}

func TestGoogleIDP_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/google-idp", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.GoogleIDP.Create(context.Background(), api.CreateGoogleIntegrationRequest{})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestGoogleIDP_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/google-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.UpdateGoogleIntegrationRequest
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, true, *req.Enabled)
			retBytes, _ := json.Marshal(testGoogleIntegration)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.GoogleIDP.Update(context.Background(), "int-1", api.UpdateGoogleIntegrationRequest{
			Enabled: ptr(true),
		})
		require.NoError(t, err)
		assert.Equal(t, testGoogleIntegration, *ret)
	})
}

func TestGoogleIDP_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/google-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.GoogleIDP.Update(context.Background(), "int-1", api.UpdateGoogleIntegrationRequest{})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestGoogleIDP_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/google-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.GoogleIDP.Delete(context.Background(), "int-1")
		require.NoError(t, err)
	})
}

func TestGoogleIDP_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/google-idp/int-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.GoogleIDP.Delete(context.Background(), "int-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestGoogleIDP_Sync_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/google-idp/int-1/sync", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			retBytes, _ := json.Marshal(api.SyncResult{Result: ptr("ok")})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.GoogleIDP.Sync(context.Background(), "int-1")
		require.NoError(t, err)
		assert.Equal(t, "ok", *ret.Result)
	})
}

func TestGoogleIDP_Sync_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/google-idp/int-1/sync", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.GoogleIDP.Sync(context.Background(), "int-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Nil(t, ret)
	})
}

func TestGoogleIDP_GetLogs_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/google-idp/int-1/logs", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal([]api.IdpIntegrationSyncLog{testSyncLog})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.GoogleIDP.GetLogs(context.Background(), "int-1")
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testSyncLog, ret[0])
	})
}

func TestGoogleIDP_GetLogs_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/google-idp/int-1/logs", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.GoogleIDP.GetLogs(context.Background(), "int-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Empty(t, ret)
	})
}
