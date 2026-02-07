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
	testIntegrationResponse = api.IntegrationResponse{
		Id:        ptr[int64](1),
		AccountId: ptr("acc-1"),
		Platform:  (*api.IntegrationResponsePlatform)(ptr("datadog")),
		Enabled:   ptr(true),
		Config:    &map[string]string{"api_key": "****"},
		CreatedAt: ptr(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
		UpdatedAt: ptr(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
	}
)

func TestEventStreaming_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/event-streaming", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal([]api.IntegrationResponse{testIntegrationResponse})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EventStreaming.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testIntegrationResponse, ret[0])
	})
}

func TestEventStreaming_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/event-streaming", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EventStreaming.List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestEventStreaming_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/event-streaming/1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal(testIntegrationResponse)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EventStreaming.Get(context.Background(), 1)
		require.NoError(t, err)
		assert.Equal(t, testIntegrationResponse, *ret)
	})
}

func TestEventStreaming_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/event-streaming/1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EventStreaming.Get(context.Background(), 1)
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Nil(t, ret)
	})
}

func TestEventStreaming_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/event-streaming", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.CreateIntegrationRequest
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, api.CreateIntegrationRequestPlatformDatadog, req.Platform)
			assert.Equal(t, true, req.Enabled)
			retBytes, _ := json.Marshal(testIntegrationResponse)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EventStreaming.Create(context.Background(), api.CreateIntegrationRequest{
			Platform: api.CreateIntegrationRequestPlatformDatadog,
			Enabled:  true,
			Config:   map[string]string{"api_key": "test-key"},
		})
		require.NoError(t, err)
		assert.Equal(t, testIntegrationResponse, *ret)
	})
}

func TestEventStreaming_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/event-streaming", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EventStreaming.Create(context.Background(), api.CreateIntegrationRequest{})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestEventStreaming_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/event-streaming/1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.CreateIntegrationRequest
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, false, req.Enabled)
			retBytes, _ := json.Marshal(testIntegrationResponse)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EventStreaming.Update(context.Background(), 1, api.CreateIntegrationRequest{
			Platform: api.CreateIntegrationRequestPlatformDatadog,
			Enabled:  false,
			Config:   map[string]string{"api_key": "updated-key"},
		})
		require.NoError(t, err)
		assert.Equal(t, testIntegrationResponse, *ret)
	})
}

func TestEventStreaming_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/event-streaming/1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EventStreaming.Update(context.Background(), 1, api.CreateIntegrationRequest{})
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Nil(t, ret)
	})
}

func TestEventStreaming_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/event-streaming/1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.EventStreaming.Delete(context.Background(), 1)
		require.NoError(t, err)
	})
}

func TestEventStreaming_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/event-streaming/1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.EventStreaming.Delete(context.Background(), 1)
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}
