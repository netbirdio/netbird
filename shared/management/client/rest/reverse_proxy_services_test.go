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

var testServiceTarget = api.ServiceTarget{
	TargetId:   "peer-123",
	TargetType: "peer",
	Protocol:   "https",
	Port:       8443,
	Enabled:    true,
}

var testService = api.Service{
	Id:      "svc-1",
	Name:    "test-service",
	Domain:  "test.example.com",
	Enabled: true,
	Auth:    api.ServiceAuthConfig{},
	Meta: api.ServiceMeta{
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Status:    "active",
	},
	Targets: []api.ServiceTarget{testServiceTarget},
}

func TestReverseProxyServices_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/services", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.Service{testService})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.ReverseProxyServices.List(context.Background())
		require.NoError(t, err)
		require.Len(t, ret, 1)
		assert.Equal(t, testService.Id, ret[0].Id)
		assert.Equal(t, testService.Name, ret[0].Name)
	})
}

func TestReverseProxyServices_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/services", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.ReverseProxyServices.List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestReverseProxyServices_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/services/svc-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testService)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.ReverseProxyServices.Get(context.Background(), "svc-1")
		require.NoError(t, err)
		assert.Equal(t, testService.Id, ret.Id)
		assert.Equal(t, testService.Domain, ret.Domain)
	})
}

func TestReverseProxyServices_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/services/svc-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.ReverseProxyServices.Get(context.Background(), "svc-1")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestReverseProxyServices_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/services", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.ServiceRequest
			require.NoError(t, json.Unmarshal(reqBytes, &req))
			assert.Equal(t, "test-service", req.Name)
			assert.Equal(t, "test.example.com", req.Domain)
			retBytes, _ := json.Marshal(testService)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.ReverseProxyServices.Create(context.Background(), api.PostApiReverseProxiesServicesJSONRequestBody{
			Name:    "test-service",
			Domain:  "test.example.com",
			Enabled: true,
			Auth:    api.ServiceAuthConfig{},
			Targets: []api.ServiceTarget{testServiceTarget},
		})
		require.NoError(t, err)
		assert.Equal(t, testService.Id, ret.Id)
	})
}

func TestReverseProxyServices_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/services", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.ReverseProxyServices.Create(context.Background(), api.PostApiReverseProxiesServicesJSONRequestBody{
			Name:    "test-service",
			Domain:  "test.example.com",
			Enabled: true,
			Auth:    api.ServiceAuthConfig{},
			Targets: []api.ServiceTarget{testServiceTarget},
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestReverseProxyServices_Create_WithPerTargetOptions(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/services", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.ServiceRequest
			require.NoError(t, json.Unmarshal(reqBytes, &req))

			require.Len(t, req.Targets, 1)
			target := req.Targets[0]
			require.NotNil(t, target.Options, "options should be present")
			opts := target.Options
			require.NotNil(t, opts.SkipTlsVerify, "skip_tls_verify should be present")
			assert.True(t, *opts.SkipTlsVerify)
			require.NotNil(t, opts.RequestTimeout, "request_timeout should be present")
			assert.Equal(t, "30s", *opts.RequestTimeout)
			require.NotNil(t, opts.PathRewrite, "path_rewrite should be present")
			assert.Equal(t, api.ServiceTargetOptionsPathRewrite("preserve"), *opts.PathRewrite)
			require.NotNil(t, opts.CustomHeaders, "custom_headers should be present")
			assert.Equal(t, "bar", (*opts.CustomHeaders)["X-Foo"])

			retBytes, _ := json.Marshal(testService)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})

		pathRewrite := api.ServiceTargetOptionsPathRewrite("preserve")
		ret, err := c.ReverseProxyServices.Create(context.Background(), api.PostApiReverseProxiesServicesJSONRequestBody{
			Name:    "test-service",
			Domain:  "test.example.com",
			Enabled: true,
			Auth:    api.ServiceAuthConfig{},
			Targets: []api.ServiceTarget{
				{
					TargetId:   "peer-123",
					TargetType: "peer",
					Protocol:   "https",
					Port:       8443,
					Enabled:    true,
					Options: &api.ServiceTargetOptions{
						SkipTlsVerify:  ptr(true),
						RequestTimeout: ptr("30s"),
						PathRewrite:    &pathRewrite,
						CustomHeaders:  &map[string]string{"X-Foo": "bar"},
					},
				},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, testService.Id, ret.Id)
	})
}

func TestReverseProxyServices_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/services/svc-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.ServiceRequest
			require.NoError(t, json.Unmarshal(reqBytes, &req))
			assert.Equal(t, "updated-service", req.Name)
			retBytes, _ := json.Marshal(testService)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.ReverseProxyServices.Update(context.Background(), "svc-1", api.PutApiReverseProxiesServicesServiceIdJSONRequestBody{
			Name:    "updated-service",
			Domain:  "test.example.com",
			Enabled: true,
			Auth:    api.ServiceAuthConfig{},
			Targets: []api.ServiceTarget{testServiceTarget},
		})
		require.NoError(t, err)
		assert.Equal(t, testService.Id, ret.Id)
	})
}

func TestReverseProxyServices_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/services/svc-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.ReverseProxyServices.Update(context.Background(), "svc-1", api.PutApiReverseProxiesServicesServiceIdJSONRequestBody{
			Name:    "updated-service",
			Domain:  "test.example.com",
			Enabled: true,
			Auth:    api.ServiceAuthConfig{},
			Targets: []api.ServiceTarget{testServiceTarget},
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestReverseProxyServices_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/services/svc-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.ReverseProxyServices.Delete(context.Background(), "svc-1")
		require.NoError(t, err)
	})
}

func TestReverseProxyServices_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/services/svc-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.ReverseProxyServices.Delete(context.Background(), "svc-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}
