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
	testTenant = api.TenantResponse{
		Id:           "tenant-1",
		Name:         "Test Tenant",
		Domain:       "test.example.com",
		DnsChallenge: "challenge-123",
		Status:       "active",
		Groups:       []api.TenantGroupResponse{},
		CreatedAt:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}
)

func TestMSP_ListTenants_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/msp/tenants", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal([]api.TenantResponse{testTenant})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.MSP.ListTenants(context.Background())
		require.NoError(t, err)
		assert.Len(t, *ret, 1)
		assert.Equal(t, testTenant, (*ret)[0])
	})
}

func TestMSP_ListTenants_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/msp/tenants", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.MSP.ListTenants(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestMSP_CreateTenant_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/msp/tenants", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.CreateTenantRequest
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "Test Tenant", req.Name)
			assert.Equal(t, "test.example.com", req.Domain)
			retBytes, _ := json.Marshal(testTenant)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.MSP.CreateTenant(context.Background(), api.CreateTenantRequest{
			Name:   "Test Tenant",
			Domain: "test.example.com",
			Groups: []api.TenantGroupResponse{},
		})
		require.NoError(t, err)
		assert.Equal(t, testTenant, *ret)
	})
}

func TestMSP_CreateTenant_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/msp/tenants", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.MSP.CreateTenant(context.Background(), api.CreateTenantRequest{
			Name:   "Test Tenant",
			Domain: "test.example.com",
			Groups: []api.TenantGroupResponse{},
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestMSP_UpdateTenant_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/msp/tenants/tenant-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.UpdateTenantRequest
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "Updated Tenant", req.Name)
			retBytes, _ := json.Marshal(testTenant)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.MSP.UpdateTenant(context.Background(), "tenant-1", api.UpdateTenantRequest{
			Name:   "Updated Tenant",
			Groups: []api.TenantGroupResponse{},
		})
		require.NoError(t, err)
		assert.Equal(t, testTenant, *ret)
	})
}

func TestMSP_UpdateTenant_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/msp/tenants/tenant-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.MSP.UpdateTenant(context.Background(), "tenant-1", api.UpdateTenantRequest{
			Name:   "Updated Tenant",
			Groups: []api.TenantGroupResponse{},
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestMSP_DeleteTenant_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/msp/tenants/tenant-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.MSP.DeleteTenant(context.Background(), "tenant-1")
		require.NoError(t, err)
	})
}

func TestMSP_DeleteTenant_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/msp/tenants/tenant-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.MSP.DeleteTenant(context.Background(), "tenant-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestMSP_UnlinkTenant_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/msp/tenants/tenant-1/unlink", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			w.WriteHeader(200)
		})
		err := c.MSP.UnlinkTenant(context.Background(), "tenant-1", "owner-1")
		require.NoError(t, err)
	})
}

func TestMSP_UnlinkTenant_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/msp/tenants/tenant-1/unlink", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.MSP.UnlinkTenant(context.Background(), "tenant-1", "owner-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestMSP_VerifyTenantDNS_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/msp/tenants/tenant-1/dns", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			w.WriteHeader(200)
		})
		err := c.MSP.VerifyTenantDNS(context.Background(), "tenant-1")
		require.NoError(t, err)
	})
}

func TestMSP_VerifyTenantDNS_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/msp/tenants/tenant-1/dns", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Failed", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.MSP.VerifyTenantDNS(context.Background(), "tenant-1")
		assert.Error(t, err)
		assert.Equal(t, "Failed", err.Error())
	})
}

func TestMSP_InviteTenant_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/msp/tenants/tenant-1/invite", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			retBytes, _ := json.Marshal(testTenant)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.MSP.InviteTenant(context.Background(), "tenant-1")
		require.NoError(t, err)
		assert.Equal(t, testTenant, *ret)
	})
}

func TestMSP_InviteTenant_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/msp/tenants/tenant-1/invite", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.MSP.InviteTenant(context.Background(), "tenant-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
		assert.Nil(t, ret)
	})
}
