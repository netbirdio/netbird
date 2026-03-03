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
	testNameserverGroup = api.NameserverGroup{
		Id:   "Test",
		Name: "wow",
	}

	testSettings = api.DNSSettings{
		DisabledManagementGroups: []string{"gone"},
	}
)

func TestDNSNameserverGroup_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/nameservers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.NameserverGroup{testNameserverGroup})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNS.ListNameserverGroups(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testNameserverGroup, ret[0])
	})
}

func TestDNSNameserverGroup_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/nameservers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNS.ListNameserverGroups(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestDNSNameserverGroup_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/nameservers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testNameserverGroup)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNS.GetNameserverGroup(context.Background(), "Test")
		require.NoError(t, err)
		assert.Equal(t, testNameserverGroup, *ret)
	})
}

func TestDNSNameserverGroup_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/nameservers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNS.GetNameserverGroup(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestDNSNameserverGroup_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/nameservers", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PostApiDnsNameserversJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "weaw", req.Name)
			retBytes, _ := json.Marshal(testNameserverGroup)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNS.CreateNameserverGroup(context.Background(), api.PostApiDnsNameserversJSONRequestBody{
			Name: "weaw",
		})
		require.NoError(t, err)
		assert.Equal(t, testNameserverGroup, *ret)
	})
}

func TestDNSNameserverGroup_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/nameservers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNS.CreateNameserverGroup(context.Background(), api.PostApiDnsNameserversJSONRequestBody{
			Name: "weaw",
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestDNSNameserverGroup_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/nameservers/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PutApiDnsNameserversNsgroupIdJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "weaw", req.Name)
			retBytes, _ := json.Marshal(testNameserverGroup)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNS.UpdateNameserverGroup(context.Background(), "Test", api.PutApiDnsNameserversNsgroupIdJSONRequestBody{
			Name: "weaw",
		})
		require.NoError(t, err)
		assert.Equal(t, testNameserverGroup, *ret)
	})
}

func TestDNSNameserverGroup_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/nameservers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNS.UpdateNameserverGroup(context.Background(), "Test", api.PutApiDnsNameserversNsgroupIdJSONRequestBody{
			Name: "weaw",
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestDNSNameserverGroup_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/nameservers/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.DNS.DeleteNameserverGroup(context.Background(), "Test")
		require.NoError(t, err)
	})
}

func TestDNSNameserverGroup_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/nameservers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.DNS.DeleteNameserverGroup(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestDNSSettings_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/settings", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testSettings)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNS.GetSettings(context.Background())
		require.NoError(t, err)
		assert.Equal(t, testSettings, *ret)
	})
}

func TestDNSSettings_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/settings", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNS.GetSettings(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestDNSSettings_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/settings", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PutApiDnsSettingsJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, []string{"test"}, req.DisabledManagementGroups)
			retBytes, _ := json.Marshal(testSettings)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNS.UpdateSettings(context.Background(), api.PutApiDnsSettingsJSONRequestBody{
			DisabledManagementGroups: []string{"test"},
		})
		require.NoError(t, err)
		assert.Equal(t, testSettings, *ret)
	})
}

func TestDNSSettings_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/dns/settings", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.DNS.UpdateSettings(context.Background(), api.PutApiDnsSettingsJSONRequestBody{
			DisabledManagementGroups: []string{"test"},
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestDNS_Integration(t *testing.T) {
	nsGroupReq := api.NameserverGroupRequest{
		Description: "Test",
		Enabled:     true,
		Domains:     []string{},
		Groups:      []string{"cs1tnh0hhcjnqoiuebeg"},
		Name:        "test",
		Nameservers: []api.Nameserver{
			{
				Ip:     "8.8.8.8",
				NsType: api.NameserverNsTypeUdp,
				Port:   53,
			},
		},
		Primary:              true,
		SearchDomainsEnabled: false,
	}
	withBlackBoxServer(t, func(c *rest.Client) {
		// Create
		nsGroup, err := c.DNS.CreateNameserverGroup(context.Background(), nsGroupReq)
		require.NoError(t, err)

		// List
		nsGroups, err := c.DNS.ListNameserverGroups(context.Background())
		require.NoError(t, err)
		assert.Equal(t, *nsGroup, nsGroups[0])

		// Update
		nsGroupReq.Description = "TestUpdate"
		nsGroup, err = c.DNS.UpdateNameserverGroup(context.Background(), nsGroup.Id, nsGroupReq)
		require.NoError(t, err)
		assert.Equal(t, "TestUpdate", nsGroup.Description)

		// Delete
		err = c.DNS.DeleteNameserverGroup(context.Background(), nsGroup.Id)
		require.NoError(t, err)

		// List again to ensure deletion
		nsGroups, err = c.DNS.ListNameserverGroups(context.Background())
		require.NoError(t, err)
		assert.Len(t, nsGroups, 0)
	})
}
