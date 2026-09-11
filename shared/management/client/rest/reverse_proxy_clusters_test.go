//go:build integration

package rest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

func boolPtr(b bool) *bool { return &b }

var testCluster = api.ProxyCluster{
	Id:                  "cluster-1",
	Address:             "proxy.netbird.local",
	Type:                "shared",
	Online:              true,
	ConnectedProxies:    2,
	SupportsCustomPorts: boolPtr(true),
	RequireSubdomain:    boolPtr(false),
	SupportsCrowdsec:    boolPtr(false),
	Private:             boolPtr(true),
}

func TestReverseProxyClusters_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/clusters", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method, "List must use GET")
			retBytes, _ := json.Marshal([]api.ProxyCluster{testCluster})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.ReverseProxyClusters.List(context.Background())
		require.NoError(t, err)
		require.Len(t, ret, 1)
		assert.Equal(t, testCluster.Id, ret[0].Id)
		assert.Equal(t, testCluster.Address, ret[0].Address)
		require.NotNil(t, ret[0].Private, "private capability must round-trip through the client")
		assert.True(t, *ret[0].Private, "private capability must reflect the server value")
	})
}

func TestReverseProxyClusters_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/clusters", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 500})
			w.WriteHeader(500)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.ReverseProxyClusters.List(context.Background())
		assert.Error(t, err)
		assert.Empty(t, ret)
	})
}

func TestReverseProxyClusters_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		// PathEscape on "proxy.netbird.local" leaves it intact; the route mux
		// matches the unescaped form. Sanity-check both the method and that
		// path-escaping doesn't double-encode the dotted address.
		mux.HandleFunc("/api/reverse-proxies/clusters/proxy.netbird.local", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method, "Delete must use DELETE")
			w.WriteHeader(200)
		})
		err := c.ReverseProxyClusters.Delete(context.Background(), "proxy.netbird.local")
		require.NoError(t, err)
	})
}

func TestReverseProxyClusters_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/clusters/proxy.netbird.local", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.ReverseProxyClusters.Delete(context.Background(), "proxy.netbird.local")
		assert.Error(t, err)
	})
}

// TestReverseProxyClusters_Delete_EmptyAddress guards against an empty
// clusterAddress reaching the wire — that would collapse the URL onto
// the collection endpoint instead of a specific cluster. The client
// must short-circuit with a typed error before any request is issued.
func TestReverseProxyClusters_Delete_EmptyAddress(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/clusters/", func(http.ResponseWriter, *http.Request) {
			t.Fatal("empty clusterAddress must be rejected client-side; no request should reach the server")
		})
		err := c.ReverseProxyClusters.Delete(context.Background(), "")
		assert.Error(t, err, "empty clusterAddress must surface as an error")
	})
}
