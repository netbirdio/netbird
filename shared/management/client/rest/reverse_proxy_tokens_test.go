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

func intPtr(v int) *int { return &v }

var testProxyToken = api.ProxyToken{
	Id:        "tok-1",
	Name:      "ci-runner",
	CreatedAt: time.Date(2026, 5, 21, 9, 0, 0, 0, time.UTC),
	Revoked:   false,
}

var testProxyTokenCreated = api.ProxyTokenCreated{
	Id:         "tok-1",
	Name:       "ci-runner",
	CreatedAt:  time.Date(2026, 5, 21, 9, 0, 0, 0, time.UTC),
	PlainToken: "nbproxy_abcdef0123456789",
	Revoked:    false,
}

func TestReverseProxyTokens_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/proxy-tokens", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method, "List must use GET")
			retBytes, _ := json.Marshal([]api.ProxyToken{testProxyToken})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.ReverseProxyTokens.List(context.Background())
		require.NoError(t, err)
		require.Len(t, ret, 1)
		assert.Equal(t, testProxyToken.Id, ret[0].Id)
		assert.Equal(t, testProxyToken.Name, ret[0].Name)
	})
}

func TestReverseProxyTokens_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/proxy-tokens", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 500})
			w.WriteHeader(500)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.ReverseProxyTokens.List(context.Background())
		assert.Error(t, err)
		assert.Empty(t, ret)
	})
}

func TestReverseProxyTokens_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/proxy-tokens", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method, "Create must use POST")
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.ProxyTokenRequest
			require.NoError(t, json.Unmarshal(body, &req), "server must receive a valid ProxyTokenRequest body")
			assert.Equal(t, "ci-runner", req.Name, "name must round-trip through the client")
			require.NotNil(t, req.ExpiresIn, "expires_in must be sent when provided")
			assert.Equal(t, 3600, *req.ExpiresIn, "expires_in value must round-trip unchanged")

			retBytes, _ := json.Marshal(testProxyTokenCreated)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.ReverseProxyTokens.Create(context.Background(), api.ProxyTokenRequest{
			Name:      "ci-runner",
			ExpiresIn: intPtr(3600),
		})
		require.NoError(t, err)
		assert.Equal(t, testProxyTokenCreated.Id, ret.Id)
		assert.Equal(t, testProxyTokenCreated.PlainToken, ret.PlainToken,
			"PlainToken must be returned to the caller — it's the one-shot secret")
	})
}

func TestReverseProxyTokens_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/proxy-tokens", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Bad", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.ReverseProxyTokens.Create(context.Background(), api.ProxyTokenRequest{Name: ""})
		assert.Error(t, err)
		assert.Nil(t, ret)
	})
}

func TestReverseProxyTokens_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/proxy-tokens/tok-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method, "Delete must use DELETE")
			w.WriteHeader(200)
		})
		err := c.ReverseProxyTokens.Delete(context.Background(), "tok-1")
		require.NoError(t, err)
	})
}

func TestReverseProxyTokens_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/proxy-tokens/tok-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.ReverseProxyTokens.Delete(context.Background(), "tok-1")
		assert.Error(t, err)
	})
}

// TestReverseProxyTokens_Delete_EmptyID guards against an empty tokenID
// reaching the wire — url.PathEscape("") would collapse the URL onto
// the collection endpoint.
func TestReverseProxyTokens_Delete_EmptyID(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/reverse-proxies/proxy-tokens/", func(http.ResponseWriter, *http.Request) {
			t.Fatal("empty tokenID must be rejected client-side; no request should reach the server")
		})
		err := c.ReverseProxyTokens.Delete(context.Background(), "")
		assert.Error(t, err, "empty tokenID must surface as an error")
	})
}
