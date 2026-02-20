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

var testIdentityProvider = api.IdentityProvider{
	ClientId: "test-client-id",
	Id:       ptr("Test"),
}

func TestIdentityProviders_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/identity-providers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.IdentityProvider{testIdentityProvider})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.IdentityProviders.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testIdentityProvider, ret[0])
	})
}

func TestIdentityProviders_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/identity-providers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.IdentityProviders.List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestIdentityProviders_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/identity-providers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testIdentityProvider)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.IdentityProviders.Get(context.Background(), "Test")
		require.NoError(t, err)
		assert.Equal(t, testIdentityProvider, *ret)
	})
}

func TestIdentityProviders_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/identity-providers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.IdentityProviders.Get(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestIdentityProviders_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/identity-providers", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PostApiIdentityProvidersJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "new-client-id", req.ClientId)
			retBytes, _ := json.Marshal(testIdentityProvider)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.IdentityProviders.Create(context.Background(), api.PostApiIdentityProvidersJSONRequestBody{
			ClientId: "new-client-id",
		})
		require.NoError(t, err)
		assert.Equal(t, testIdentityProvider, *ret)
	})
}

func TestIdentityProviders_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/identity-providers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.IdentityProviders.Create(context.Background(), api.PostApiIdentityProvidersJSONRequestBody{
			ClientId: "new-client-id",
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestIdentityProviders_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/identity-providers/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PutApiIdentityProvidersIdpIdJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "updated-client-id", req.ClientId)
			retBytes, _ := json.Marshal(testIdentityProvider)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.IdentityProviders.Update(context.Background(), "Test", api.PutApiIdentityProvidersIdpIdJSONRequestBody{
			ClientId: "updated-client-id",
		})
		require.NoError(t, err)
		assert.Equal(t, testIdentityProvider, *ret)
	})
}

func TestIdentityProviders_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/identity-providers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.IdentityProviders.Update(context.Background(), "Test", api.PutApiIdentityProvidersIdpIdJSONRequestBody{
			ClientId: "updated-client-id",
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestIdentityProviders_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/identity-providers/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.IdentityProviders.Delete(context.Background(), "Test")
		require.NoError(t, err)
	})
}

func TestIdentityProviders_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/identity-providers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.IdentityProviders.Delete(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}
