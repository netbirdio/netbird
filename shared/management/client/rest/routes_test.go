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
	testRoute = api.Route{
		Id:      "Test",
		Domains: ptr([]string{"google.com"}),
	}
)

func TestRoutes_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/routes", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.Route{testRoute})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Routes.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testRoute, ret[0])
	})
}

func TestRoutes_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/routes", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Routes.List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestRoutes_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/routes/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testRoute)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Routes.Get(context.Background(), "Test")
		require.NoError(t, err)
		assert.Equal(t, testRoute, *ret)
	})
}

func TestRoutes_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/routes/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Routes.Get(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestRoutes_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/routes", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PostApiRoutesJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "meow", req.Description)
			retBytes, _ := json.Marshal(testRoute)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Routes.Create(context.Background(), api.PostApiRoutesJSONRequestBody{
			Description: "meow",
		})
		require.NoError(t, err)
		assert.Equal(t, testRoute, *ret)
	})
}

func TestRoutes_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/routes", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Routes.Create(context.Background(), api.PostApiRoutesJSONRequestBody{
			Description: "meow",
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestRoutes_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/routes/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PutApiRoutesRouteIdJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "meow", req.Description)
			retBytes, _ := json.Marshal(testRoute)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Routes.Update(context.Background(), "Test", api.PutApiRoutesRouteIdJSONRequestBody{
			Description: "meow",
		})
		require.NoError(t, err)
		assert.Equal(t, testRoute, *ret)
	})
}

func TestRoutes_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/routes/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Routes.Update(context.Background(), "Test", api.PutApiRoutesRouteIdJSONRequestBody{
			Description: "meow",
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestRoutes_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/routes/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.Routes.Delete(context.Background(), "Test")
		require.NoError(t, err)
	})
}

func TestRoutes_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/routes/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.Routes.Delete(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestRoutes_Integration(t *testing.T) {
	withBlackBoxServer(t, func(c *rest.Client) {
		route, err := c.Routes.Create(context.Background(), api.RouteRequest{
			Description: "Meow",
			Enabled:     false,
			Groups:      []string{"cs1tnh0hhcjnqoiuebeg"},
			PeerGroups:  ptr([]string{"cs1tnh0hhcjnqoiuebeg"}),
			Domains:     ptr([]string{"google.com"}),
			Masquerade:  true,
			Metric:      9999,
			KeepRoute:   false,
			NetworkId:   "Test",
		})

		require.NoError(t, err)
		assert.Equal(t, "Test", route.NetworkId)

		routes, err := c.Routes.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, routes, 1)

		route, err = c.Routes.Update(context.Background(), route.Id, api.RouteRequest{
			Description: "Testings",
			Enabled:     false,
			Groups:      []string{"cs1tnh0hhcjnqoiuebeg"},
			PeerGroups:  ptr([]string{"cs1tnh0hhcjnqoiuebeg"}),
			Domains:     ptr([]string{"google.com"}),
			Masquerade:  true,
			Metric:      9999,
			KeepRoute:   false,
			NetworkId:   "Tests",
		})

		require.NoError(t, err)
		assert.Equal(t, "Testings", route.Description)

		route, err = c.Routes.Get(context.Background(), route.Id)
		require.NoError(t, err)
		assert.Equal(t, "Tests", route.NetworkId)

		err = c.Routes.Delete(context.Background(), route.Id)
		require.NoError(t, err)
	})
}
