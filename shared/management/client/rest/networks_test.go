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
	testNetwork = api.Network{
		Id:   "Test",
		Name: "wow",
	}

	testNetworkResource = api.NetworkResource{
		Description: ptr("meaw"),
		Id:          "awa",
	}

	testNetworkRouter = api.NetworkRouter{
		Id: "ouch",
	}
)

func TestNetworks_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.Network{testNetwork})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testNetwork, ret[0])
	})
}

func TestNetworks_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestNetworks_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testNetwork)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Get(context.Background(), "Test")
		require.NoError(t, err)
		assert.Equal(t, testNetwork, *ret)
	})
}

func TestNetworks_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Get(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestNetworks_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PostApiNetworksJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "weaw", req.Name)
			retBytes, _ := json.Marshal(testNetwork)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Create(context.Background(), api.PostApiNetworksJSONRequestBody{
			Name: "weaw",
		})
		require.NoError(t, err)
		assert.Equal(t, testNetwork, *ret)
	})
}

func TestNetworks_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Create(context.Background(), api.PostApiNetworksJSONRequestBody{
			Name: "weaw",
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestNetworks_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PutApiNetworksNetworkIdJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "weaw", req.Name)
			retBytes, _ := json.Marshal(testNetwork)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Update(context.Background(), "Test", api.PutApiNetworksNetworkIdJSONRequestBody{
			Name: "weaw",
		})
		require.NoError(t, err)
		assert.Equal(t, testNetwork, *ret)
	})
}

func TestNetworks_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Update(context.Background(), "Test", api.PutApiNetworksNetworkIdJSONRequestBody{
			Name: "weaw",
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestNetworks_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.Networks.Delete(context.Background(), "Test")
		require.NoError(t, err)
	})
}

func TestNetworks_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.Networks.Delete(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestNetworks_Integration(t *testing.T) {
	withBlackBoxServer(t, func(c *rest.Client) {
		network, err := c.Networks.Create(context.Background(), api.NetworkRequest{
			Description: ptr("TestNetwork"),
			Name:        "Test",
		})
		assert.NoError(t, err)
		assert.Equal(t, "Test", network.Name)

		networks, err := c.Networks.List(context.Background())
		assert.NoError(t, err)
		assert.Empty(t, networks)

		network, err = c.Networks.Update(context.Background(), "TestID", api.NetworkRequest{
			Description: ptr("TestNetwork?"),
			Name:        "Test",
		})

		assert.NoError(t, err)
		assert.Equal(t, "TestNetwork?", *network.Description)

		err = c.Networks.Delete(context.Background(), "TestID")
		assert.NoError(t, err)
	})
}

func TestNetworks_ListAllRouters_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/routers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.NetworkRouter{testNetworkRouter})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.ListAllRouters(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testNetworkRouter, ret[0])
	})
}

func TestNetworks_ListAllRouters_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/routers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.ListAllRouters(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestNetworkResources_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/resources", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.NetworkResource{testNetworkResource})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Resources("Meow").List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testNetworkResource, ret[0])
	})
}

func TestNetworkResources_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/resources", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Resources("Meow").List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestNetworkResources_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/resources/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testNetworkResource)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Resources("Meow").Get(context.Background(), "Test")
		require.NoError(t, err)
		assert.Equal(t, testNetworkResource, *ret)
	})
}

func TestNetworkResources_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/resources/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Resources("Meow").Get(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestNetworkResources_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/resources", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PostApiNetworksNetworkIdResourcesJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "weaw", req.Name)
			retBytes, _ := json.Marshal(testNetworkResource)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Resources("Meow").Create(context.Background(), api.PostApiNetworksNetworkIdResourcesJSONRequestBody{
			Name: "weaw",
		})
		require.NoError(t, err)
		assert.Equal(t, testNetworkResource, *ret)
	})
}

func TestNetworkResources_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/resources", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Resources("Meow").Create(context.Background(), api.PostApiNetworksNetworkIdResourcesJSONRequestBody{
			Name: "weaw",
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestNetworkResources_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/resources/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PutApiNetworksNetworkIdResourcesResourceIdJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "weaw", req.Name)
			retBytes, _ := json.Marshal(testNetworkResource)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Resources("Meow").Update(context.Background(), "Test", api.PutApiNetworksNetworkIdResourcesResourceIdJSONRequestBody{
			Name: "weaw",
		})
		require.NoError(t, err)
		assert.Equal(t, testNetworkResource, *ret)
	})
}

func TestNetworkResources_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/resources/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Resources("Meow").Update(context.Background(), "Test", api.PutApiNetworksNetworkIdResourcesResourceIdJSONRequestBody{
			Name: "weaw",
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestNetworkResources_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/resources/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.Networks.Resources("Meow").Delete(context.Background(), "Test")
		require.NoError(t, err)
	})
}

func TestNetworkResources_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/resources/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.Networks.Resources("Meow").Delete(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestNetworkResources_Integration(t *testing.T) {
	withBlackBoxServer(t, func(c *rest.Client) {
		_, err := c.Networks.Resources("TestNetwork").Create(context.Background(), api.NetworkResourceRequest{
			Address:     "test.com",
			Description: ptr("Description"),
			Enabled:     false,
			Groups:      []string{"test"},
			Name:        "test",
		})
		assert.NoError(t, err)

		_, err = c.Networks.Resources("TestNetwork").List(context.Background())
		assert.NoError(t, err)

		_, err = c.Networks.Resources("TestNetwork").Get(context.Background(), "TestResource")
		assert.NoError(t, err)

		_, err = c.Networks.Resources("TestNetwork").Update(context.Background(), "TestResource", api.NetworkResourceRequest{
			Address: "testnt.com",
		})
		assert.NoError(t, err)

		err = c.Networks.Resources("TestNetwork").Delete(context.Background(), "TestResource")
		assert.NoError(t, err)
	})
}

func TestNetworkRouters_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/routers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.NetworkRouter{testNetworkRouter})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Routers("Meow").List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testNetworkRouter, ret[0])
	})
}

func TestNetworkRouters_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/routers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Routers("Meow").List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestNetworkRouters_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/routers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testNetworkRouter)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Routers("Meow").Get(context.Background(), "Test")
		require.NoError(t, err)
		assert.Equal(t, testNetworkRouter, *ret)
	})
}

func TestNetworkRouters_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/routers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Routers("Meow").Get(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestNetworkRouters_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/routers", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PostApiNetworksNetworkIdRoutersJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "test", *req.Peer)
			retBytes, _ := json.Marshal(testNetworkRouter)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Routers("Meow").Create(context.Background(), api.PostApiNetworksNetworkIdRoutersJSONRequestBody{
			Peer: ptr("test"),
		})
		require.NoError(t, err)
		assert.Equal(t, testNetworkRouter, *ret)
	})
}

func TestNetworkRouters_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/routers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Routers("Meow").Create(context.Background(), api.PostApiNetworksNetworkIdRoutersJSONRequestBody{
			Peer: ptr("test"),
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestNetworkRouters_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/routers/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PutApiNetworksNetworkIdRoutersRouterIdJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "test", *req.Peer)
			retBytes, _ := json.Marshal(testNetworkRouter)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Routers("Meow").Update(context.Background(), "Test", api.PutApiNetworksNetworkIdRoutersRouterIdJSONRequestBody{
			Peer: ptr("test"),
		})
		require.NoError(t, err)
		assert.Equal(t, testNetworkRouter, *ret)
	})
}

func TestNetworkRouters_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/routers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Networks.Routers("Meow").Update(context.Background(), "Test", api.PutApiNetworksNetworkIdRoutersRouterIdJSONRequestBody{
			Peer: ptr("test"),
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestNetworkRouters_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/routers/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.Networks.Routers("Meow").Delete(context.Background(), "Test")
		require.NoError(t, err)
	})
}

func TestNetworkRouters_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/networks/Meow/routers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.Networks.Routers("Meow").Delete(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestNetworkRouters_Integration(t *testing.T) {
	withBlackBoxServer(t, func(c *rest.Client) {
		_, err := c.Networks.Routers("TestNetwork").Create(context.Background(), api.NetworkRouterRequest{
			Enabled:    false,
			Masquerade: false,
			Metric:     9999,
			PeerGroups: ptr([]string{"test"}),
		})
		assert.NoError(t, err)

		_, err = c.Networks.Routers("TestNetwork").List(context.Background())
		assert.NoError(t, err)

		_, err = c.Networks.Routers("TestNetwork").Get(context.Background(), "TestRouter")
		assert.NoError(t, err)

		_, err = c.Networks.Routers("TestNetwork").Update(context.Background(), "TestRouter", api.NetworkRouterRequest{
			Enabled: true,
		})
		assert.NoError(t, err)

		err = c.Networks.Routers("TestNetwork").Delete(context.Background(), "TestRouter")
		assert.NoError(t, err)
	})
}
