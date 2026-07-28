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

var testIngressPeer = api.IngressPeer{
	Connected: true,
	Enabled:   true,
	Id:        "Test",
}

func TestIngress_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ingress/peers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.IngressPeer{testIngressPeer})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Ingress.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testIngressPeer, ret[0])
	})
}

func TestIngress_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ingress/peers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Ingress.List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestIngress_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ingress/peers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testIngressPeer)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Ingress.Get(context.Background(), "Test")
		require.NoError(t, err)
		assert.Equal(t, testIngressPeer, *ret)
	})
}

func TestIngress_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ingress/peers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Ingress.Get(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestIngress_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ingress/peers", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PostApiIngressPeersJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "peer-id", req.PeerId)
			retBytes, _ := json.Marshal(testIngressPeer)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Ingress.Create(context.Background(), api.PostApiIngressPeersJSONRequestBody{
			PeerId: "peer-id",
		})
		require.NoError(t, err)
		assert.Equal(t, testIngressPeer, *ret)
	})
}

func TestIngress_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ingress/peers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Ingress.Create(context.Background(), api.PostApiIngressPeersJSONRequestBody{
			PeerId: "peer-id",
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestIngress_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ingress/peers/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PutApiIngressPeersIngressPeerIdJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, true, req.Enabled)
			retBytes, _ := json.Marshal(testIngressPeer)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Ingress.Update(context.Background(), "Test", api.PutApiIngressPeersIngressPeerIdJSONRequestBody{
			Enabled: true,
		})
		require.NoError(t, err)
		assert.Equal(t, testIngressPeer, *ret)
	})
}

func TestIngress_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ingress/peers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Ingress.Update(context.Background(), "Test", api.PutApiIngressPeersIngressPeerIdJSONRequestBody{
			Enabled: true,
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestIngress_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ingress/peers/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.Ingress.Delete(context.Background(), "Test")
		require.NoError(t, err)
	})
}

func TestIngress_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/ingress/peers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.Ingress.Delete(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}
