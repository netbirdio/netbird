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
	testPeer = api.Peer{
		ApprovalRequired: false,
		Connected:        false,
		ConnectionIp:     "127.0.0.1",
		DnsLabel:         "test",
		Id:               "Test",
	}

	testPeerTemporaryAccess = api.PeerTemporaryAccessResponse{
		Id:   "Test",
		Name: "test-peer",
	}

	testIngressPortAllocation = api.IngressPortAllocation{
		Enabled: true,
		Id:      "alloc-1",
	}

	testJobResponse = api.JobResponse{
		Id:     "job-1",
		Status: "pending",
	}
)

func TestPeers_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.Peer{testPeer})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testPeer, ret[0])
	})
}

func TestPeers_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestPeers_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testPeer)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.Get(context.Background(), "Test")
		require.NoError(t, err)
		assert.Equal(t, testPeer, *ret)
	})
}

func TestPeers_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.Get(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestPeers_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PutApiPeersPeerIdJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, true, req.InactivityExpirationEnabled)
			retBytes, _ := json.Marshal(testPeer)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.Update(context.Background(), "Test", api.PutApiPeersPeerIdJSONRequestBody{
			InactivityExpirationEnabled: true,
		})
		require.NoError(t, err)
		assert.Equal(t, testPeer, *ret)
	})
}

func TestPeers_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.Update(context.Background(), "Test", api.PutApiPeersPeerIdJSONRequestBody{
			InactivityExpirationEnabled: false,
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestPeers_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.Peers.Delete(context.Background(), "Test")
		require.NoError(t, err)
	})
}

func TestPeers_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.Peers.Delete(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestPeers_ListAccessiblePeers_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/accessible-peers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.Peer{testPeer})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.ListAccessiblePeers(context.Background(), "Test")
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testPeer, ret[0])
	})
}

func TestPeers_ListAccessiblePeers_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/accessible-peers", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.ListAccessiblePeers(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestPeers_CreateTemporaryAccess_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/temporary-access", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			retBytes, _ := json.Marshal(testPeerTemporaryAccess)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.CreateTemporaryAccess(context.Background(), "Test", api.PostApiPeersPeerIdTemporaryAccessJSONRequestBody{})
		require.NoError(t, err)
		assert.Equal(t, testPeerTemporaryAccess, *ret)
	})
}

func TestPeers_CreateTemporaryAccess_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/temporary-access", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.CreateTemporaryAccess(context.Background(), "Test", api.PostApiPeersPeerIdTemporaryAccessJSONRequestBody{})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestPeerIngressPorts_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/ingress/ports", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.IngressPortAllocation{testIngressPortAllocation})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.IngressPorts("Test").List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testIngressPortAllocation, ret[0])
	})
}

func TestPeerIngressPorts_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/ingress/ports", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.IngressPorts("Test").List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestPeerIngressPorts_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/ingress/ports/alloc-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testIngressPortAllocation)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.IngressPorts("Test").Get(context.Background(), "alloc-1")
		require.NoError(t, err)
		assert.Equal(t, testIngressPortAllocation, *ret)
	})
}

func TestPeerIngressPorts_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/ingress/ports/alloc-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.IngressPorts("Test").Get(context.Background(), "alloc-1")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestPeerIngressPorts_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/ingress/ports", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			retBytes, _ := json.Marshal(testIngressPortAllocation)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.IngressPorts("Test").Create(context.Background(), api.PostApiPeersPeerIdIngressPortsJSONRequestBody{})
		require.NoError(t, err)
		assert.Equal(t, testIngressPortAllocation, *ret)
	})
}

func TestPeerIngressPorts_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/ingress/ports", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.IngressPorts("Test").Create(context.Background(), api.PostApiPeersPeerIdIngressPortsJSONRequestBody{})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestPeerIngressPorts_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/ingress/ports/alloc-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			retBytes, _ := json.Marshal(testIngressPortAllocation)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.IngressPorts("Test").Update(context.Background(), "alloc-1", api.PutApiPeersPeerIdIngressPortsAllocationIdJSONRequestBody{})
		require.NoError(t, err)
		assert.Equal(t, testIngressPortAllocation, *ret)
	})
}

func TestPeerIngressPorts_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/ingress/ports/alloc-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.IngressPorts("Test").Update(context.Background(), "alloc-1", api.PutApiPeersPeerIdIngressPortsAllocationIdJSONRequestBody{})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestPeerIngressPorts_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/ingress/ports/alloc-1", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.Peers.IngressPorts("Test").Delete(context.Background(), "alloc-1")
		require.NoError(t, err)
	})
}

func TestPeerIngressPorts_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/ingress/ports/alloc-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.Peers.IngressPorts("Test").Delete(context.Background(), "alloc-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestPeerJobs_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/jobs", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.JobResponse{testJobResponse})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.Jobs("Test").List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testJobResponse.Id, ret[0].Id)
		assert.Equal(t, testJobResponse.Status, ret[0].Status)
	})
}

func TestPeerJobs_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/jobs", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.Jobs("Test").List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestPeerJobs_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/jobs/job-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testJobResponse)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.Jobs("Test").Get(context.Background(), "job-1")
		require.NoError(t, err)
		assert.Equal(t, testJobResponse.Id, ret.Id)
		assert.Equal(t, testJobResponse.Status, ret.Status)
	})
}

func TestPeerJobs_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/jobs/job-1", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.Jobs("Test").Get(context.Background(), "job-1")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestPeerJobs_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/jobs", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			retBytes, _ := json.Marshal(testJobResponse)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.Jobs("Test").Create(context.Background(), api.PostApiPeersPeerIdJobsJSONRequestBody{})
		require.NoError(t, err)
		assert.Equal(t, testJobResponse.Id, ret.Id)
		assert.Equal(t, testJobResponse.Status, ret.Status)
	})
}

func TestPeerJobs_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/Test/jobs", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Peers.Jobs("Test").Create(context.Background(), api.PostApiPeersPeerIdJobsJSONRequestBody{})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestPeers_Integration(t *testing.T) {
	withBlackBoxServer(t, func(c *rest.Client) {
		peers, err := c.Peers.List(context.Background())
		require.NoError(t, err)
		require.NotEmpty(t, peers)

		filteredPeers, err := c.Peers.List(context.Background(), rest.PeerIPFilter("192.168.10.0"))
		require.NoError(t, err)
		require.Empty(t, filteredPeers)

		peer, err := c.Peers.Get(context.Background(), peers[0].Id)
		require.NoError(t, err)
		assert.Equal(t, peers[0].Id, peer.Id)

		peer, err = c.Peers.Update(context.Background(), peer.Id, api.PeerRequest{
			LoginExpirationEnabled:      true,
			Name:                        "Test",
			SshEnabled:                  false,
			ApprovalRequired:            ptr(false),
			InactivityExpirationEnabled: false,
		})
		require.NoError(t, err)
		assert.Equal(t, true, peer.LoginExpirationEnabled)

		accessiblePeers, err := c.Peers.ListAccessiblePeers(context.Background(), peer.Id)
		require.NoError(t, err)
		assert.Empty(t, accessiblePeers)

		err = c.Peers.Delete(context.Background(), peer.Id)
		require.NoError(t, err)
	})
}
