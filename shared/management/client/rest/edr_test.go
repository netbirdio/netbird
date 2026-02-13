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
	testIntuneResponse = api.EDRIntuneResponse{
		AccountId:          "acc-1",
		ClientId:           "client-1",
		TenantId:           "tenant-1",
		Enabled:            true,
		Id:                 1,
		Groups:             []api.Group{},
		LastSyncedInterval: 24,
		CreatedAt:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastSyncedAt:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		CreatedBy:          "user-1",
	}

	testSentinelOneResponse = api.EDRSentinelOneResponse{
		AccountId:          "acc-1",
		ApiUrl:             "https://sentinelone.example.com",
		Enabled:            true,
		Id:                 2,
		Groups:             []api.Group{},
		LastSyncedInterval: 24,
		MatchAttributes:    api.SentinelOneMatchAttributes{},
		CreatedAt:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastSyncedAt:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		CreatedBy:          "user-1",
	}

	testFalconResponse = api.EDRFalconResponse{
		AccountId:         "acc-1",
		CloudId:           "us-1",
		Enabled:           true,
		Id:                3,
		Groups:            []api.Group{},
		ZtaScoreThreshold: 50,
		CreatedAt:         time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastSyncedAt:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:         time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		CreatedBy:         "user-1",
	}

	testHuntressResponse = api.EDRHuntressResponse{
		AccountId:          "acc-1",
		Enabled:            true,
		Id:                 4,
		Groups:             []api.Group{},
		LastSyncedInterval: 24,
		MatchAttributes:    api.HuntressMatchAttributes{},
		CreatedAt:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastSyncedAt:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		CreatedBy:          "user-1",
	}

	testBypassResponse = api.BypassResponse{
		PeerId: "peer-1",
	}
)

// Intune tests

func TestEDR_GetIntuneIntegration_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/edr/intune", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal(testIntuneResponse)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EDR.GetIntuneIntegration(context.Background())
		require.NoError(t, err)
		assert.Equal(t, testIntuneResponse, *ret)
	})
}

func TestEDR_GetIntuneIntegration_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/edr/intune", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EDR.GetIntuneIntegration(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestEDR_CreateIntuneIntegration_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/edr/intune", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.EDRIntuneRequest
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "client-1", req.ClientId)
			retBytes, _ := json.Marshal(testIntuneResponse)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EDR.CreateIntuneIntegration(context.Background(), api.EDRIntuneRequest{
			ClientId:           "client-1",
			Secret:             "secret",
			TenantId:           "tenant-1",
			Groups:             []string{"group-1"},
			LastSyncedInterval: 24,
		})
		require.NoError(t, err)
		assert.Equal(t, testIntuneResponse, *ret)
	})
}

func TestEDR_CreateIntuneIntegration_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/edr/intune", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EDR.CreateIntuneIntegration(context.Background(), api.EDRIntuneRequest{})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestEDR_UpdateIntuneIntegration_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/edr/intune", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			retBytes, _ := json.Marshal(testIntuneResponse)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EDR.UpdateIntuneIntegration(context.Background(), api.EDRIntuneRequest{
			ClientId: "client-1",
			Secret:   "new-secret",
			TenantId: "tenant-1",
			Groups:   []string{"group-1"},
		})
		require.NoError(t, err)
		assert.Equal(t, testIntuneResponse, *ret)
	})
}

func TestEDR_DeleteIntuneIntegration_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/edr/intune", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.EDR.DeleteIntuneIntegration(context.Background())
		require.NoError(t, err)
	})
}

func TestEDR_DeleteIntuneIntegration_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/edr/intune", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.EDR.DeleteIntuneIntegration(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

// SentinelOne tests

func TestEDR_GetSentinelOneIntegration_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/edr/sentinelone", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal(testSentinelOneResponse)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EDR.GetSentinelOneIntegration(context.Background())
		require.NoError(t, err)
		assert.Equal(t, testSentinelOneResponse, *ret)
	})
}

func TestEDR_CreateSentinelOneIntegration_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/edr/sentinelone", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			retBytes, _ := json.Marshal(testSentinelOneResponse)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EDR.CreateSentinelOneIntegration(context.Background(), api.EDRSentinelOneRequest{
			ApiToken:           "token",
			ApiUrl:             "https://sentinelone.example.com",
			Groups:             []string{"group-1"},
			LastSyncedInterval: 24,
			MatchAttributes:    api.SentinelOneMatchAttributes{},
		})
		require.NoError(t, err)
		assert.Equal(t, testSentinelOneResponse, *ret)
	})
}

func TestEDR_DeleteSentinelOneIntegration_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/edr/sentinelone", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.EDR.DeleteSentinelOneIntegration(context.Background())
		require.NoError(t, err)
	})
}

// Falcon tests

func TestEDR_GetFalconIntegration_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/edr/falcon", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal(testFalconResponse)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EDR.GetFalconIntegration(context.Background())
		require.NoError(t, err)
		assert.Equal(t, testFalconResponse, *ret)
	})
}

func TestEDR_CreateFalconIntegration_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/edr/falcon", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			retBytes, _ := json.Marshal(testFalconResponse)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EDR.CreateFalconIntegration(context.Background(), api.EDRFalconRequest{
			ClientId:          "client-1",
			Secret:            "secret",
			CloudId:           "us-1",
			Groups:            []string{"group-1"},
			ZtaScoreThreshold: 50,
		})
		require.NoError(t, err)
		assert.Equal(t, testFalconResponse, *ret)
	})
}

func TestEDR_DeleteFalconIntegration_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/edr/falcon", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.EDR.DeleteFalconIntegration(context.Background())
		require.NoError(t, err)
	})
}

// Huntress tests

func TestEDR_GetHuntressIntegration_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/edr/huntress", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal(testHuntressResponse)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EDR.GetHuntressIntegration(context.Background())
		require.NoError(t, err)
		assert.Equal(t, testHuntressResponse, *ret)
	})
}

func TestEDR_CreateHuntressIntegration_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/edr/huntress", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			retBytes, _ := json.Marshal(testHuntressResponse)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EDR.CreateHuntressIntegration(context.Background(), api.EDRHuntressRequest{
			ApiKey:             "key",
			ApiSecret:          "secret",
			Groups:             []string{"group-1"},
			LastSyncedInterval: 24,
			MatchAttributes:    api.HuntressMatchAttributes{},
		})
		require.NoError(t, err)
		assert.Equal(t, testHuntressResponse, *ret)
	})
}

func TestEDR_DeleteHuntressIntegration_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/integrations/edr/huntress", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.EDR.DeleteHuntressIntegration(context.Background())
		require.NoError(t, err)
	})
}

// Peer bypass tests

func TestEDR_BypassPeerCompliance_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/peer-1/edr/bypass", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			retBytes, _ := json.Marshal(testBypassResponse)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EDR.BypassPeerCompliance(context.Background(), "peer-1")
		require.NoError(t, err)
		assert.Equal(t, testBypassResponse, *ret)
	})
}

func TestEDR_BypassPeerCompliance_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/peer-1/edr/bypass", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Bad request", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EDR.BypassPeerCompliance(context.Background(), "peer-1")
		assert.Error(t, err)
		assert.Equal(t, "Bad request", err.Error())
		assert.Nil(t, ret)
	})
}

func TestEDR_RevokePeerBypass_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/peer-1/edr/bypass", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.EDR.RevokePeerBypass(context.Background(), "peer-1")
		require.NoError(t, err)
	})
}

func TestEDR_RevokePeerBypass_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/peer-1/edr/bypass", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.EDR.RevokePeerBypass(context.Background(), "peer-1")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestEDR_ListBypassedPeers_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/edr/bypassed", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			retBytes, _ := json.Marshal([]api.BypassResponse{testBypassResponse})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EDR.ListBypassedPeers(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testBypassResponse, ret[0])
	})
}

func TestEDR_ListBypassedPeers_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/peers/edr/bypassed", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.EDR.ListBypassedPeers(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}
