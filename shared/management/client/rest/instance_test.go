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
	testInstanceStatus = api.InstanceStatus{
		SetupRequired: true,
	}

	testSetupResponse = api.SetupResponse{
		Email:  "admin@example.com",
		UserId: "user-123",
	}
)

func TestInstance_GetStatus_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/instance", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testInstanceStatus)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Instance.GetStatus(context.Background())
		require.NoError(t, err)
		assert.Equal(t, testInstanceStatus, *ret)
	})
}

func TestInstance_GetStatus_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/instance", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Instance.GetStatus(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestInstance_Setup_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/setup", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PostApiSetupJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "admin@example.com", req.Email)
			retBytes, _ := json.Marshal(testSetupResponse)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Instance.Setup(context.Background(), api.PostApiSetupJSONRequestBody{
			Email: "admin@example.com",
		})
		require.NoError(t, err)
		assert.Equal(t, testSetupResponse, *ret)
	})
}

func TestInstance_Setup_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/setup", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Instance.Setup(context.Background(), api.PostApiSetupJSONRequestBody{
			Email: "admin@example.com",
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}
