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
	testSetupKey = api.SetupKey{
		Id:         "Test",
		Name:       "wow",
		AutoGroups: []string{"meow"},
		Ephemeral:  true,
	}

	testSteupKeyGenerated = api.SetupKeyClear{
		Id:         "Test",
		Name:       "wow",
		AutoGroups: []string{"meow"},
		Ephemeral:  true,
		Key:        "shhh",
	}
)

func TestSetupKeys_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/setup-keys", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.SetupKey{testSetupKey})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SetupKeys.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testSetupKey, ret[0])
	})
}

func TestSetupKeys_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/setup-keys", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SetupKeys.List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestSetupKeys_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/setup-keys/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testSetupKey)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SetupKeys.Get(context.Background(), "Test")
		require.NoError(t, err)
		assert.Equal(t, testSetupKey, *ret)
	})
}

func TestSetupKeys_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/setup-keys/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SetupKeys.Get(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestSetupKeys_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/setup-keys", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PostApiSetupKeysJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, 5, req.ExpiresIn)
			retBytes, _ := json.Marshal(testSteupKeyGenerated)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SetupKeys.Create(context.Background(), api.PostApiSetupKeysJSONRequestBody{
			ExpiresIn: 5,
		})
		require.NoError(t, err)
		assert.Equal(t, testSteupKeyGenerated, *ret)
	})
}

func TestSetupKeys_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/setup-keys", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SetupKeys.Create(context.Background(), api.PostApiSetupKeysJSONRequestBody{
			ExpiresIn: 5,
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestSetupKeys_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/setup-keys/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PutApiSetupKeysKeyIdJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, true, req.Revoked)
			retBytes, _ := json.Marshal(testSetupKey)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SetupKeys.Update(context.Background(), "Test", api.PutApiSetupKeysKeyIdJSONRequestBody{
			Revoked: true,
		})
		require.NoError(t, err)
		assert.Equal(t, testSetupKey, *ret)
	})
}

func TestSetupKeys_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/setup-keys/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.SetupKeys.Update(context.Background(), "Test", api.PutApiSetupKeysKeyIdJSONRequestBody{
			Revoked: true,
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestSetupKeys_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/setup-keys/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.SetupKeys.Delete(context.Background(), "Test")
		require.NoError(t, err)
	})
}

func TestSetupKeys_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/setup-keys/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.SetupKeys.Delete(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestSetupKeys_Integration(t *testing.T) {
	withBlackBoxServer(t, func(c *rest.Client) {
		group, err := c.Groups.Create(context.Background(), api.GroupRequest{
			Name: "Test",
		})
		require.NoError(t, err)

		skClear, err := c.SetupKeys.Create(context.Background(), api.CreateSetupKeyRequest{
			AutoGroups: []string{group.Id},
			Ephemeral:  ptr(false),
			Name:       "test",
			Type:       "reusable",
		})

		require.NoError(t, err)
		assert.Equal(t, true, skClear.Valid)

		keys, err := c.SetupKeys.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, keys, 2)

		sk, err := c.SetupKeys.Update(context.Background(), skClear.Id, api.SetupKeyRequest{
			Revoked:    true,
			AutoGroups: []string{group.Id},
		})
		require.NoError(t, err)

		sk, err = c.SetupKeys.Get(context.Background(), sk.Id)
		require.NoError(t, err)
		assert.Equal(t, false, sk.Valid)

		err = c.SetupKeys.Delete(context.Background(), sk.Id)
		require.NoError(t, err)
	})
}
