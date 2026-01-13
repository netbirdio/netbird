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
	testGroup = api.Group{
		Id:         "Test",
		Name:       "wow",
		PeersCount: 0,
	}
)

func TestGroups_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.Group{testGroup})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Groups.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testGroup, ret[0])
	})
}

func TestGroups_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Groups.List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestGroups_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/groups/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testGroup)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Groups.Get(context.Background(), "Test")
		require.NoError(t, err)
		assert.Equal(t, testGroup, *ret)
	})
}

func TestGroups_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/groups/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Groups.Get(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestGroups_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PostApiGroupsJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "weaw", req.Name)
			retBytes, _ := json.Marshal(testGroup)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Groups.Create(context.Background(), api.PostApiGroupsJSONRequestBody{
			Name: "weaw",
		})
		require.NoError(t, err)
		assert.Equal(t, testGroup, *ret)
	})
}

func TestGroups_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Groups.Create(context.Background(), api.PostApiGroupsJSONRequestBody{
			Name: "weaw",
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestGroups_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/groups/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PutApiGroupsGroupIdJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, "weaw", req.Name)
			retBytes, _ := json.Marshal(testGroup)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Groups.Update(context.Background(), "Test", api.PutApiGroupsGroupIdJSONRequestBody{
			Name: "weaw",
		})
		require.NoError(t, err)
		assert.Equal(t, testGroup, *ret)
	})
}

func TestGroups_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/groups/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Groups.Update(context.Background(), "Test", api.PutApiGroupsGroupIdJSONRequestBody{
			Name: "weaw",
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestGroups_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/groups/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.Groups.Delete(context.Background(), "Test")
		require.NoError(t, err)
	})
}

func TestGroups_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/groups/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.Groups.Delete(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestGroups_Integration(t *testing.T) {
	withBlackBoxServer(t, func(c *rest.Client) {
		groups, err := c.Groups.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, groups, 1)

		group, err := c.Groups.Create(context.Background(), api.GroupRequest{
			Name: "Test",
		})
		require.NoError(t, err)
		assert.Equal(t, "Test", group.Name)
		assert.NotEmpty(t, group.Id)

		group, err = c.Groups.Update(context.Background(), group.Id, api.GroupRequest{
			Name: "Testnt",
		})
		require.NoError(t, err)
		assert.Equal(t, "Testnt", group.Name)

		err = c.Groups.Delete(context.Background(), group.Id)
		require.NoError(t, err)

		groups, err = c.Groups.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, groups, 1)
	})
}
