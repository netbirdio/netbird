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
	testUser = api.User{
		Id:            "Test",
		AutoGroups:    []string{"test-group"},
		Email:         "test@test.com",
		IsBlocked:     false,
		IsCurrent:     ptr(false),
		IsServiceUser: ptr(false),
		Issued:        ptr("api"),
		LastLogin:     &time.Time{},
		Name:          "M. Essam",
		Role:          "user",
		Status:        api.UserStatusActive,
	}
)

func TestUsers_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.User{testUser})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Users.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testUser, ret[0])
	})
}

func TestUsers_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Users.List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestUsers_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PostApiUsersJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, []string{"meow"}, req.AutoGroups)
			retBytes, _ := json.Marshal(testUser)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Users.Create(context.Background(), api.PostApiUsersJSONRequestBody{
			AutoGroups: []string{"meow"},
		})
		require.NoError(t, err)
		assert.Equal(t, testUser, *ret)
	})
}

func TestUsers_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Users.Create(context.Background(), api.PostApiUsersJSONRequestBody{
			AutoGroups: []string{"meow"},
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestUsers_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PutApiUsersUserIdJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, true, req.IsBlocked)
			retBytes, _ := json.Marshal(testUser)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Users.Update(context.Background(), "Test", api.PutApiUsersUserIdJSONRequestBody{
			IsBlocked: true,
		})
		require.NoError(t, err)
		assert.Equal(t, testUser, *ret)
	})

}

func TestUsers_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Users.Update(context.Background(), "Test", api.PutApiUsersUserIdJSONRequestBody{
			IsBlocked: true,
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestUsers_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.Users.Delete(context.Background(), "Test")
		require.NoError(t, err)
	})
}

func TestUsers_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.Users.Delete(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestUsers_ResendInvitation_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users/Test/invite", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			w.WriteHeader(200)
		})
		err := c.Users.ResendInvitation(context.Background(), "Test")
		require.NoError(t, err)
	})
}

func TestUsers_ResendInvitation_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users/Test/invite", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.Users.ResendInvitation(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestUsers_Current_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users/current", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testUser)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Users.Current(context.Background())
		require.NoError(t, err)
		assert.Equal(t, testUser, *ret)
	})
}

func TestUsers_Current_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users/current", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Users.Current(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestUsers_Integration(t *testing.T) {
	withBlackBoxServer(t, func(c *rest.Client) {
		// rest client PAT is owner's
		current, err := c.Users.Current(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "a23efe53-63fb-11ec-90d6-0242ac120003", current.Id)
		assert.Equal(t, "owner", current.Role)

		user, err := c.Users.Create(context.Background(), api.UserCreateRequest{
			AutoGroups:    []string{},
			Email:         ptr("test@example.com"),
			IsServiceUser: true,
			Name:          ptr("Nobody"),
			Role:          "user",
		})

		require.NoError(t, err)
		assert.Equal(t, "Nobody", user.Name)

		users, err := c.Users.List(context.Background())
		require.NoError(t, err)
		assert.NotEmpty(t, users)

		user, err = c.Users.Update(context.Background(), user.Id, api.UserRequest{
			AutoGroups: []string{},
			Role:       "admin",
		})

		require.NoError(t, err)
		assert.Equal(t, "admin", user.Role)

		err = c.Users.Delete(context.Background(), user.Id)
		require.NoError(t, err)
	})
}
