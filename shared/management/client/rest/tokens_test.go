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
	testToken = api.PersonalAccessToken{
		Id:             "Test",
		CreatedAt:      time.Time{},
		CreatedBy:      "meow",
		ExpirationDate: time.Time{},
		LastUsed:       nil,
		Name:           "wow",
	}

	testTokenGenerated = api.PersonalAccessTokenGenerated{
		PersonalAccessToken: testToken,
		PlainToken:          "shhh",
	}
)

func TestTokens_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users/meow/tokens", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.PersonalAccessToken{testToken})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Tokens.List(context.Background(), "meow")
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testToken, ret[0])
	})
}

func TestTokens_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users/meow/tokens", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Tokens.List(context.Background(), "meow")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestTokens_Get_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users/meow/tokens/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(testToken)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Tokens.Get(context.Background(), "meow", "Test")
		require.NoError(t, err)
		assert.Equal(t, testToken, *ret)
	})
}

func TestTokens_Get_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users/meow/tokens/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Tokens.Get(context.Background(), "meow", "Test")
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestTokens_Create_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users/meow/tokens", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PostApiUsersUserIdTokensJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, 5, req.ExpiresIn)
			retBytes, _ := json.Marshal(testTokenGenerated)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Tokens.Create(context.Background(), "meow", api.PostApiUsersUserIdTokensJSONRequestBody{
			ExpiresIn: 5,
		})
		require.NoError(t, err)
		assert.Equal(t, testTokenGenerated, *ret)
	})
}

func TestTokens_Create_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users/meow/tokens", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Tokens.Create(context.Background(), "meow", api.PostApiUsersUserIdTokensJSONRequestBody{
			ExpiresIn: 5,
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestTokens_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users/meow/tokens/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.Tokens.Delete(context.Background(), "meow", "Test")
		require.NoError(t, err)
	})
}

func TestTokens_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/users/meow/tokens/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.Tokens.Delete(context.Background(), "meow", "Test")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestTokens_Integration(t *testing.T) {
	withBlackBoxServer(t, func(c *rest.Client) {
		tokenClear, err := c.Tokens.Create(context.Background(), "a23efe53-63fb-11ec-90d6-0242ac120003", api.PersonalAccessTokenRequest{
			Name:      "Test",
			ExpiresIn: 365,
		})

		require.NoError(t, err)
		assert.Equal(t, "Test", tokenClear.PersonalAccessToken.Name)

		tokens, err := c.Tokens.List(context.Background(), "a23efe53-63fb-11ec-90d6-0242ac120003")
		require.NoError(t, err)
		assert.Len(t, tokens, 2)

		token, err := c.Tokens.Get(context.Background(), "a23efe53-63fb-11ec-90d6-0242ac120003", tokenClear.PersonalAccessToken.Id)
		require.NoError(t, err)
		assert.Equal(t, "Test", token.Name)

		err = c.Tokens.Delete(context.Background(), "a23efe53-63fb-11ec-90d6-0242ac120003", token.Id)
		require.NoError(t, err)
	})
}
