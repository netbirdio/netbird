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
	testAccount = api.Account{
		Id: "Test",
		Settings: api.AccountSettings{
			Extra: &api.AccountExtraSettings{
				PeerApprovalEnabled: false,
			},
			GroupsPropagationEnabled:        ptr(true),
			JwtGroupsEnabled:                ptr(false),
			PeerInactivityExpiration:        7,
			PeerInactivityExpirationEnabled: true,
			PeerLoginExpiration:             24,
			PeerLoginExpirationEnabled:      true,
			RegularUsersViewBlocked:         false,
			RoutingPeerDnsResolutionEnabled: ptr(false),
		},
	}
)

func TestAccounts_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/accounts", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal([]api.Account{testAccount})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Accounts.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testAccount, ret[0])
	})
}

func TestAccounts_List_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/accounts", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Accounts.List(context.Background())
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Empty(t, ret)
	})
}

func TestAccounts_List_ConnErr(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		ret, err := c.Accounts.List(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "404")
		assert.Empty(t, ret)
	})
}

func TestAccounts_Update_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/accounts/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "PUT", r.Method)
			reqBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var req api.PutApiAccountsAccountIdJSONRequestBody
			err = json.Unmarshal(reqBytes, &req)
			require.NoError(t, err)
			assert.Equal(t, true, *req.Settings.RoutingPeerDnsResolutionEnabled)
			retBytes, _ := json.Marshal(testAccount)
			_, err = w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Accounts.Update(context.Background(), "Test", api.PutApiAccountsAccountIdJSONRequestBody{
			Settings: api.AccountSettings{
				RoutingPeerDnsResolutionEnabled: ptr(true),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, testAccount, *ret)
	})

}

func TestAccounts_Update_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/accounts/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "No", Code: 400})
			w.WriteHeader(400)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := c.Accounts.Update(context.Background(), "Test", api.PutApiAccountsAccountIdJSONRequestBody{
			Settings: api.AccountSettings{
				RoutingPeerDnsResolutionEnabled: ptr(true),
			},
		})
		assert.Error(t, err)
		assert.Equal(t, "No", err.Error())
		assert.Nil(t, ret)
	})
}

func TestAccounts_Delete_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/accounts/Test", func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "DELETE", r.Method)
			w.WriteHeader(200)
		})
		err := c.Accounts.Delete(context.Background(), "Test")
		require.NoError(t, err)
	})
}

func TestAccounts_Delete_Err(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		mux.HandleFunc("/api/accounts/Test", func(w http.ResponseWriter, r *http.Request) {
			retBytes, _ := json.Marshal(util.ErrorResponse{Message: "Not found", Code: 404})
			w.WriteHeader(404)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		err := c.Accounts.Delete(context.Background(), "Test")
		assert.Error(t, err)
		assert.Equal(t, "Not found", err.Error())
	})
}

func TestAccounts_Integration_List(t *testing.T) {
	withBlackBoxServer(t, func(c *rest.Client) {
		accounts, err := c.Accounts.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, accounts, 1)
		assert.Equal(t, "bf1c8084-ba50-4ce7-9439-34653001fc3b", accounts[0].Id)
		assert.Equal(t, false, accounts[0].Settings.Extra.PeerApprovalEnabled)
	})
}

func TestAccounts_Integration_Update(t *testing.T) {
	withBlackBoxServer(t, func(c *rest.Client) {
		accounts, err := c.Accounts.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, accounts, 1)
		accounts[0].Settings.JwtAllowGroups = ptr([]string{"test"})
		account, err := c.Accounts.Update(context.Background(), accounts[0].Id, api.AccountRequest{
			Settings: accounts[0].Settings,
		})
		require.NoError(t, err)
		assert.Equal(t, accounts[0].Id, account.Id)
		assert.Equal(t, []string{"test"}, *account.Settings.JwtAllowGroups)
	})
}

// Account deletion on MySQL and PostgreSQL databases causes unknown errors
// func TestAccounts_Integration_Delete(t *testing.T) {
// 	withBlackBoxServer(t, func(c *rest.Client) {
// 		accounts, err := c.Accounts.List(context.Background())
// 		require.NoError(t, err)
// 		assert.Len(t, accounts, 1)
// 		err = c.Accounts.Delete(context.Background(), accounts[0].Id)
// 		require.NoError(t, err)
// 		_, err = c.Accounts.List(context.Background())
// 		assert.Error(t, err)
// 	})
// }
