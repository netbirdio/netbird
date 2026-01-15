//go:build integration

package rest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

var (
	testImpersonatedAccount = api.Account{
		Id: "ImpersonatedTest",
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

func TestImpersonation_Peers_List_200(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		impersonatedClient := c.Impersonate(testImpersonatedAccount.Id)
		mux.HandleFunc("/api/peers", func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, r.URL.Query().Get("account"), testImpersonatedAccount.Id)
			retBytes, _ := json.Marshal([]api.Peer{testPeer})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		ret, err := impersonatedClient.Peers.List(context.Background())
		require.NoError(t, err)
		assert.Len(t, ret, 1)
		assert.Equal(t, testPeer, ret[0])
	})
}

func TestImpersonation_Change_Account(t *testing.T) {
	withMockClient(func(c *rest.Client, mux *http.ServeMux) {
		impersonatedClient := c.Impersonate(testImpersonatedAccount.Id)
		mux.HandleFunc("/api/peers", func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, r.URL.Query().Get("account"), testImpersonatedAccount.Id)
			retBytes, _ := json.Marshal([]api.Peer{testPeer})
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})
		_, err := impersonatedClient.Peers.List(context.Background())
		require.NoError(t, err)

		impersonatedClient = impersonatedClient.Impersonate("another-test-account")
		mux.HandleFunc("/api/peers/Test", func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, r.URL.Query().Get("account"), "another-test-account")
			retBytes, _ := json.Marshal(testPeer)
			_, err := w.Write(retBytes)
			require.NoError(t, err)
		})

		_, err = impersonatedClient.Peers.Get(context.Background(), "Test")
		require.NoError(t, err)
	})
}
