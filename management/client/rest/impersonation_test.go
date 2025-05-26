package rest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/client/rest"
	"github.com/netbirdio/netbird/management/server/http/api"
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
