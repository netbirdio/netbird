package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wiretrustee/wiretrustee/management/server"
	"github.com/wiretrustee/wiretrustee/management/server/mock_server"
)

// 1. mock the server, and the JWTtokenvalidator, so we can
// 2. analyze request pattern, what we need to trigger the wanted endpoints
// 3. prepare testdata for the purpose of testing
// 4. check the return values with the test data
func TestHandlePeer(t *testing.T) {
	var tt = []struct {
		request *http.Request
		want    []byte
	}{
		{httptest.NewRequest(http.MethodGet, "", nil), []byte(`{"Name": "Bob"}`)},
		{httptest.NewRequest(http.MethodGet, "", nil), []byte(`{"Name": "Bob"}`)},
		{httptest.NewRequest(http.MethodDelete, "", nil), []byte(`{"Name": "Bob"}`)},
		{httptest.NewRequest(http.MethodPut, "", nil), []byte(`{"Name": "Bob"}`)},
	}

	p := &Peers{
		accountManager: &mock_server.MockAccountManager{
			GetAccountByUserOrAccountIdFunc: func(userId, accountId, domain string) (*server.Account, error) {
				return &server.Account{}, nil
			},
			GetPeerByIPFunc: func(accountId string, peerIP string) (*server.Peer, error) {
				return &server.Peer{}, nil
			},
			RenamePeerFunc: func(accountId string, peerKey string, newName string) (*server.Peer, error) {
				return &server.Peer{}, nil
			},
			DeletePeerFunc: func(accountId string, peerKey string) (*server.Peer, error) {
				return &server.Peer{}, nil
			},
		},
		authAudience: "",
		jwtExtractor: JWTClaimsExtractor{
			extractClaimsFromRequestContext: func(r *http.Request, authAudiance string) JWTClaims {
				return JWTClaims{
					UserId:    "test_user",
					Domain:    "hotmail.com",
					AccountId: "",
				}
			},
		},
	}

	rr := httptest.NewRecorder()

	for _, tv := range tt {
		p.HandlePeer(rr, tv.request)

		// Check the status code is what we expect.
		if status := rr.Code; status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v",
				status, http.StatusOK)
		}

		if bytes.Compare([]byte(rr.Body.String()), tv.want) != 0 {
			t.Errorf("handler returned unexpected body: got %v want %v",
				rr.Body.String(), tv.want)
		}
	}
}

func createManager(t *testing.T) (*server.DefaultAccountManager, error) {
	store, err := createStore(t)
	if err != nil {
		return nil, err
	}
	return server.NewManager(store, server.NewPeersUpdateManager(), nil), nil
}

func createStore(t *testing.T) (server.Store, error) {
	dataDir := t.TempDir()
	store, err := server.NewStore(dataDir)
	if err != nil {
		return nil, err
	}

	return store, nil
}
