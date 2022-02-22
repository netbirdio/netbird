package handler

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/magiconair/properties/assert"
	"github.com/wiretrustee/wiretrustee/management/server"
	"github.com/wiretrustee/wiretrustee/management/server/mock_server"
)

func initPeer() *Peers {
	return &Peers{
		accountManager: &mock_server.MockAccountManager{
			GetAccountByUserOrAccountIdFunc: func(userId, accountId, domain string) (*server.Account, error) {
				return &server.Account{
					Id:     accountId,
					Domain: "hotmail.com",
					// CreatedBy: "test_date",
					// User.Id   it was created by
					// CreatedBy string
					// Domain    string
					// SetupKeys map[string]*SetupKey
					// Network   *Network
					// Peers     map[string]*Peer
					Peers: map[string]*server.Peer{
						"test_user": &server.Peer{
							Key:      "key",
							SetupKey: "setupkey",
							IP:       net.IP("Ipv4"),
							Status:   &server.PeerStatus{},
							Name:     "PeerName",
							Meta: server.PeerSystemMeta{
								Hostname:  "hostname",
								GoOS:      "GoOS",
								Kernel:    "kernel",
								Core:      "core",
								Platform:  "platform",
								OS:        "OS",
								WtVersion: "development",
							},
						},
					},
					// Users     map[string]*User
				}, nil
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
					AccountId: "test_id",
				}
			},
		},
	}
}

// 1. mock the server, and the JWTtokenvalidator, so we can
// 2. analyze request pattern, what we need to trigger the wanted endpoints
// 3. prepare testdata for the purpose of testing
// 4. check the return values with the test data
func TestHandlePeer(t *testing.T) {
	var tt = []struct {
		name               string
		expected           []byte
		requestType        string
		requestPath        string
		requestBody        io.Reader
		requestHeaderKey   string
		requestHeaderValue string
	}{
		{name: "GetPeers", requestType: http.MethodGet, requestPath: "/api/peers/", requestHeaderKey: "key", requestHeaderValue: "value", expected: []byte(`{"Name": "Bob"}`)},
	}

	rr := httptest.NewRecorder()
	p := initPeer()

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			p.GetPeers(rr, req)

			res := rr.Result()
			defer res.Body.Close()

			// Check the status code is what we expect.
			if status := rr.Code; status != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, http.StatusOK)
			}

			content, err := io.ReadAll(res.Body)
			if err != nil {
				t.Errorf("I don't know what I expected; %v", err)
			}

			respBody := []*PeerResponse{}
			err = json.Unmarshal(content, &respBody)
			if err != nil {
				t.Errorf("Sent content is not in correct json format; %v", err)
			}

			assert.Equal(t, respBody[0].Version, "development")
		})
	}
}
