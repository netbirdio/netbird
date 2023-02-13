package http

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/server/http/api"

	"github.com/netbirdio/netbird/management/server/jwtclaims"

	"github.com/magiconair/properties/assert"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/mock_server"
)

const testPeerID = "test_peer"

func initTestMetaData(peers ...*server.Peer) *Peers {
	return &Peers{
		accountManager: &mock_server.MockAccountManager{
			GetPeerFunc: func(accountID, peerID, userID string) (*server.Peer, error) {
				return peers[0], nil
			},
			GetPeersFunc: func(accountID, userID string) ([]*server.Peer, error) {
				return peers, nil
			},
			GetAccountFromTokenFunc: func(claims jwtclaims.AuthorizationClaims) (*server.Account, *server.User, error) {
				user := server.NewAdminUser("test_user")
				return &server.Account{
					Id:     claims.AccountId,
					Domain: "hotmail.com",
					Peers: map[string]*server.Peer{
						peers[0].ID: peers[0],
					},
					Users: map[string]*server.User{
						"test_user": user,
					},
					Settings: &server.Settings{
						PeerLoginExpirationEnabled: false,
						PeerLoginExpiration:        time.Hour,
					},
				}, user, nil
			},
		},
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithFromRequestContext(func(r *http.Request) jwtclaims.AuthorizationClaims {
				return jwtclaims.AuthorizationClaims{
					UserId:    "test_user",
					Domain:    "hotmail.com",
					AccountId: "test_id",
				}
			}),
		),
	}
}

// Tests the GetPeers endpoint reachable in the route /api/peers
// Use the metadata generated by initTestMetaData() to check for values
func TestGetPeers(t *testing.T) {
	tt := []struct {
		name           string
		expectedStatus int
		requestType    string
		requestPath    string
		requestBody    io.Reader
		expectedArray  bool
	}{
		{
			name:           "GetPeersMetaData",
			requestType:    http.MethodGet,
			requestPath:    "/api/peers/",
			expectedStatus: http.StatusOK,
			expectedArray:  true,
		},
		{
			name:           "GetPeer",
			requestType:    http.MethodGet,
			requestPath:    "/api/peers/" + testPeerID,
			expectedStatus: http.StatusOK,
			expectedArray:  false,
		},
	}

	rr := httptest.NewRecorder()
	peer := &server.Peer{
		ID:       testPeerID,
		Key:      "key",
		SetupKey: "setupkey",
		IP:       net.ParseIP("100.64.0.1"),
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
	}

	p := initTestMetaData(peer)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)

			router := mux.NewRouter()
			router.HandleFunc("/api/peers/", p.GetPeers).Methods("GET")
			router.HandleFunc("/api/peers/{id}", p.HandlePeer).Methods("GET")
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			defer res.Body.Close()

			if status := rr.Code; status != tc.expectedStatus {
				t.Fatalf("handler returned wrong status code: got %v want %v",
					status, http.StatusOK)
			}

			content, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("I don't know what I expected; %v", err)
			}

			var got *api.Peer
			if tc.expectedArray {
				respBody := []*api.Peer{}
				err = json.Unmarshal(content, &respBody)
				if err != nil {
					t.Fatalf("Sent content is not in correct json format; %v", err)
				}

				got = respBody[0]
			} else {
				got = &api.Peer{}
				err = json.Unmarshal(content, got)
				if err != nil {
					t.Fatalf("Sent content is not in correct json format; %v", err)
				}
			}

			assert.Equal(t, got.Name, peer.Name)
			assert.Equal(t, got.Version, peer.Meta.WtVersion)
			assert.Equal(t, got.Ip, peer.IP.String())
			assert.Equal(t, got.Os, "OS core")
		})
	}
}
