package peers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	ugomock "go.uber.org/mock/gomock"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/mock_server"
)

const (
	testPeerID                = "test_peer"
	noUpdateChannelTestPeerID = "no-update-channel"

	adminUser   = "admin_user"
	regularUser = "regular_user"
	serviceUser = "service_user"
)

func initTestMetaData(t *testing.T, peers ...*nbpeer.Peer) *Handler {

	peersMap := make(map[string]*nbpeer.Peer)
	for _, peer := range peers {
		peersMap[peer.ID] = peer.Copy()
	}

	policy := &types.Policy{
		ID:        "policy",
		AccountID: "test_id",
		Name:      "policy",
		Enabled:   true,
		Rules: []*types.PolicyRule{
			{
				ID:            "rule",
				Name:          "rule",
				Enabled:       true,
				Action:        "accept",
				Destinations:  []string{"group1"},
				Sources:       []string{"group1"},
				Bidirectional: true,
				Protocol:      "all",
				Ports:         []string{"80"},
			},
		},
	}

	srvUser := types.NewRegularUser(serviceUser, "", "")
	srvUser.IsServiceUser = true

	account := &types.Account{
		Id:     "test_id",
		Domain: "hotmail.com",
		Peers:  peersMap,
		Users: map[string]*types.User{
			adminUser:   types.NewAdminUser(adminUser),
			regularUser: types.NewRegularUser(regularUser, "", ""),
			serviceUser: srvUser,
		},
		Groups: map[string]*types.Group{
			"group1": {
				ID:        "group1",
				AccountID: "test_id",
				Name:      "group1",
				Issued:    "api",
				Peers:     maps.Keys(peersMap),
			},
		},
		Settings: &types.Settings{
			PeerLoginExpirationEnabled: true,
			PeerLoginExpiration:        time.Hour,
		},
		Policies: []*types.Policy{policy},
		Network: &types.Network{
			Identifier: "ciclqisab2ss43jdn8q0",
			Net: net.IPNet{
				IP:   net.ParseIP("100.67.0.0"),
				Mask: net.IPv4Mask(255, 255, 0, 0),
			},
			Serial: 51,
		},
	}

	ctrl := ugomock.NewController(t)

	networkMapController := network_map.NewMockController(ctrl)
	networkMapController.EXPECT().
		GetDNSDomain(gomock.Any()).
		Return("domain").
		AnyTimes()

	ctrl2 := gomock.NewController(t)
	permissionsManager := permissions.NewMockManager(ctrl2)
	permissionsManager.EXPECT().ValidateAccountAccess(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	return &Handler{
		accountManager: &mock_server.MockAccountManager{
			UpdatePeerFunc: func(_ context.Context, accountID, userID string, update *nbpeer.Peer) (*nbpeer.Peer, error) {
				var p *nbpeer.Peer
				for _, peer := range peers {
					if update.ID == peer.ID {
						p = peer.Copy()
						break
					}
				}
				p.SSHEnabled = update.SSHEnabled
				p.LoginExpirationEnabled = update.LoginExpirationEnabled
				p.Name = update.Name
				return p, nil
			},
			UpdatePeerIPFunc: func(_ context.Context, accountID, userID, peerID string, newIP netip.Addr) error {
				for _, peer := range peers {
					if peer.ID == peerID {
						peer.IP = net.IP(newIP.AsSlice())
						return nil
					}
				}
				return fmt.Errorf("peer not found")
			},
			GetPeerFunc: func(_ context.Context, accountID, peerID, userID string) (*nbpeer.Peer, error) {
				var p *nbpeer.Peer
				for _, peer := range peers {
					if peerID == peer.ID {
						p = peer.Copy()
						break
					}
				}
				return p, nil
			},
			GetUserByIDFunc: func(ctx context.Context, id string) (*types.User, error) {
				switch id {
				case adminUser:
					return account.Users[adminUser], nil
				case regularUser:
					return account.Users[regularUser], nil
				case serviceUser:
					return account.Users[serviceUser], nil
				default:
					return nil, fmt.Errorf("user not found")
				}
			},
			GetPeersFunc: func(_ context.Context, accountID, userID, nameFilter, ipFilter string) ([]*nbpeer.Peer, error) {
				return peers, nil
			},
			GetPeerGroupsFunc: func(ctx context.Context, accountID, peerID string) ([]*types.Group, error) {
				peersID := make([]string, len(peers))
				for _, peer := range peers {
					peersID = append(peersID, peer.ID)
				}
				return []*types.Group{
					{
						ID:        "group1",
						AccountID: accountID,
						Name:      "group1",
						Issued:    "api",
						Peers:     peersID,
					},
				}, nil
			},
			GetDNSDomainFunc: func(settings *types.Settings) string {
				return "netbird.selfhosted"
			},
			GetAccountFunc: func(ctx context.Context, accountID string) (*types.Account, error) {
				return account, nil
			},
			GetAccountByIDFunc: func(ctx context.Context, accountID string, userID string) (*types.Account, error) {
				return account, nil
			},
			HasConnectedChannelFunc: func(peerID string) bool {
				statuses := make(map[string]struct{})
				for _, peer := range peers {
					if peer.ID == noUpdateChannelTestPeerID {
						break
					}
					statuses[peer.ID] = struct{}{}
				}
				_, ok := statuses[peerID]
				return ok
			},
			GetAccountSettingsFunc: func(ctx context.Context, accountID string, userID string) (*types.Settings, error) {
				return account.Settings, nil
			},
		},
		networkMapController: networkMapController,
		permissionsManager:   permissionsManager,
	}
}

// Tests the GetAllPeers endpoint reachable in the route /api/peers
// Use the metadata generated by initTestMetaData() to check for values
func TestGetPeers(t *testing.T) {

	peer := &nbpeer.Peer{
		ID:                     testPeerID,
		Key:                    "key",
		IP:                     net.ParseIP("100.64.0.1"),
		Status:                 &nbpeer.PeerStatus{Connected: true},
		Name:                   "PeerName",
		LoginExpirationEnabled: false,
		Meta: nbpeer.PeerSystemMeta{
			Hostname:           "hostname",
			GoOS:               "GoOS",
			Kernel:             "kernel",
			Core:               "core",
			Platform:           "platform",
			OS:                 "OS",
			WtVersion:          "development",
			SystemSerialNumber: "C02XJ0J0JGH7",
		},
	}

	peer1 := peer.Copy()
	peer1.ID = noUpdateChannelTestPeerID

	expectedUpdatedPeer := peer.Copy()
	expectedUpdatedPeer.LoginExpirationEnabled = true
	expectedUpdatedPeer.SSHEnabled = true
	expectedUpdatedPeer.Name = "New Name"

	expectedPeer1 := peer1.Copy()
	expectedPeer1.Status.Connected = false

	tt := []struct {
		name           string
		expectedStatus int
		requestType    string
		requestPath    string
		requestBody    io.Reader
		expectedArray  bool
		expectedPeer   *nbpeer.Peer
	}{
		{
			name:           "GetPeersMetaData",
			requestType:    http.MethodGet,
			requestPath:    "/api/peers/",
			expectedStatus: http.StatusOK,
			expectedArray:  true,
			expectedPeer:   peer,
		},
		{
			name:           "GetPeer with update channel",
			requestType:    http.MethodGet,
			requestPath:    "/api/peers/" + testPeerID,
			expectedStatus: http.StatusOK,
			expectedArray:  false,
			expectedPeer:   peer,
		},
		{
			name:           "PutPeer",
			requestType:    http.MethodPut,
			requestPath:    "/api/peers/" + testPeerID,
			expectedStatus: http.StatusOK,
			expectedArray:  false,
			requestBody:    bytes.NewBufferString("{\"login_expiration_enabled\":true,\"name\":\"New Name\",\"ssh_enabled\":true}"),
			expectedPeer:   expectedUpdatedPeer,
		},
	}

	rr := httptest.NewRecorder()

	p := initTestMetaData(t, peer, peer1)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.requestType, tc.requestPath, tc.requestBody)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    "admin_user",
				Domain:    "hotmail.com",
				AccountId: "test_id",
			})

			router := mux.NewRouter()
			router.HandleFunc("/api/peers/", p.GetAllPeers).Methods("GET")
			router.HandleFunc("/api/peers/{peerId}", p.HandlePeer).Methods("GET")
			router.HandleFunc("/api/peers/{peerId}", p.HandlePeer).Methods("PUT")
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

				// hardcode this check for now as we only have two peers in this suite
				assert.Equal(t, len(respBody), 2)

				for _, peer := range respBody {
					if peer.Id == testPeerID {
						got = peer
					}
				}

			} else {
				got = &api.Peer{}
				err = json.Unmarshal(content, got)
				if err != nil {
					t.Fatalf("Sent content is not in correct json format; %v", err)
				}
			}

			t.Log(got)

			assert.Equal(t, tc.expectedPeer.Name, got.Name)
			assert.Equal(t, tc.expectedPeer.Meta.WtVersion, got.Version)
			assert.Equal(t, tc.expectedPeer.IP.String(), got.Ip)
			assert.Equal(t, "OS core", got.Os)
			assert.Equal(t, tc.expectedPeer.LoginExpirationEnabled, got.LoginExpirationEnabled)
			assert.Equal(t, tc.expectedPeer.SSHEnabled, got.SshEnabled)
			assert.Equal(t, tc.expectedPeer.Status.Connected, got.Connected)
			assert.Equal(t, tc.expectedPeer.Meta.SystemSerialNumber, got.SerialNumber)
		})
	}
}

func TestGetAccessiblePeers(t *testing.T) {
	peer1 := &nbpeer.Peer{
		ID:                     "peer1",
		Key:                    "key1",
		IP:                     net.ParseIP("100.64.0.1"),
		Status:                 &nbpeer.PeerStatus{Connected: true},
		Name:                   "peer1",
		LoginExpirationEnabled: false,
		UserID:                 regularUser,
	}

	peer2 := &nbpeer.Peer{
		ID:                     "peer2",
		Key:                    "key2",
		IP:                     net.ParseIP("100.64.0.2"),
		Status:                 &nbpeer.PeerStatus{Connected: true},
		Name:                   "peer2",
		LoginExpirationEnabled: false,
		UserID:                 adminUser,
	}

	peer3 := &nbpeer.Peer{
		ID:                     "peer3",
		Key:                    "key3",
		IP:                     net.ParseIP("100.64.0.3"),
		Status:                 &nbpeer.PeerStatus{Connected: true},
		Name:                   "peer3",
		LoginExpirationEnabled: false,
		UserID:                 regularUser,
	}

	p := initTestMetaData(t, peer1, peer2, peer3)

	tt := []struct {
		name           string
		peerID         string
		callerUserID   string
		expectedStatus int
		expectedPeers  []string
	}{
		{
			name:           "non admin user can access owned peer",
			peerID:         "peer1",
			callerUserID:   regularUser,
			expectedStatus: http.StatusOK,
			expectedPeers:  []string{"peer2", "peer3"},
		},
		{
			name:           "non admin user can't access unowned peer",
			peerID:         "peer2",
			callerUserID:   regularUser,
			expectedStatus: http.StatusOK,
			expectedPeers:  []string{},
		},
		{
			name:           "admin user can access owned peer",
			peerID:         "peer2",
			callerUserID:   adminUser,
			expectedStatus: http.StatusOK,
			expectedPeers:  []string{"peer1", "peer3"},
		},
		{
			name:           "admin user can access unowned peer",
			peerID:         "peer3",
			callerUserID:   adminUser,
			expectedStatus: http.StatusOK,
			expectedPeers:  []string{"peer1", "peer2"},
		},
		{
			name:           "service user can access unowned peer",
			peerID:         "peer3",
			callerUserID:   serviceUser,
			expectedStatus: http.StatusOK,
			expectedPeers:  []string{"peer1", "peer2"},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/peers/%s/accessible-peers", tc.peerID), nil)
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    tc.callerUserID,
				Domain:    "hotmail.com",
				AccountId: "test_id",
			})

			router := mux.NewRouter()
			router.HandleFunc("/api/peers/{peerId}/accessible-peers", p.GetAccessiblePeers).Methods("GET")
			router.ServeHTTP(recorder, req)

			res := recorder.Result()
			if res.StatusCode != tc.expectedStatus {
				t.Fatalf("handler returned wrong status code: got %v want %v", res.StatusCode, tc.expectedStatus)
			}

			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}
			defer res.Body.Close()

			var accessiblePeers []api.AccessiblePeer
			err = json.Unmarshal(body, &accessiblePeers)
			if err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			peerIDs := make([]string, len(accessiblePeers))
			for i, peer := range accessiblePeers {
				peerIDs[i] = peer.Id
			}

			assert.ElementsMatch(t, peerIDs, tc.expectedPeers)
		})
	}
}

func TestPeersHandlerUpdatePeerIP(t *testing.T) {
	testPeer := &nbpeer.Peer{
		ID:                     testPeerID,
		Key:                    "key",
		IP:                     net.ParseIP("100.64.0.1"),
		Status:                 &nbpeer.PeerStatus{Connected: false, LastSeen: time.Now()},
		Name:                   "test-host@netbird.io",
		LoginExpirationEnabled: false,
		UserID:                 regularUser,
		Meta: nbpeer.PeerSystemMeta{
			Hostname: "test-host@netbird.io",
			Core:     "22.04",
		},
	}

	p := initTestMetaData(t, testPeer)

	tt := []struct {
		name           string
		peerID         string
		requestBody    string
		callerUserID   string
		expectedStatus int
		expectedIP     string
	}{
		{
			name:           "update peer IP successfully",
			peerID:         testPeerID,
			requestBody:    `{"ip": "100.64.0.100"}`,
			callerUserID:   adminUser,
			expectedStatus: http.StatusOK,
			expectedIP:     "100.64.0.100",
		},
		{
			name:           "update peer IP with invalid IP",
			peerID:         testPeerID,
			requestBody:    `{"ip": "invalid-ip"}`,
			callerUserID:   adminUser,
			expectedStatus: http.StatusUnprocessableEntity,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/peers/%s", tc.peerID), bytes.NewBuffer([]byte(tc.requestBody)))
			req.Header.Set("Content-Type", "application/json")
			req = nbcontext.SetUserAuthInRequest(req, auth.UserAuth{
				UserId:    tc.callerUserID,
				Domain:    "hotmail.com",
				AccountId: "test_id",
			})

			rr := httptest.NewRecorder()
			router := mux.NewRouter()
			router.HandleFunc("/peers/{peerId}", p.HandlePeer).Methods("PUT")

			router.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)

			if tc.expectedStatus == http.StatusOK && tc.expectedIP != "" {
				var updatedPeer api.Peer
				err := json.Unmarshal(rr.Body.Bytes(), &updatedPeer)
				require.NoError(t, err)
				assert.Equal(t, tc.expectedIP, updatedPeer.Ip)
			}
		})
	}
}
