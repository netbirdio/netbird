//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools/channel"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	testPeerId2 = "testPeerId2"
)

func Test_Peers_GetAll(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{
			name:           "Regular user",
			userId:         testing_tools.TestUserId,
			expectResponse: false,
		},
		{
			name:           "Admin user",
			userId:         testing_tools.TestAdminId,
			expectResponse: true,
		},
		{
			name:           "Owner user",
			userId:         testing_tools.TestOwnerId,
			expectResponse: true,
		},
		{
			name:           "Regular service user",
			userId:         testing_tools.TestServiceUserId,
			expectResponse: true,
		},
		{
			name:           "Admin service user",
			userId:         testing_tools.TestServiceAdminId,
			expectResponse: true,
		},
		{
			name:           "Blocked user",
			userId:         testing_tools.BlockedUserId,
			expectResponse: false,
		},
		{
			name:           "Other user",
			userId:         testing_tools.OtherUserId,
			expectResponse: false,
		},
		{
			name:           "Invalid token",
			userId:         testing_tools.InvalidToken,
			expectResponse: false,
		},
	}

	for _, user := range users {
		t.Run(user.name+" - Get all peers", func(t *testing.T) {
			apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/peers_integration.sql", nil, true)

			req := testing_tools.BuildRequest(t, []byte{}, http.MethodGet, "/api/peers", user.userId)
			recorder := httptest.NewRecorder()

			apiHandler.ServeHTTP(recorder, req)

			content, expectResponse := testing_tools.ReadResponse(t, recorder, http.StatusOK, user.expectResponse)
			if !expectResponse {
				return
			}

			var got []api.PeerBatch
			if err := json.Unmarshal(content, &got); err != nil {
				t.Fatalf("Sent content is not in correct json format; %v", err)
			}

			assert.GreaterOrEqual(t, len(got), 2, "Expected at least 2 peers")

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout waiting for peerShouldNotReceiveUpdate")
			}
		})
	}
}

func Test_Peers_GetById(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{
			name:           "Regular user",
			userId:         testing_tools.TestUserId,
			expectResponse: false,
		},
		{
			name:           "Admin user",
			userId:         testing_tools.TestAdminId,
			expectResponse: true,
		},
		{
			name:           "Owner user",
			userId:         testing_tools.TestOwnerId,
			expectResponse: true,
		},
		{
			name:           "Regular service user",
			userId:         testing_tools.TestServiceUserId,
			expectResponse: true,
		},
		{
			name:           "Admin service user",
			userId:         testing_tools.TestServiceAdminId,
			expectResponse: true,
		},
		{
			name:           "Blocked user",
			userId:         testing_tools.BlockedUserId,
			expectResponse: false,
		},
		{
			name:           "Other user",
			userId:         testing_tools.OtherUserId,
			expectResponse: false,
		},
		{
			name:           "Invalid token",
			userId:         testing_tools.InvalidToken,
			expectResponse: false,
		},
	}

	tt := []struct {
		name           string
		expectedStatus int
		requestType    string
		requestPath    string
		requestId      string
		verifyResponse func(t *testing.T, peer *api.Peer)
	}{
		{
			name:           "Get existing peer",
			requestType:    http.MethodGet,
			requestPath:    "/api/peers/{peerId}",
			requestId:      testing_tools.TestPeerId,
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, peer *api.Peer) {
				t.Helper()
				assert.Equal(t, testing_tools.TestPeerId, peer.Id)
				assert.Equal(t, "test-peer-1", peer.Name)
				assert.Equal(t, "test-host-1", peer.Hostname)
				assert.Equal(t, "Debian GNU/Linux ", peer.Os)
				assert.Equal(t, "0.12.0", peer.Version)
				assert.Equal(t, false, peer.SshEnabled)
				assert.Equal(t, true, peer.LoginExpirationEnabled)
			},
		},
		{
			name:           "Get second existing peer",
			requestType:    http.MethodGet,
			requestPath:    "/api/peers/{peerId}",
			requestId:      testPeerId2,
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, peer *api.Peer) {
				t.Helper()
				assert.Equal(t, testPeerId2, peer.Id)
				assert.Equal(t, "test-peer-2", peer.Name)
				assert.Equal(t, "test-host-2", peer.Hostname)
				assert.Equal(t, "Ubuntu ", peer.Os)
				assert.Equal(t, true, peer.SshEnabled)
				assert.Equal(t, false, peer.LoginExpirationEnabled)
				assert.Equal(t, true, peer.Connected)
			},
		},
		{
			name:           "Get non-existing peer",
			requestType:    http.MethodGet,
			requestPath:    "/api/peers/{peerId}",
			requestId:      "nonExistingPeerId",
			expectedStatus: http.StatusNotFound,
			verifyResponse: nil,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/peers_integration.sql", nil, true)

				req := testing_tools.BuildRequest(t, []byte{}, tc.requestType, strings.Replace(tc.requestPath, "{peerId}", tc.requestId, 1), user.userId)
				recorder := httptest.NewRecorder()

				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.Peer{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)
				}

				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("timeout waiting for peerShouldNotReceiveUpdate")
				}
			})
		}
	}
}

func Test_Peers_Update(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{
			name:           "Regular user",
			userId:         testing_tools.TestUserId,
			expectResponse: false,
		},
		{
			name:           "Admin user",
			userId:         testing_tools.TestAdminId,
			expectResponse: true,
		},
		{
			name:           "Owner user",
			userId:         testing_tools.TestOwnerId,
			expectResponse: true,
		},
		{
			name:           "Regular service user",
			userId:         testing_tools.TestServiceUserId,
			expectResponse: false,
		},
		{
			name:           "Admin service user",
			userId:         testing_tools.TestServiceAdminId,
			expectResponse: true,
		},
		{
			name:           "Blocked user",
			userId:         testing_tools.BlockedUserId,
			expectResponse: false,
		},
		{
			name:           "Other user",
			userId:         testing_tools.OtherUserId,
			expectResponse: false,
		},
		{
			name:           "Invalid token",
			userId:         testing_tools.InvalidToken,
			expectResponse: false,
		},
	}

	tt := []struct {
		name           string
		expectedStatus int
		requestBody    *api.PeerRequest
		requestType    string
		requestPath    string
		requestId      string
		verifyResponse func(t *testing.T, peer *api.Peer)
	}{
		{
			name:        "Update peer name",
			requestType: http.MethodPut,
			requestPath: "/api/peers/{peerId}",
			requestId:   testing_tools.TestPeerId,
			requestBody: &api.PeerRequest{
				Name:                        "updated-peer-name",
				SshEnabled:                  false,
				LoginExpirationEnabled:      true,
				InactivityExpirationEnabled: false,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, peer *api.Peer) {
				t.Helper()
				assert.Equal(t, testing_tools.TestPeerId, peer.Id)
				assert.Equal(t, "updated-peer-name", peer.Name)
				assert.Equal(t, false, peer.SshEnabled)
				assert.Equal(t, true, peer.LoginExpirationEnabled)
			},
		},
		{
			name:        "Enable SSH on peer",
			requestType: http.MethodPut,
			requestPath: "/api/peers/{peerId}",
			requestId:   testing_tools.TestPeerId,
			requestBody: &api.PeerRequest{
				Name:                        "test-peer-1",
				SshEnabled:                  true,
				LoginExpirationEnabled:      true,
				InactivityExpirationEnabled: false,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, peer *api.Peer) {
				t.Helper()
				assert.Equal(t, testing_tools.TestPeerId, peer.Id)
				assert.Equal(t, "test-peer-1", peer.Name)
				assert.Equal(t, true, peer.SshEnabled)
				assert.Equal(t, true, peer.LoginExpirationEnabled)
			},
		},
		{
			name:        "Disable login expiration on peer",
			requestType: http.MethodPut,
			requestPath: "/api/peers/{peerId}",
			requestId:   testing_tools.TestPeerId,
			requestBody: &api.PeerRequest{
				Name:                        "test-peer-1",
				SshEnabled:                  false,
				LoginExpirationEnabled:      false,
				InactivityExpirationEnabled: false,
			},
			expectedStatus: http.StatusOK,
			verifyResponse: func(t *testing.T, peer *api.Peer) {
				t.Helper()
				assert.Equal(t, testing_tools.TestPeerId, peer.Id)
				assert.Equal(t, false, peer.LoginExpirationEnabled)
			},
		},
		{
			name:        "Update non-existing peer",
			requestType: http.MethodPut,
			requestPath: "/api/peers/{peerId}",
			requestId:   "nonExistingPeerId",
			requestBody: &api.PeerRequest{
				Name:                        "updated-name",
				SshEnabled:                  false,
				LoginExpirationEnabled:      false,
				InactivityExpirationEnabled: false,
			},
			expectedStatus: http.StatusNotFound,
			verifyResponse: nil,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/peers_integration.sql", nil, false)

				body, err := json.Marshal(tc.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}

				req := testing_tools.BuildRequest(t, body, tc.requestType, strings.Replace(tc.requestPath, "{peerId}", tc.requestId, 1), user.userId)
				recorder := httptest.NewRecorder()

				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.verifyResponse != nil {
					got := &api.Peer{}
					if err := json.Unmarshal(content, got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					tc.verifyResponse(t, got)

					// Verify updated peer in DB
					db := testing_tools.GetDB(t, am.GetStore())
					dbPeer := testing_tools.VerifyPeerInDB(t, db, tc.requestId)
					assert.Equal(t, tc.requestBody.Name, dbPeer.Name)
					assert.Equal(t, tc.requestBody.SshEnabled, dbPeer.SSHEnabled)
					assert.Equal(t, tc.requestBody.LoginExpirationEnabled, dbPeer.LoginExpirationEnabled)
					assert.Equal(t, tc.requestBody.InactivityExpirationEnabled, dbPeer.InactivityExpirationEnabled)
				}
			})
		}
	}
}

func Test_Peers_Delete(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{
			name:           "Regular user",
			userId:         testing_tools.TestUserId,
			expectResponse: false,
		},
		{
			name:           "Admin user",
			userId:         testing_tools.TestAdminId,
			expectResponse: true,
		},
		{
			name:           "Owner user",
			userId:         testing_tools.TestOwnerId,
			expectResponse: true,
		},
		{
			name:           "Regular service user",
			userId:         testing_tools.TestServiceUserId,
			expectResponse: false,
		},
		{
			name:           "Admin service user",
			userId:         testing_tools.TestServiceAdminId,
			expectResponse: true,
		},
		{
			name:           "Blocked user",
			userId:         testing_tools.BlockedUserId,
			expectResponse: false,
		},
		{
			name:           "Other user",
			userId:         testing_tools.OtherUserId,
			expectResponse: false,
		},
		{
			name:           "Invalid token",
			userId:         testing_tools.InvalidToken,
			expectResponse: false,
		},
	}

	tt := []struct {
		name           string
		expectedStatus int
		requestType    string
		requestPath    string
		requestId      string
	}{
		{
			name:           "Delete existing peer",
			requestType:    http.MethodDelete,
			requestPath:    "/api/peers/{peerId}",
			requestId:      testPeerId2,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Delete non-existing peer",
			requestType:    http.MethodDelete,
			requestPath:    "/api/peers/{peerId}",
			requestId:      "nonExistingPeerId",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, am, _ := channel.BuildApiBlackBoxWithDBState(t, "../testdata/peers_integration.sql", nil, false)

				req := testing_tools.BuildRequest(t, []byte{}, tc.requestType, strings.Replace(tc.requestPath, "{peerId}", tc.requestId, 1), user.userId)
				recorder := httptest.NewRecorder()

				apiHandler.ServeHTTP(recorder, req)

				_, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				// Verify peer is actually deleted in DB
				if tc.expectedStatus == http.StatusOK {
					db := testing_tools.GetDB(t, am.GetStore())
					testing_tools.VerifyPeerNotInDB(t, db, tc.requestId)
				}
			})
		}
	}
}

func Test_Peers_GetAccessiblePeers(t *testing.T) {
	users := []struct {
		name           string
		userId         string
		expectResponse bool
	}{
		{
			name:           "Regular user",
			userId:         testing_tools.TestUserId,
			expectResponse: false,
		},
		{
			name:           "Admin user",
			userId:         testing_tools.TestAdminId,
			expectResponse: true,
		},
		{
			name:           "Owner user",
			userId:         testing_tools.TestOwnerId,
			expectResponse: true,
		},
		{
			name:           "Regular service user",
			userId:         testing_tools.TestServiceUserId,
			expectResponse: false,
		},
		{
			name:           "Admin service user",
			userId:         testing_tools.TestServiceAdminId,
			expectResponse: true,
		},
		{
			name:           "Blocked user",
			userId:         testing_tools.BlockedUserId,
			expectResponse: false,
		},
		{
			name:           "Other user",
			userId:         testing_tools.OtherUserId,
			expectResponse: false,
		},
		{
			name:           "Invalid token",
			userId:         testing_tools.InvalidToken,
			expectResponse: false,
		},
	}

	tt := []struct {
		name           string
		expectedStatus int
		requestType    string
		requestPath    string
		requestId      string
	}{
		{
			name:           "Get accessible peers for existing peer",
			requestType:    http.MethodGet,
			requestPath:    "/api/peers/{peerId}/accessible-peers",
			requestId:      testing_tools.TestPeerId,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Get accessible peers for non-existing peer",
			requestType:    http.MethodGet,
			requestPath:    "/api/peers/{peerId}/accessible-peers",
			requestId:      "nonExistingPeerId",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range tt {
		for _, user := range users {
			t.Run(user.name+" - "+tc.name, func(t *testing.T) {
				apiHandler, _, done := channel.BuildApiBlackBoxWithDBState(t, "../testdata/peers_integration.sql", nil, true)

				req := testing_tools.BuildRequest(t, []byte{}, tc.requestType, strings.Replace(tc.requestPath, "{peerId}", tc.requestId, 1), user.userId)
				recorder := httptest.NewRecorder()

				apiHandler.ServeHTTP(recorder, req)

				content, expectResponse := testing_tools.ReadResponse(t, recorder, tc.expectedStatus, user.expectResponse)
				if !expectResponse {
					return
				}

				if tc.expectedStatus == http.StatusOK {
					var got []api.AccessiblePeer
					if err := json.Unmarshal(content, &got); err != nil {
						t.Fatalf("Sent content is not in correct json format; %v", err)
					}
					// The accessible peers list should be a valid array (may be empty if no policies connect peers)
					assert.NotNil(t, got, "Expected accessible peers to be a valid array")
				}

				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("timeout waiting for peerShouldNotReceiveUpdate")
				}
			})
		}
	}
}
