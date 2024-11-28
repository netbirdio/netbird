package http

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/geolocation"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

type TB interface {
	Cleanup(func())
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	TempDir() string
}

func buildApiBlackBoxWithDBState(t TB, sqlFile string, expectedPeerUpdate *server.UpdateMessage) (http.Handler, server.AccountManager, chan struct{}) {
	store, cleanup, err := server.NewTestStoreFromSQL(context.Background(), sqlFile, t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create test store: %v", err)
	}
	t.Cleanup(cleanup)

	metrics, err := telemetry.NewDefaultAppMetrics(context.Background())
	if err != nil {
		t.Fatalf("Failed to create metrics: %v", err)
	}

	peersUpdateManager := server.NewPeersUpdateManager(nil)
	updMsg := peersUpdateManager.CreateChannel(context.Background(), testPeerId)
	done := make(chan struct{})
	go func() {
		if expectedPeerUpdate != nil {
			peerShouldReceiveUpdate(t, updMsg, expectedPeerUpdate)
		} else {
			peerShouldNotReceiveUpdate(t, updMsg)
		}
		close(done)
	}()

	geoMock := &geolocation.Mock{}
	validatorMock := server.MocIntegratedValidator{}
	am, err := server.BuildManager(context.Background(), store, peersUpdateManager, nil, "", "", &activity.InMemoryEventStore{}, geoMock, false, validatorMock, metrics)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	apiHandler, err := APIHandler(context.Background(), am, geoMock, &jwtclaims.JwtValidatorMock{}, metrics, AuthCfg{}, validatorMock)
	if err != nil {
		t.Fatalf("Failed to create API handler: %v", err)
	}

	return apiHandler, am, done
}

func peerShouldNotReceiveUpdate(t TB, updateMessage <-chan *server.UpdateMessage) {
	t.Helper()
	select {
	case msg := <-updateMessage:
		t.Errorf("Unexpected message received: %+v", msg)
	case <-time.After(500 * time.Millisecond):
		return
	}
}

func peerShouldReceiveUpdate(t TB, updateMessage <-chan *server.UpdateMessage, expected *server.UpdateMessage) {
	t.Helper()

	select {
	case msg := <-updateMessage:
		if msg == nil {
			t.Errorf("Received nil update message, expected valid message")
		}
		assert.Equal(t, expected, msg)
	case <-time.After(500 * time.Millisecond):
		t.Errorf("Timed out waiting for update message")
	}
}

func buildRequest(t TB, requestBody []byte, requestType, requestPath, user string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(requestType, requestPath, bytes.NewBuffer(requestBody))
	req.Header.Set("Authorization", "Bearer "+user)

	return req
}

func readResponse(t *testing.T, recorder *httptest.ResponseRecorder, expectedStatus int, expectResponse bool) ([]byte, bool) {
	t.Helper()

	res := recorder.Result()
	defer res.Body.Close()

	content, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if !expectResponse {
		return nil, false
	}

	if status := recorder.Code; status != expectedStatus {
		t.Fatalf("handler returned wrong status code: got %v want %v, content: %s",
			status, expectedStatus, string(content))
	}

	return content, expectedStatus == http.StatusOK
}

func populateTestData(b *testing.B, am *server.DefaultAccountManager, peers, groups, users, setupKeys int) {
	b.Helper()

	ctx := context.Background()
	account, err := am.GetAccount(ctx, testAccountId)
	if err != nil {
		b.Fatalf("Failed to get account: %v", err)
	}

	// Create peers
	for i := 0; i < peers; i++ {
		peerKey, _ := wgtypes.GeneratePrivateKey()
		peer := &nbpeer.Peer{
			ID:       fmt.Sprintf("oldpeer-%d", i),
			DNSLabel: fmt.Sprintf("oldpeer-%d", i),
			Key:      peerKey.PublicKey().String(),
			IP:       net.ParseIP(fmt.Sprintf("100.64.%d.%d", i/256, i%256)),
			Status:   &nbpeer.PeerStatus{},
			UserID:   regularUser,
		}
		account.Peers[peer.ID] = peer
	}

	// Create users
	for i := 0; i < users; i++ {
		user := &server.User{
			Id:        fmt.Sprintf("olduser-%d", i),
			AccountID: account.Id,
			Role:      server.UserRoleUser,
		}
		account.Users[user.Id] = user
	}

	for i := 0; i < setupKeys; i++ {
		key := &server.SetupKey{
			Id:         fmt.Sprintf("oldkey-%d", i),
			AccountID:  account.Id,
			AutoGroups: []string{"someGroupID"},
			ExpiresAt:  time.Now().Add(expiresIn * time.Second),
			Name:       newKeyName + strconv.Itoa(i),
			Type:       "reusable",
			UsageLimit: 0,
		}
		account.SetupKeys[key.Id] = key
	}

	// Create groups and policies
	account.Policies = make([]*server.Policy, 0, groups)
	for i := 0; i < groups; i++ {
		groupID := fmt.Sprintf("group-%d", i)
		group := &nbgroup.Group{
			ID:   groupID,
			Name: fmt.Sprintf("Group %d", i),
		}
		for j := 0; j < peers/groups; j++ {
			peerIndex := i*(peers/groups) + j
			group.Peers = append(group.Peers, fmt.Sprintf("peer-%d", peerIndex))
		}
		account.Groups[groupID] = group

		// Create a policy for this group
		policy := &server.Policy{
			ID:      fmt.Sprintf("policy-%d", i),
			Name:    fmt.Sprintf("Policy for Group %d", i),
			Enabled: true,
			Rules: []*server.PolicyRule{
				{
					ID:            fmt.Sprintf("rule-%d", i),
					Name:          fmt.Sprintf("Rule for Group %d", i),
					Enabled:       true,
					Sources:       []string{groupID},
					Destinations:  []string{groupID},
					Bidirectional: true,
					Protocol:      server.PolicyRuleProtocolALL,
					Action:        server.PolicyTrafficActionAccept,
				},
			},
		}
		account.Policies = append(account.Policies, policy)
	}

	account.PostureChecks = []*posture.Checks{
		{
			ID:   "PostureChecksAll",
			Name: "All",
			Checks: posture.ChecksDefinition{
				NBVersionCheck: &posture.NBVersionCheck{
					MinVersion: "0.0.1",
				},
			},
		},
	}

	err = am.Store.SaveAccount(context.Background(), account)
	if err != nil {
		b.Fatalf("Failed to save account: %v", err)
	}

}
