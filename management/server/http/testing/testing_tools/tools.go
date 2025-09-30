package testing_tools

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/management/server/account"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
)

const (
	TestAccountId = "testAccountId"
	TestPeerId    = "testPeerId"
	TestGroupId   = "testGroupId"
	TestKeyId     = "testKeyId"

	TestUserId         = "testUserId"
	TestAdminId        = "testAdminId"
	TestOwnerId        = "testOwnerId"
	TestServiceUserId  = "testServiceUserId"
	TestServiceAdminId = "testServiceAdminId"
	BlockedUserId      = "blockedUserId"
	OtherUserId        = "otherUserId"
	InvalidToken       = "invalidToken"

	NewKeyName   = "newKey"
	NewGroupId   = "newGroupId"
	ExpiresIn    = 3600
	RevokedKeyId = "revokedKeyId"
	ExpiredKeyId = "expiredKeyId"

	ExistingKeyName = "existingKey"

	OperationCreate = "create"
	OperationUpdate = "update"
	OperationDelete = "delete"
	OperationGetOne = "get_one"
	OperationGetAll = "get_all"
)

var BenchmarkDuration = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "benchmark_duration_ms",
		Help: "Benchmark duration per op in ms",
	},
	[]string{"module", "operation", "test_case", "branch"},
)

type TB interface {
	Cleanup(func())
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	TempDir() string
}

// BenchmarkCase defines a single benchmark test case
type BenchmarkCase struct {
	Peers     int
	Groups    int
	Users     int
	SetupKeys int
}

// PerformanceMetrics holds the performance expectations
type PerformanceMetrics struct {
	MinMsPerOpLocal float64
	MaxMsPerOpLocal float64
	MinMsPerOpCICD  float64
	MaxMsPerOpCICD  float64
}

func BuildApiBlackBoxWithDBState(t TB, sqlFile string, expectedPeerUpdate *server.UpdateMessage, validateUpdate bool) (http.Handler, account.Manager, chan struct{}) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), sqlFile, t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create test store: %v", err)
	}
	t.Cleanup(cleanup)

	metrics, err := telemetry.NewDefaultAppMetrics(context.Background())
	if err != nil {
		t.Fatalf("Failed to create metrics: %v", err)
	}

	peersUpdateManager := server.NewPeersUpdateManager(nil)
	jobManager := server.NewJobManager(nil, store)
	updMsg := peersUpdateManager.CreateChannel(context.Background(), TestPeerId)
	done := make(chan struct{})
	if validateUpdate {
		go func() {
			if expectedPeerUpdate != nil {
				peerShouldReceiveUpdate(t, updMsg, expectedPeerUpdate)
			} else {
				peerShouldNotReceiveUpdate(t, updMsg)
			}
			close(done)
		}()
	}

	geoMock := &geolocation.Mock{}
	validatorMock := server.MockIntegratedValidator{}
	proxyController := integrations.NewController(store)
	userManager := users.NewManager(store)
	permissionsManager := permissions.NewManager(store)
	settingsManager := settings.NewManager(store, userManager, integrations.NewManager(&activity.InMemoryEventStore{}), permissionsManager)
	am, err := server.BuildManager(context.Background(), store, peersUpdateManager, jobManager, nil, "", "", &activity.InMemoryEventStore{}, geoMock, false, validatorMock, metrics, proxyController, settingsManager, permissionsManager, false)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	// @note this is required so that PAT's validate from store, but JWT's are mocked
	authManager := auth.NewManager(store, "", "", "", "", []string{}, false)
	authManagerMock := &auth.MockManager{
		ValidateAndParseTokenFunc:       mockValidateAndParseToken,
		EnsureUserAccessByJWTGroupsFunc: authManager.EnsureUserAccessByJWTGroups,
		MarkPATUsedFunc:                 authManager.MarkPATUsed,
		GetPATInfoFunc:                  authManager.GetPATInfo,
	}

	networksManagerMock := networks.NewManagerMock()
	resourcesManagerMock := resources.NewManagerMock()
	routersManagerMock := routers.NewManagerMock()
	groupsManagerMock := groups.NewManagerMock()
	peersManager := peers.NewManager(store, permissionsManager)

	apiHandler, err := nbhttp.NewAPIHandler(context.Background(), am, networksManagerMock, resourcesManagerMock, routersManagerMock, groupsManagerMock, geoMock, authManagerMock, metrics, validatorMock, proxyController, permissionsManager, peersManager, settingsManager)
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

func BuildRequest(t TB, requestBody []byte, requestType, requestPath, user string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(requestType, requestPath, bytes.NewBuffer(requestBody))
	req.Header.Set("Authorization", "Bearer "+user)

	return req
}

func ReadResponse(t *testing.T, recorder *httptest.ResponseRecorder, expectedStatus int, expectResponse bool) ([]byte, bool) {
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

func PopulateTestData(b *testing.B, am account.Manager, peers, groups, users, setupKeys int) {
	b.Helper()

	ctx := context.Background()
	acc, err := am.GetAccount(ctx, TestAccountId)
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
			Status:   &nbpeer.PeerStatus{LastSeen: time.Now().UTC(), Connected: true},
			UserID:   TestUserId,
		}
		acc.Peers[peer.ID] = peer
	}

	// Create users
	for i := 0; i < users; i++ {
		user := &types.User{
			Id:        fmt.Sprintf("olduser-%d", i),
			AccountID: acc.Id,
			Role:      types.UserRoleUser,
		}
		acc.Users[user.Id] = user
	}

	for i := 0; i < setupKeys; i++ {
		key := &types.SetupKey{
			Id:         fmt.Sprintf("oldkey-%d", i),
			AccountID:  acc.Id,
			AutoGroups: []string{"someGroupID"},
			UpdatedAt:  time.Now().UTC(),
			ExpiresAt:  util.ToPtr(time.Now().Add(ExpiresIn * time.Second)),
			Name:       NewKeyName + strconv.Itoa(i),
			Type:       "reusable",
			UsageLimit: 0,
		}
		acc.SetupKeys[key.Id] = key
	}

	// Create groups and policies
	acc.Policies = make([]*types.Policy, 0, groups)
	for i := 0; i < groups; i++ {
		groupID := fmt.Sprintf("group-%d", i)
		group := &types.Group{
			ID:   groupID,
			Name: fmt.Sprintf("Group %d", i),
		}
		for j := 0; j < peers/groups; j++ {
			peerIndex := i*(peers/groups) + j
			group.Peers = append(group.Peers, fmt.Sprintf("peer-%d", peerIndex))
		}
		acc.Groups[groupID] = group

		// Create a policy for this group
		policy := &types.Policy{
			ID:      fmt.Sprintf("policy-%d", i),
			Name:    fmt.Sprintf("Policy for Group %d", i),
			Enabled: true,
			Rules: []*types.PolicyRule{
				{
					ID:            fmt.Sprintf("rule-%d", i),
					Name:          fmt.Sprintf("Rule for Group %d", i),
					Enabled:       true,
					Sources:       []string{groupID},
					Destinations:  []string{groupID},
					Bidirectional: true,
					Protocol:      types.PolicyRuleProtocolALL,
					Action:        types.PolicyTrafficActionAccept,
				},
			},
		}
		acc.Policies = append(acc.Policies, policy)
	}

	acc.PostureChecks = []*posture.Checks{
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

	store := am.GetStore()

	err = store.SaveAccount(context.Background(), acc)
	if err != nil {
		b.Fatalf("Failed to save account: %v", err)
	}

}

func EvaluateAPIBenchmarkResults(b *testing.B, testCase string, duration time.Duration, recorder *httptest.ResponseRecorder, module string, operation string) {
	b.Helper()

	if recorder.Code != http.StatusOK {
		b.Fatalf("Benchmark %s failed: unexpected status code %d", testCase, recorder.Code)
	}

	EvaluateBenchmarkResults(b, testCase, duration, module, operation)

}

func EvaluateBenchmarkResults(b *testing.B, testCase string, duration time.Duration, module string, operation string) {
	b.Helper()

	branch := os.Getenv("GIT_BRANCH")
	if branch == "" && os.Getenv("CI") == "true" {
		b.Fatalf("environment variable GIT_BRANCH is not set")
	}

	msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6

	gauge := BenchmarkDuration.WithLabelValues(module, operation, testCase, branch)
	gauge.Set(msPerOp)

	b.ReportMetric(msPerOp, "ms/op")
}
