package channel

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/netbirdio/management-integrations/integrations"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/auth"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/groups"
	http2 "github.com/netbirdio/netbird/management/server/http"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
	"github.com/netbirdio/netbird/management/server/networks"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	"github.com/netbirdio/netbird/management/server/peers"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/users"
)

func BuildApiBlackBoxWithDBState(t testing_tools.TB, sqlFile string, expectedPeerUpdate *server.UpdateMessage, validateUpdate bool) (http.Handler, account.Manager, chan struct{}) {
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
	updMsg := peersUpdateManager.CreateChannel(context.Background(), testing_tools.TestPeerId)
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
	am, err := server.BuildManager(context.Background(), store, peersUpdateManager, nil, "", "", &activity.InMemoryEventStore{}, geoMock, false, validatorMock, metrics, proxyController, settingsManager, permissionsManager, false)
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

	apiHandler, err := http2.NewAPIHandler(context.Background(), am, networksManagerMock, resourcesManagerMock, routersManagerMock, groupsManagerMock, geoMock, authManagerMock, metrics, validatorMock, proxyController, permissionsManager, peersManager, settingsManager)
	if err != nil {
		t.Fatalf("Failed to create API handler: %v", err)
	}

	return apiHandler, am, done
}

func peerShouldNotReceiveUpdate(t testing_tools.TB, updateMessage <-chan *server.UpdateMessage) {
	t.Helper()
	select {
	case msg := <-updateMessage:
		t.Errorf("Unexpected message received: %+v", msg)
	case <-time.After(500 * time.Millisecond):
		return
	}
}

func peerShouldReceiveUpdate(t testing_tools.TB, updateMessage <-chan *server.UpdateMessage, expected *server.UpdateMessage) {
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

func mockValidateAndParseToken(_ context.Context, token string) (nbcontext.UserAuth, *jwt.Token, error) {
	userAuth := nbcontext.UserAuth{}

	switch token {
	case "testUserId", "testAdminId", "testOwnerId", "testServiceUserId", "testServiceAdminId", "blockedUserId":
		userAuth.UserId = token
		userAuth.AccountId = "testAccountId"
		userAuth.Domain = "test.com"
		userAuth.DomainCategory = "private"
	case "otherUserId":
		userAuth.UserId = "otherUserId"
		userAuth.AccountId = "otherAccountId"
		userAuth.Domain = "other.com"
		userAuth.DomainCategory = "private"
	case "invalidToken":
		return userAuth, nil, errors.New("invalid token")
	}

	jwtToken := jwt.New(jwt.SigningMethodHS256)
	return userAuth, jwtToken, nil
}
