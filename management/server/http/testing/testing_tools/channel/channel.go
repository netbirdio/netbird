package channel

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/management-integrations/integrations"

	zonesManager "github.com/netbirdio/netbird/management/internals/modules/zones/manager"
	recordsManager "github.com/netbirdio/netbird/management/internals/modules/zones/records/manager"
	"github.com/netbirdio/netbird/management/internals/server/config"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	ephemeral_manager "github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral/manager"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	"github.com/netbirdio/netbird/management/server/job"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	serverauth "github.com/netbirdio/netbird/management/server/auth"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/groups"
	http2 "github.com/netbirdio/netbird/management/server/http"
	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools"
	"github.com/netbirdio/netbird/management/server/networks"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/users"
	"github.com/netbirdio/netbird/shared/auth"
)

func BuildApiBlackBoxWithDBState(t testing_tools.TB, sqlFile string, expectedPeerUpdate *network_map.UpdateMessage, validateUpdate bool) (http.Handler, account.Manager, chan struct{}) {
	store, cleanup, err := store.NewTestStoreFromSQL(context.Background(), sqlFile, t.TempDir())
	if err != nil {
		t.Fatalf("Failed to create test store: %v", err)
	}
	t.Cleanup(cleanup)

	metrics, err := telemetry.NewDefaultAppMetrics(context.Background())
	if err != nil {
		t.Fatalf("Failed to create metrics: %v", err)
	}

	peersUpdateManager := update_channel.NewPeersUpdateManager(nil)
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
	settingsManager := settings.NewManager(store, userManager, integrations.NewManager(&activity.InMemoryEventStore{}), permissionsManager, settings.IdpConfig{})
	peersManager := peers.NewManager(store, permissionsManager)

	jobManager := job.NewJobManager(nil, store, peersManager)

	ctx := context.Background()
	requestBuffer := server.NewAccountRequestBuffer(ctx, store)
	networkMapController := controller.NewController(ctx, store, metrics, peersUpdateManager, requestBuffer, server.MockIntegratedValidator{}, settingsManager, "", port_forwarding.NewControllerMock(), ephemeral_manager.NewEphemeralManager(store, peersManager), &config.Config{})
	am, err := server.BuildManager(ctx, nil, store, networkMapController, jobManager, nil, "", &activity.InMemoryEventStore{}, geoMock, false, validatorMock, metrics, proxyController, settingsManager, permissionsManager, false)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	// @note this is required so that PAT's validate from store, but JWT's are mocked
	authManager := serverauth.NewManager(store, "", "", "", "", []string{}, false)
	authManagerMock := &serverauth.MockManager{
		ValidateAndParseTokenFunc:       mockValidateAndParseToken,
		EnsureUserAccessByJWTGroupsFunc: authManager.EnsureUserAccessByJWTGroups,
		MarkPATUsedFunc:                 authManager.MarkPATUsed,
		GetPATInfoFunc:                  authManager.GetPATInfo,
	}

	networksManagerMock := networks.NewManagerMock()
	resourcesManagerMock := resources.NewManagerMock()
	routersManagerMock := routers.NewManagerMock()
	groupsManagerMock := groups.NewManagerMock()
	customZonesManager := zonesManager.NewManager(store, am, permissionsManager, "")
	zoneRecordsManager := recordsManager.NewManager(store, am, permissionsManager)

	apiHandler, err := http2.NewAPIHandler(context.Background(), am, networksManagerMock, resourcesManagerMock, routersManagerMock, groupsManagerMock, geoMock, authManagerMock, metrics, validatorMock, proxyController, permissionsManager, peersManager, settingsManager, customZonesManager, zoneRecordsManager, networkMapController, nil)
	if err != nil {
		t.Fatalf("Failed to create API handler: %v", err)
	}

	return apiHandler, am, done
}

func peerShouldNotReceiveUpdate(t testing_tools.TB, updateMessage <-chan *network_map.UpdateMessage) {
	t.Helper()
	select {
	case msg := <-updateMessage:
		t.Errorf("Unexpected message received: %+v", msg)
	case <-time.After(500 * time.Millisecond):
		return
	}
}

func peerShouldReceiveUpdate(t testing_tools.TB, updateMessage <-chan *network_map.UpdateMessage, expected *network_map.UpdateMessage) {
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

func mockValidateAndParseToken(_ context.Context, token string) (auth.UserAuth, *jwt.Token, error) {
	userAuth := auth.UserAuth{}

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
