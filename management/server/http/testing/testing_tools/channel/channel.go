package channel

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/otel/metric/noop"

	"github.com/netbirdio/management-integrations/integrations"

	accesslogsmanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs/manager"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain/manager"
	proxymanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy/manager"
	reverseproxymanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service/manager"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"

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

	accessLogsManager := accesslogsmanager.NewManager(store, permissionsManager, nil)
	proxyTokenStore, err := nbgrpc.NewOneTimeTokenStore(ctx, 5*time.Minute, 10*time.Minute, 100)
	if err != nil {
		t.Fatalf("Failed to create proxy token store: %v", err)
	}
	pkceverifierStore, err := nbgrpc.NewPKCEVerifierStore(ctx, 10*time.Minute, 10*time.Minute, 100)
	if err != nil {
		t.Fatalf("Failed to create PKCE verifier store: %v", err)
	}
	noopMeter := noop.NewMeterProvider().Meter("")
	proxyMgr, err := proxymanager.NewManager(store, noopMeter)
	if err != nil {
		t.Fatalf("Failed to create proxy manager: %v", err)
	}
	proxyServiceServer := nbgrpc.NewProxyServiceServer(accessLogsManager, proxyTokenStore, pkceverifierStore, nbgrpc.ProxyOIDCConfig{}, peersManager, userManager, proxyMgr)
	domainManager := manager.NewManager(store, proxyMgr, permissionsManager, am)
	serviceProxyController, err := proxymanager.NewGRPCController(proxyServiceServer, noopMeter)
	if err != nil {
		t.Fatalf("Failed to create proxy controller: %v", err)
	}
	serviceManager := reverseproxymanager.NewManager(store, am, permissionsManager, serviceProxyController, proxyMgr, domainManager)
	proxyServiceServer.SetServiceManager(serviceManager)
	am.SetServiceManager(serviceManager)

	// @note this is required so that PAT's validate from store, but JWT's are mocked
	authManager := serverauth.NewManager(store, "", "", "", "", []string{}, false, nil)
	authManagerMock := &serverauth.MockManager{
		ValidateAndParseTokenFunc:       mockValidateAndParseToken,
		EnsureUserAccessByJWTGroupsFunc: authManager.EnsureUserAccessByJWTGroups,
		MarkPATUsedFunc:                 authManager.MarkPATUsed,
		GetPATInfoFunc:                  authManager.GetPATInfo,
	}

	groupsManager := groups.NewManager(store, permissionsManager, am)
	routersManager := routers.NewManager(store, permissionsManager, am)
	resourcesManager := resources.NewManager(store, permissionsManager, groupsManager, am, serviceManager)
	networksManager := networks.NewManager(store, permissionsManager, resourcesManager, routersManager, am)
	customZonesManager := zonesManager.NewManager(store, am, permissionsManager, "")
	zoneRecordsManager := recordsManager.NewManager(store, am, permissionsManager)

	apiHandler, err := http2.NewAPIHandler(context.Background(), am, networksManager, resourcesManager, routersManager, groupsManager, geoMock, authManagerMock, metrics, validatorMock, proxyController, permissionsManager, peersManager, settingsManager, customZonesManager, zoneRecordsManager, networkMapController, nil, serviceManager, nil, nil, nil, nil)
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

// PeerShouldReceiveAnyUpdate waits for a peer update message and returns it.
// Fails the test if no update is received within timeout.
func PeerShouldReceiveAnyUpdate(t testing_tools.TB, updateMessage <-chan *network_map.UpdateMessage) *network_map.UpdateMessage {
	t.Helper()
	select {
	case msg := <-updateMessage:
		if msg == nil {
			t.Errorf("Received nil update message, expected valid message")
		}
		return msg
	case <-time.After(500 * time.Millisecond):
		t.Errorf("Timed out waiting for update message")
		return nil
	}
}

// PeerShouldNotReceiveAnyUpdate verifies no peer update message is received.
func PeerShouldNotReceiveAnyUpdate(t testing_tools.TB, updateMessage <-chan *network_map.UpdateMessage) {
	t.Helper()
	peerShouldNotReceiveUpdate(t, updateMessage)
}

// BuildApiBlackBoxWithDBStateAndPeerChannel creates the API handler and returns
// the peer update channel directly so tests can verify updates inline.
func BuildApiBlackBoxWithDBStateAndPeerChannel(t testing_tools.TB, sqlFile string) (http.Handler, account.Manager, <-chan *network_map.UpdateMessage) {
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

	accessLogsManager := accesslogsmanager.NewManager(store, permissionsManager, nil)
	proxyTokenStore, err := nbgrpc.NewOneTimeTokenStore(ctx, 5*time.Minute, 10*time.Minute, 100)
	if err != nil {
		t.Fatalf("Failed to create proxy token store: %v", err)
	}
	pkceverifierStore, err := nbgrpc.NewPKCEVerifierStore(ctx, 10*time.Minute, 10*time.Minute, 100)
	if err != nil {
		t.Fatalf("Failed to create PKCE verifier store: %v", err)
	}
	noopMeter := noop.NewMeterProvider().Meter("")
	proxyMgr, err := proxymanager.NewManager(store, noopMeter)
	if err != nil {
		t.Fatalf("Failed to create proxy manager: %v", err)
	}
	proxyServiceServer := nbgrpc.NewProxyServiceServer(accessLogsManager, proxyTokenStore, pkceverifierStore, nbgrpc.ProxyOIDCConfig{}, peersManager, userManager, proxyMgr)
	domainManager := manager.NewManager(store, proxyMgr, permissionsManager, am)
	serviceProxyController, err := proxymanager.NewGRPCController(proxyServiceServer, noopMeter)
	if err != nil {
		t.Fatalf("Failed to create proxy controller: %v", err)
	}
	serviceManager := reverseproxymanager.NewManager(store, am, permissionsManager, serviceProxyController, proxyMgr, domainManager)
	proxyServiceServer.SetServiceManager(serviceManager)
	am.SetServiceManager(serviceManager)

	// @note this is required so that PAT's validate from store, but JWT's are mocked
	authManager := serverauth.NewManager(store, "", "", "", "", []string{}, false, nil)
	authManagerMock := &serverauth.MockManager{
		ValidateAndParseTokenFunc:       mockValidateAndParseToken,
		EnsureUserAccessByJWTGroupsFunc: authManager.EnsureUserAccessByJWTGroups,
		MarkPATUsedFunc:                 authManager.MarkPATUsed,
		GetPATInfoFunc:                  authManager.GetPATInfo,
	}

	groupsManager := groups.NewManager(store, permissionsManager, am)
	routersManager := routers.NewManager(store, permissionsManager, am)
	resourcesManager := resources.NewManager(store, permissionsManager, groupsManager, am, serviceManager)
	networksManager := networks.NewManager(store, permissionsManager, resourcesManager, routersManager, am)
	customZonesManager := zonesManager.NewManager(store, am, permissionsManager, "")
	zoneRecordsManager := recordsManager.NewManager(store, am, permissionsManager)

	apiHandler, err := http2.NewAPIHandler(context.Background(), am, networksManager, resourcesManager, routersManager, groupsManager, geoMock, authManagerMock, metrics, validatorMock, proxyController, permissionsManager, peersManager, settingsManager, customZonesManager, zoneRecordsManager, networkMapController, nil, serviceManager, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create API handler: %v", err)
	}

	return apiHandler, am, updMsg
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
