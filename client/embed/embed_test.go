package embed

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.uber.org/mock/gomock"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/controllers/peerliveness/peerlivenesstest"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral/manager"
	"github.com/netbirdio/netbird/management/internals/server/config"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	mgmt "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator/validator"
	"github.com/netbirdio/netbird/management/server/job"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
	sigProto "github.com/netbirdio/netbird/shared/signal/proto"
	sigServer "github.com/netbirdio/netbird/signal/server"
	"github.com/netbirdio/netbird/util"
)

const (
	testSetupKey  = "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"
	testAccountID = "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	testAdminID   = "edafee4e-63fb-11ec-90d6-0242ac120003"
)

// testManagement is a Management instance started for a test, with the handles a test
// needs to change its state underneath a running client.
type testManagement struct {
	addr         string
	store        store.Store
	peersManager peers.Manager
}

// TestClientStartTimeoutRollback reproduces a deadlock between Engine.Start and
// Engine.Stop. The signal endpoint accepts gRPC connections but never serves the
// SignalExchange service, so Engine.Start parks in WaitStreamConnected while
// holding the engine mutex. When the Start context expires, the rollback path
// calls ConnectClient.Stop, which must not block forever acquiring that mutex.
func TestClientStartTimeoutRollback(t *testing.T) {
	signalAddr := startBlackholeSignal(t)
	mgmAddr := startManagement(t, signalAddr).addr

	wgPort := 0
	client, err := New(Options{
		DeviceName:    "embed-rollback-test",
		SetupKey:      testSetupKey,
		ManagementURL: "http://" + mgmAddr,
		WireguardPort: &wgPort,
	})
	require.NoError(t, err, "embed client creation must succeed")

	startCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	startErr := make(chan error, 1)
	go func() {
		startErr <- client.Start(startCtx)
	}()

	select {
	case err := <-startErr:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(60 * time.Second):
		t.Fatal("client.Start did not return after its context expired: Engine.Stop deadlocked against Engine.Start waiting for the signal stream")
	}
}

// startBlackholeSignal starts a gRPC server without the SignalExchange service
// registered. Connections succeed, but the signal stream can never be
// established, which keeps Engine.Start parked in WaitStreamConnected.
func startBlackholeSignal(t *testing.T) string {
	t.Helper()

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	s := grpc.NewServer()
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(s.Stop)

	return lis.Addr().String()
}

// TestClientStartReportsRunExit covers a client whose peer is deleted by Management while
// it runs (an ephemeral peer left offline past its lifetime). The run loop exits on the
// PermissionDenied login; Start must report that instead of ErrClientAlreadyStarted, so a
// caller knows the client is dead and has to be replaced.
func TestClientStartReportsRunExit(t *testing.T) {
	mgm := startManagement(t, startSignal(t))

	wgPort := 0
	client, err := New(Options{
		DeviceName:    "embed-run-exit-test",
		SetupKey:      testSetupKey,
		ManagementURL: "http://" + mgm.addr,
		WireguardPort: &wgPort,
	})
	require.NoError(t, err, "embed client creation must succeed")

	startCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, client.Start(startCtx), "client must start against a working Management")
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		_ = client.Stop(stopCtx)
	})

	require.NoError(t, client.RunErr(), "a running client has no run error")
	require.ErrorIs(t, client.Start(startCtx), ErrClientAlreadyStarted)

	cfg, err := client.GetConfig()
	require.NoError(t, err)
	privateKey, err := wgtypes.ParseKey(cfg.PrivateKey)
	require.NoError(t, err)
	p, err := mgm.store.GetPeerByPeerPubKey(context.Background(), store.LockingStrengthNone, privateKey.PublicKey().String())
	require.NoError(t, err, "the started client must be registered in Management")
	require.NoError(t, mgm.peersManager.DeletePeers(context.Background(), testAccountID, []string{p.ID}, testAdminID, false))

	require.Eventually(t, func() bool { return client.RunErr() != nil }, 60*time.Second, 100*time.Millisecond,
		"the run loop must exit once Management no longer knows the peer")
	assert.ErrorIs(t, client.Start(startCtx), ErrClientRunExited,
		"Start must report the exited run loop instead of claiming the client is running")
}

func startSignal(t *testing.T) string {
	t.Helper()

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	s := grpc.NewServer()
	srv, err := sigServer.NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	sigProto.RegisterSignalExchangeServer(s, srv)
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(s.Stop)

	return lis.Addr().String()
}

func startManagement(t *testing.T, signalAddr string) testManagement {
	t.Helper()

	cfg := &config.Config{
		Stuns:      []*config.Host{},
		TURNConfig: &config.TURNConfig{},
		Relay: &config.Relay{
			Addresses:      []string{"127.0.0.1:1234"},
			CredentialsTTL: util.Duration{Duration: time.Hour},
			Secret:         "222222222222222222",
		},
		Signal: &config.Host{
			Proto: "http",
			URI:   signalAddr,
		},
		Datadir:    t.TempDir(),
		HttpConfig: nil,
	}

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	s := grpc.NewServer()

	testStore, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", cfg.Datadir)
	require.NoError(t, err)
	t.Cleanup(cleanUp)

	eventStore := &activity.InMemoryEventStore{}

	permissionsManager := permissions.NewManager(testStore)
	peerLiveness := peerlivenesstest.NewStarted(t, testStore)
	peersManager := peers.NewManager(testStore, permissionsManager, peerLiveness)
	jobManager := job.NewJobManager(nil, testStore, peersManager)

	cacheStore, err := nbcache.NewStore(context.Background(), 100*time.Millisecond, 300*time.Millisecond, 100)
	require.NoError(t, err)

	iv, err := validator.NewIntegratedValidator(context.Background(), peersManager, nil, eventStore, cacheStore)
	require.NoError(t, err)
	metrics, err := telemetry.NewDefaultAppMetrics(context.Background())
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	settingsMockManager := settings.NewMockManager(ctrl)
	settingsMockManager.EXPECT().
		GetSettings(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&types.Settings{}, nil).
		AnyTimes()
	settingsMockManager.EXPECT().
		GetExtraSettings(gomock.Any(), gomock.Any()).
		Return(&types.ExtraSettings{}, nil).
		AnyTimes()

	groupsManager := groups.NewManagerMock()

	updateManager := update_channel.NewPeersUpdateManager(metrics)
	requestBuffer := mgmt.NewAccountRequestBuffer(context.Background(), testStore)
	networkMapController := controller.NewController(context.Background(), testStore, metrics, updateManager, requestBuffer, mgmt.MockIntegratedValidator{}, settingsMockManager, "netbird.selfhosted", manager.NewEphemeralManager(testStore, peersManager), cfg, nil)
	accountManager, err := mgmt.BuildManager(context.Background(), cfg, testStore, networkMapController, jobManager, nil, "", eventStore, nil, false, iv, metrics, settingsMockManager, permissionsManager, false, cacheStore, peerLiveness)
	require.NoError(t, err)
	peersManager.SetNetworkMapController(networkMapController)
	peersManager.SetAccountManager(accountManager)
	peersManager.SetIntegratedPeerValidator(mgmt.MockIntegratedValidator{})

	secretsManager, err := nbgrpc.NewTimeBasedAuthSecretsManager(updateManager, cfg.TURNConfig, cfg.Relay, settingsMockManager, groupsManager)
	require.NoError(t, err)

	mgmtServer, err := nbgrpc.NewServer(cfg, accountManager, settingsMockManager, jobManager, secretsManager, nil, nil, &mgmt.MockIntegratedValidator{}, networkMapController, nil, nil)
	require.NoError(t, err)
	mgmtProto.RegisterManagementServiceServer(s, mgmtServer)

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(s.Stop)

	return testManagement{addr: lis.Addr().String(), store: testStore, peersManager: peersManager}
}
