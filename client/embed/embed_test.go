package embed

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral/manager"
	"github.com/netbirdio/netbird/management/internals/server/config"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	mgmt "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator/validator"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	"github.com/netbirdio/netbird/management/server/job"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
	signalProto "github.com/netbirdio/netbird/shared/signal/proto"
	signalServer "github.com/netbirdio/netbird/signal/server"
	"github.com/netbirdio/netbird/util"
)

const testSetupKey = "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"

// TestClientStartTimeoutRollback reproduces a deadlock between Engine.Start and
// Engine.Stop. The signal endpoint accepts gRPC connections but never serves the
// SignalExchange service, so Engine.Start parks in WaitStreamConnected while
// holding the engine mutex. When the Start context expires, the rollback path
// calls ConnectClient.Stop, which must not block forever acquiring that mutex.
func TestClientStartTimeoutRollback(t *testing.T) {
	signalAddr := startBlackholeSignal(t)
	mgmAddr := startManagement(t, signalAddr)

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

func startManagement(t *testing.T, signalAddr string) string {
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
	peersManager := peers.NewManager(testStore, permissionsManager)
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
	networkMapController := controller.NewController(context.Background(), testStore, metrics, updateManager, requestBuffer, mgmt.MockIntegratedValidator{}, settingsMockManager, "netbird.selfhosted", port_forwarding.NewControllerMock(), manager.NewEphemeralManager(testStore, peersManager), cfg, nil)
	accountManager, err := mgmt.BuildManager(context.Background(), cfg, testStore, networkMapController, jobManager, nil, "", eventStore, nil, false, iv, metrics, port_forwarding.NewControllerMock(), settingsMockManager, permissionsManager, false, cacheStore)
	require.NoError(t, err)

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

	return lis.Addr().String()
}

// startSignal starts a signal server that serves the SignalExchange service, so
// an embedded client can get past WaitStreamConnected and finish Engine.Start.
func startSignal(t *testing.T) string {
	t.Helper()

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	s := grpc.NewServer()
	srv, err := signalServer.NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	signalProto.RegisterSignalExchangeServer(s, srv)

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(s.Stop)

	return lis.Addr().String()
}

// TestClientSyncResponsePersistence checks that DisableSyncResponsePersistence
// controls whether the engine retains the latest management sync response, which
// is observable through GetLatestSyncResponse.
func TestClientSyncResponsePersistence(t *testing.T) {
	tests := []struct {
		name      string
		disable   bool
		persisted bool
	}{
		{name: "retained by default", disable: false, persisted: true},
		{name: "dropped when disabled", disable: true, persisted: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signalAddr := startSignal(t)
			mgmAddr := startManagement(t, signalAddr)

			wgPort := 0
			client, err := New(Options{
				DeviceName:                     "embed-persistence-test",
				SetupKey:                       testSetupKey,
				ManagementURL:                  "http://" + mgmAddr,
				WireguardPort:                  &wgPort,
				DisableSyncResponsePersistence: tc.disable,
			})
			require.NoError(t, err, "embed client creation must succeed")

			startCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			require.NoError(t, client.Start(startCtx), "client must start")

			t.Cleanup(func() {
				stopCtx, stopCancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer stopCancel()
				if err := client.Stop(stopCtx); err != nil {
					t.Logf("stop client: %v", err)
				}
			})

			if !tc.persisted {
				_, err := client.GetLatestSyncResponse()
				require.Error(t, err, "no sync response may be retained when persistence is disabled")
				return
			}

			require.Eventually(t, func() bool {
				resp, err := client.GetLatestSyncResponse()
				return err == nil && resp.GetNetworkMap() != nil
			}, 30*time.Second, 200*time.Millisecond, "the sync response and its network map should be retained by default")
		})
	}
}

// TestClientStatusSnapshot checks that StatusSnapshot reports a started client's
// state without going through the health probes Status runs.
func TestClientStatusSnapshot(t *testing.T) {
	signalAddr := startSignal(t)
	mgmAddr := startManagement(t, signalAddr)

	mgmtURL := "http://" + mgmAddr
	wgPort := 0
	client, err := New(Options{
		DeviceName:    "embed-status-snapshot-test",
		SetupKey:      testSetupKey,
		ManagementURL: mgmtURL,
		WireguardPort: &wgPort,
	})
	require.NoError(t, err, "embed client creation must succeed")

	// Safe before Start: the recorder exists from New, and no engine is needed.
	require.Empty(t, client.StatusSnapshot().LocalPeerState.IP, "an unstarted client has no overlay address")

	startCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	require.NoError(t, client.Start(startCtx), "client must start")

	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer stopCancel()
		if err := client.Stop(stopCtx); err != nil {
			t.Logf("stop client: %v", err)
		}
	})

	require.Eventually(t, func() bool {
		return client.StatusSnapshot().LocalPeerState.IP != ""
	}, 30*time.Second, 200*time.Millisecond, "a started client should report its overlay address")

	require.Equal(t, mgmtURL, client.StatusSnapshot().ManagementState.URL, "snapshot should carry the management URL")
}
