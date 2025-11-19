package cmd

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc"

	"github.com/netbirdio/management-integrations/integrations"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"

	clientProto "github.com/netbirdio/netbird/client/proto"
	client "github.com/netbirdio/netbird/client/server"
	"github.com/netbirdio/netbird/management/internals/server/config"
	mgmt "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	"github.com/netbirdio/netbird/management/server/peers"
	"github.com/netbirdio/netbird/management/server/peers/ephemeral/manager"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
	sigProto "github.com/netbirdio/netbird/shared/signal/proto"
	sig "github.com/netbirdio/netbird/signal/server"
	"github.com/netbirdio/netbird/util"
)

func startTestingServices(t *testing.T) string {
	t.Helper()
	config := &config.Config{}
	_, err := util.ReadJson("../testdata/management.json", config)
	if err != nil {
		t.Fatal(err)
	}

	_, signalLis := startSignal(t)
	signalAddr := signalLis.Addr().String()
	config.Signal.URI = signalAddr

	_, mgmLis := startManagement(t, config, "../testdata/store.sql")
	mgmAddr := mgmLis.Addr().String()
	return mgmAddr
}

func startSignal(t *testing.T) (*grpc.Server, net.Listener) {
	t.Helper()
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	srv, err := sig.NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)

	sigProto.RegisterSignalExchangeServer(s, srv)
	go func() {
		if err := s.Serve(lis); err != nil {
			panic(err)
		}
	}()

	return s, lis
}

func startManagement(t *testing.T, config *config.Config, testFile string) (*grpc.Server, net.Listener) {
	t.Helper()

	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), testFile, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)

	eventStore := &activity.InMemoryEventStore{}
	if err != nil {
		return nil, nil
	}

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	permissionsManagerMock := permissions.NewMockManager(ctrl)
	peersmanager := peers.NewManager(store, permissionsManagerMock)
	settingsManagerMock := settings.NewMockManager(ctrl)

	iv, _ := integrations.NewIntegratedValidator(context.Background(), peersmanager, settingsManagerMock, eventStore)

	metrics, err := telemetry.NewDefaultAppMetrics(context.Background())
	require.NoError(t, err)

	settingsMockManager := settings.NewMockManager(ctrl)
	groupsManager := groups.NewManagerMock()

	settingsMockManager.EXPECT().
		GetSettings(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&types.Settings{}, nil).
		AnyTimes()

	ctx := context.Background()
	updateManager := update_channel.NewPeersUpdateManager(metrics)
	requestBuffer := mgmt.NewAccountRequestBuffer(ctx, store)
	networkMapController := controller.NewController(ctx, store, metrics, updateManager, requestBuffer, mgmt.MockIntegratedValidator{}, settingsMockManager, "netbird.cloud", port_forwarding.NewControllerMock(), config)

	accountManager, err := mgmt.BuildManager(context.Background(), config, store, networkMapController, nil, "", eventStore, nil, false, iv, metrics, port_forwarding.NewControllerMock(), settingsMockManager, permissionsManagerMock, false)
	if err != nil {
		t.Fatal(err)
	}

	secretsManager := nbgrpc.NewTimeBasedAuthSecretsManager(updateManager, config.TURNConfig, config.Relay, settingsMockManager, groupsManager)
	mgmtServer, err := nbgrpc.NewServer(config, accountManager, settingsMockManager, updateManager, secretsManager, nil, &manager.EphemeralManager{}, nil, &mgmt.MockIntegratedValidator{}, networkMapController)
	if err != nil {
		t.Fatal(err)
	}
	mgmtProto.RegisterManagementServiceServer(s, mgmtServer)
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Error(err)
		}
	}()

	return s, lis
}

func startClientDaemon(
	t *testing.T, ctx context.Context, _, _ string,
) (*grpc.Server, net.Listener) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()

	server := client.New(ctx,
		"", "", false, false)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	clientProto.RegisterDaemonServiceServer(s, server)
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Error(err)
		}
	}()

	time.Sleep(time.Second)

	return s, lis
}
