package internal

import (
	"context"
	"net"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral/manager"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/internals/server/config"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/account"
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
	"github.com/netbirdio/netbird/util"
)

// startManagementServer runs an in-process management server backed by the
// SQL fixture at testFile. It needs no privileges, so tests that only talk
// gRPC to management can use it without the privileged build tag. The account
// manager is returned so tests can change server-side state, such as deleting
// a peer.
func startManagementServer(t *testing.T, dataDir, testFile string) (*grpc.Server, string, account.Manager, error) {
	t.Helper()

	config := &config.Config{
		Stuns:      []*config.Host{},
		TURNConfig: &config.TURNConfig{},
		Relay: &config.Relay{
			Addresses:      []string{"127.0.0.1:1234"},
			CredentialsTTL: util.Duration{Duration: time.Hour},
			Secret:         "222222222222222222",
		},
		Signal: &config.Host{
			Proto: "http",
			URI:   "localhost:10000",
		},
		Datadir:    dataDir,
		HttpConfig: nil,
	}

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, "", nil, err
	}
	// Closes the socket if setup fails before Serve. After Serve, Stop has already closed it.
	t.Cleanup(func() { _ = lis.Close() })
	s := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), testFile, config.Datadir)
	if err != nil {
		return nil, "", nil, err
	}
	t.Cleanup(cleanUp)

	eventStore := &activity.InMemoryEventStore{}

	permissionsManager := permissions.NewManager(store)
	peersManager := peers.NewManager(store, permissionsManager)
	jobManager := job.NewJobManager(nil, store, peersManager)

	cacheStore, err := nbcache.NewStore(context.Background(), 100*time.Millisecond, 300*time.Millisecond, 100)
	if err != nil {
		return nil, "", nil, err
	}

	ia, _ := validator.NewIntegratedValidator(context.Background(), peersManager, nil, eventStore, cacheStore)

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
	requestBuffer := server.NewAccountRequestBuffer(context.Background(), store)
	networkMapController := controller.NewController(context.Background(), store, metrics, updateManager, requestBuffer, server.MockIntegratedValidator{}, settingsMockManager, "netbird.selfhosted", manager.NewEphemeralManager(store, peersManager), config, nil)
	accountManager, err := server.BuildManager(context.Background(), config, store, networkMapController, jobManager, nil, "", eventStore, nil, false, ia, metrics, settingsMockManager, permissionsManager, false, cacheStore)
	if err != nil {
		return nil, "", nil, err
	}
	// Peer deletion asks the service manager whether a service still targets the peer.
	serviceMockManager := service.NewMockManager(ctrl)
	serviceMockManager.EXPECT().
		GetServiceIDByTargetID(gomock.Any(), gomock.Any(), gomock.Any()).
		Return("", nil).
		AnyTimes()
	accountManager.SetServiceManager(serviceMockManager)

	secretsManager, err := nbgrpc.NewTimeBasedAuthSecretsManager(updateManager, config.TURNConfig, config.Relay, settingsMockManager, groupsManager)
	if err != nil {
		return nil, "", nil, err
	}
	mgmtServer, err := nbgrpc.NewServer(config, accountManager, settingsMockManager, jobManager, secretsManager, nil, nil, &server.MockIntegratedValidator{}, networkMapController, nil, nil)
	if err != nil {
		return nil, "", nil, err
	}
	mgmtProto.RegisterManagementServiceServer(s, mgmtServer)
	go func() {
		if serveErr := s.Serve(lis); serveErr != nil {
			log.Errorf("failed to serve: %v", serveErr)
		}
	}()
	t.Cleanup(s.Stop)

	return s, lis.Addr().String(), accountManager, nil
}

var (
	kaep = keepalive.EnforcementPolicy{
		MinTime:             15 * time.Second,
		PermitWithoutStream: true,
	}

	kasp = keepalive.ServerParameters{
		MaxConnectionIdle:     15 * time.Second,
		MaxConnectionAgeGrace: 5 * time.Second,
		Time:                  5 * time.Second,
		Timeout:               2 * time.Second,
	}
)
