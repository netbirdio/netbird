//go:build privileged

package internal

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/peer"
	nbssh "github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/system"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral/manager"
	"github.com/netbirdio/netbird/management/internals/server/config"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server"
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
	mgmt "github.com/netbirdio/netbird/shared/management/client"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
	signal "github.com/netbirdio/netbird/shared/signal/client"
	"github.com/netbirdio/netbird/shared/signal/proto"
	signalServer "github.com/netbirdio/netbird/signal/server"
	"github.com/netbirdio/netbird/util"
)

func TestEngine_SSH(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	sshKey, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	if err != nil {
		t.Fatal(err)
		return
	}

	ctx, cancel := context.WithCancel(CtxInitState(context.Background()))
	defer cancel()

	relayMgr := relayClient.NewManager(ctx, nil, key.PublicKey().String(), iface.DefaultMTU)
	engine := NewEngine(
		ctx, cancel,
		&EngineConfig{
			WgIfaceName:      "utun101",
			WgAddr:           wgaddr.MustParseWGAddress("100.64.0.1/24"),
			WgPrivateKey:     key,
			WgPort:           33100,
			ServerSSHAllowed: true,
			MTU:              iface.DefaultMTU,
			SSHKey:           sshKey,
		},
		EngineServices{
			SignalClient:   &signal.MockClient{},
			MgmClient:      &mgmt.MockClient{},
			RelayManager:   relayMgr,
			StatusRecorder: peer.NewRecorder("https://mgm"),
		},
		MobileDependency{},
	)

	engine.dnsServer = &dns.MockServer{
		UpdateDNSServerFunc: func(serial uint64, update nbdns.Config) error { return nil },
	}

	err = engine.Start(nil, nil)
	require.NoError(t, err)

	defer func() {
		err := engine.Stop()
		if err != nil {
			return
		}
	}()

	peerWithSSH := &mgmtProto.RemotePeerConfig{
		WgPubKey:   "MNHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		AllowedIps: []string{"100.64.0.21/24"},
		SshConfig: &mgmtProto.SSHConfig{
			SshPubKey: []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFATYCqaQw/9id1Qkq3n16JYhDhXraI6Pc1fgB8ynEfQ"),
		},
	}

	// SSH server is not enabled so SSH config of a remote peer should be ignored
	networkMap := &mgmtProto.NetworkMap{
		Serial:             6,
		PeerConfig:         nil,
		RemotePeers:        []*mgmtProto.RemotePeerConfig{peerWithSSH},
		RemotePeersIsEmpty: false,
	}

	err = engine.updateNetworkMap(networkMap)
	require.NoError(t, err)

	assert.Nil(t, engine.sshServer)

	// SSH server is enabled, therefore SSH config should be applied
	networkMap = &mgmtProto.NetworkMap{
		Serial: 7,
		PeerConfig: &mgmtProto.PeerConfig{Address: "100.64.0.1/24",
			SshConfig: &mgmtProto.SSHConfig{
				SshEnabled: true,
				JwtConfig: &mgmtProto.JWTConfig{
					Issuer:       "test-issuer",
					Audience:     "test-audience",
					KeysLocation: "test-keys",
					MaxTokenAge:  3600,
				},
			}},
		RemotePeers:        []*mgmtProto.RemotePeerConfig{peerWithSSH},
		RemotePeersIsEmpty: false,
	}

	err = engine.updateNetworkMap(networkMap)
	require.NoError(t, err)

	time.Sleep(250 * time.Millisecond)
	assert.NotNil(t, engine.sshServer)

	// now remove peer
	networkMap = &mgmtProto.NetworkMap{
		Serial:             8,
		RemotePeers:        []*mgmtProto.RemotePeerConfig{},
		RemotePeersIsEmpty: false,
	}

	err = engine.updateNetworkMap(networkMap)
	require.NoError(t, err)

	// time.Sleep(250 * time.Millisecond)
	assert.NotNil(t, engine.sshServer)

	// now disable SSH server
	networkMap = &mgmtProto.NetworkMap{
		Serial: 9,
		PeerConfig: &mgmtProto.PeerConfig{Address: "100.64.0.1/24",
			SshConfig: &mgmtProto.SSHConfig{SshEnabled: false}},
		RemotePeers:        []*mgmtProto.RemotePeerConfig{peerWithSSH},
		RemotePeersIsEmpty: false,
	}

	err = engine.updateNetworkMap(networkMap)
	require.NoError(t, err)

	assert.Nil(t, engine.sshServer)
}

func TestEngine_Sync(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	ctx, cancel := context.WithCancel(CtxInitState(context.Background()))
	defer cancel()

	// feed updates to Engine via mocked Management client
	updates := make(chan *mgmtProto.SyncResponse)
	defer close(updates)
	syncFunc := func(ctx context.Context, info *system.Info, msgHandler func(msg *mgmtProto.SyncResponse) error) error {
		for msg := range updates {
			err := msgHandler(msg)
			if err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}
	relayMgr := relayClient.NewManager(ctx, nil, key.PublicKey().String(), iface.DefaultMTU)
	engine := NewEngine(ctx, cancel, &EngineConfig{
		WgIfaceName:  "utun103",
		WgAddr:       wgaddr.MustParseWGAddress("100.64.0.1/24"),
		WgPrivateKey: key,
		WgPort:       33100,
		MTU:          iface.DefaultMTU,
	}, EngineServices{
		SignalClient:   &signal.MockClient{},
		MgmClient:      &mgmt.MockClient{SyncFunc: syncFunc},
		RelayManager:   relayMgr,
		StatusRecorder: peer.NewRecorder("https://mgm"),
	}, MobileDependency{})
	engine.ctx = ctx

	engine.dnsServer = &dns.MockServer{
		UpdateDNSServerFunc: func(serial uint64, update nbdns.Config) error { return nil },
	}

	defer func() {
		err := engine.Stop()
		if err != nil {
			return
		}
	}()

	err = engine.Start(nil, nil)
	if err != nil {
		t.Fatal(err)
		return
	}

	peer1 := &mgmtProto.RemotePeerConfig{
		WgPubKey:   "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		AllowedIps: []string{"100.64.0.10/24"},
	}
	peer2 := &mgmtProto.RemotePeerConfig{
		WgPubKey:   "LLHf3Ma6z6mdLbriAJbqhX9+nM/B71lgw2+91q3LlhU=",
		AllowedIps: []string{"100.64.0.11/24"},
	}
	peer3 := &mgmtProto.RemotePeerConfig{
		WgPubKey:   "GGHf3Ma6z6mdLbriAJbqhX9+nM/B71lgw2+91q3LlhU=",
		AllowedIps: []string{"100.64.0.12/24"},
	}
	// 1st update with just 1 peer and serial larger than the current serial of the engine => apply update
	updates <- &mgmtProto.SyncResponse{
		NetworkMap: &mgmtProto.NetworkMap{
			Serial:             10,
			PeerConfig:         nil,
			RemotePeers:        []*mgmtProto.RemotePeerConfig{peer1, peer2, peer3},
			RemotePeersIsEmpty: false,
		},
	}

	timeout := time.After(time.Second * 2)
	for {
		select {
		case <-timeout:
			t.Fatalf("timeout while waiting for test to finish")
			return
		default:
		}

		if getPeers(engine) == 3 && engine.networkSerial == 10 {
			break
		}
	}
}

func TestEngine_MultiplePeers(t *testing.T) {
	// log.SetLevel(log.DebugLevel)

	ctx, cancel := context.WithCancel(CtxInitState(context.Background()))
	defer cancel()

	sigServer, signalAddr, err := startSignal(t)
	if err != nil {
		t.Fatal(err)
		return
	}
	defer sigServer.Stop()
	mgmtServer, mgmtAddr, err := startManagement(t, t.TempDir(), "../testdata/store.sql")
	if err != nil {
		t.Fatal(err)
		return
	}
	defer mgmtServer.GracefulStop()

	setupKey := "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"

	mu := sync.Mutex{}
	engines := []*Engine{}
	numPeers := 10
	wg := sync.WaitGroup{}
	wg.Add(numPeers)
	// create and start peers
	for i := 0; i < numPeers; i++ {
		j := i
		go func() {
			engine, err := createEngine(ctx, cancel, setupKey, j, mgmtAddr, signalAddr)
			if err != nil {
				wg.Done()
				t.Errorf("unable to create the engine for peer %d with error %v", j, err)
				return
			}
			engine.dnsServer = &dns.MockServer{}
			mu.Lock()
			defer mu.Unlock()
			guid := fmt.Sprintf("{%s}", uuid.New().String())
			device.CustomWindowsGUIDString = strings.ToLower(guid)
			err = engine.Start(nil, nil)
			if err != nil {
				t.Errorf("unable to start engine for peer %d with error %v", j, err)
				wg.Done()
				return
			}
			engines = append(engines, engine)
			wg.Done()
		}()
	}

	// wait until all have been created and started
	wg.Wait()
	if len(engines) != numPeers {
		t.Fatal("not all peers were started")
	}
	// check whether all the peer have expected peers connected

	expectedConnected := numPeers * (numPeers - 1)

	// adjust according to timeouts
	timeout := 50 * time.Second
	timeoutChan := time.After(timeout)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
loop:
	for {
		select {
		case <-timeoutChan:
			t.Fatalf("waiting for expected connections timeout after %s", timeout.String())
			break loop
		case <-ticker.C:
			totalConnected := 0
			for _, engine := range engines {
				totalConnected += getConnectedPeers(engine)
			}
			if totalConnected == expectedConnected {
				log.Infof("total connected=%d", totalConnected)
				break loop
			}
			log.Infof("total connected=%d", totalConnected)
		}
	}
	// cleanup test
	for n, peerEngine := range engines {
		t.Logf("stopping peer with interface %s from multipeer test, loopIndex %d", peerEngine.wgInterface.Name(), n)
		errStop := peerEngine.mgmClient.Close()
		if errStop != nil {
			log.Infoln("got error trying to close management clients from engine: ", errStop)
		}
		errStop = peerEngine.Stop()
		if errStop != nil {
			log.Infoln("got error trying to close testing peers engine: ", errStop)
		}
	}
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

func createEngine(ctx context.Context, cancel context.CancelFunc, setupKey string, i int, mgmtAddr string, signalAddr string) (*Engine, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	mgmtClient, err := mgmt.NewClient(ctx, mgmtAddr, key, false)
	if err != nil {
		return nil, err
	}
	signalClient, err := signal.NewClient(ctx, signalAddr, key, false)
	if err != nil {
		return nil, err
	}

	info := system.GetInfo(ctx)
	resp, err := mgmtClient.Register(setupKey, "", info, nil, nil)
	if err != nil {
		return nil, err
	}

	var ifaceName string
	if runtime.GOOS == "darwin" {
		ifaceName = fmt.Sprintf("utun1%d", i)
	} else {
		ifaceName = fmt.Sprintf("wt%d", i)
	}

	wgPort := 33100 + i
	conf := &EngineConfig{
		WgIfaceName:  ifaceName,
		WgAddr:       wgaddr.MustParseWGAddress(resp.PeerConfig.Address),
		WgPrivateKey: key,
		WgPort:       wgPort,
		MTU:          iface.DefaultMTU,
	}

	relayMgr := relayClient.NewManager(ctx, nil, key.PublicKey().String(), iface.DefaultMTU)
	e, err := NewEngine(ctx, cancel, conf, EngineServices{
		SignalClient:   signalClient,
		MgmClient:      mgmtClient,
		RelayManager:   relayMgr,
		StatusRecorder: peer.NewRecorder("https://mgm"),
	}, MobileDependency{}), nil
	e.ctx = ctx
	return e, err
}

func startSignal(t *testing.T) (*grpc.Server, string, error) {
	t.Helper()

	s := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	srv, err := signalServer.NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	proto.RegisterSignalExchangeServer(s, srv)

	go func() {
		if err = s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	return s, lis.Addr().String(), nil
}

func startManagement(t *testing.T, dataDir, testFile string) (*grpc.Server, string, error) {
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
		return nil, "", err
	}
	s := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))

	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), testFile, config.Datadir)
	if err != nil {
		return nil, "", err
	}
	t.Cleanup(cleanUp)

	eventStore := &activity.InMemoryEventStore{}
	if err != nil {
		return nil, "", err
	}

	permissionsManager := permissions.NewManager(store)
	peersManager := peers.NewManager(store, permissionsManager)
	jobManager := job.NewJobManager(nil, store, peersManager)

	cacheStore, err := nbcache.NewStore(context.Background(), 100*time.Millisecond, 300*time.Millisecond, 100)
	if err != nil {
		return nil, "", err
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
	networkMapController := controller.NewController(context.Background(), store, metrics, updateManager, requestBuffer, server.MockIntegratedValidator{}, settingsMockManager, "netbird.selfhosted", port_forwarding.NewControllerMock(), manager.NewEphemeralManager(store, peersManager), config)
	accountManager, err := server.BuildManager(context.Background(), config, store, networkMapController, jobManager, nil, "", eventStore, nil, false, ia, metrics, port_forwarding.NewControllerMock(), settingsMockManager, permissionsManager, false, cacheStore)
	if err != nil {
		return nil, "", err
	}

	secretsManager, err := nbgrpc.NewTimeBasedAuthSecretsManager(updateManager, config.TURNConfig, config.Relay, settingsMockManager, groupsManager)
	if err != nil {
		return nil, "", err
	}
	mgmtServer, err := nbgrpc.NewServer(config, accountManager, settingsMockManager, jobManager, secretsManager, nil, nil, &server.MockIntegratedValidator{}, networkMapController, nil, nil)
	if err != nil {
		return nil, "", err
	}
	mgmtProto.RegisterManagementServiceServer(s, mgmtServer)
	go func() {
		if err = s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	return s, lis.Addr().String(), nil
}

// getConnectedPeers returns a connection Status or nil if peer connection wasn't found
func getConnectedPeers(e *Engine) int {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()
	i := 0
	for _, id := range e.peerStore.PeersPubKey() {
		conn, _ := e.peerStore.PeerConn(id)
		if conn.IsConnected() {
			i++
		}
	}
	return i
}

func getPeers(e *Engine) int {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()

	return len(e.peerStore.PeersPubKey())
}
