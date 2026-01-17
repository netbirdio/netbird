package server_test

import (
	"context"
	"math/rand"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	pb "github.com/golang/protobuf/proto" //nolint
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	ephemeral_manager "github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral/manager"
	"github.com/netbirdio/netbird/management/internals/server/config"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	"github.com/netbirdio/netbird/management/server/job"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/util"
)

const (
	ValidSetupKey = "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"
)

type testSuite struct {
	t            *testing.T
	addr         string
	grpcServer   *grpc.Server
	dataDir      string
	client       mgmtProto.ManagementServiceClient
	serverPubKey wgtypes.Key
	conn         *grpc.ClientConn
}

func setupTest(t *testing.T) *testSuite {
	t.Helper()
	level, _ := log.ParseLevel("Debug")
	log.SetLevel(level)

	ts := &testSuite{t: t}

	var err error
	ts.dataDir, err = os.MkdirTemp("", "netbird_mgmt_test_tmp_*")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}

	config := &config.Config{}
	_, err = util.ReadJson("testdata/management.json", config)
	if err != nil {
		t.Fatalf("failed to read management.json: %v", err)
	}
	config.Datadir = ts.dataDir

	var listener net.Listener
	ts.grpcServer, listener = startServer(t, config, ts.dataDir, "testdata/store.sql")
	ts.addr = listener.Addr().String()

	ts.client, ts.conn = createRawClient(t, ts.addr)

	resp, err := ts.client.GetServerKey(context.TODO(), &mgmtProto.Empty{})
	if err != nil {
		t.Fatalf("failed to get server key: %v", err)
	}

	serverKey, err := wgtypes.ParseKey(resp.Key)
	if err != nil {
		t.Fatalf("failed to parse server key: %v", err)
	}
	ts.serverPubKey = serverKey

	return ts
}

func tearDownTest(t *testing.T, ts *testSuite) {
	t.Helper()
	ts.grpcServer.Stop()
	if err := ts.conn.Close(); err != nil {
		t.Fatalf("failed to close client connection: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := os.RemoveAll(ts.dataDir); err != nil {
		t.Fatalf("failed to remove data directory %s: %v", ts.dataDir, err)
	}
}

func loginPeerWithValidSetupKey(
	t *testing.T,
	serverPubKey wgtypes.Key,
	key wgtypes.Key,
	client mgmtProto.ManagementServiceClient,
) *mgmtProto.LoginResponse {
	t.Helper()
	meta := &mgmtProto.PeerSystemMeta{
		Hostname:       key.PublicKey().String(),
		GoOS:           runtime.GOOS,
		OS:             runtime.GOOS,
		Core:           "core",
		Platform:       "platform",
		Kernel:         "kernel",
		NetbirdVersion: "",
	}
	msgToEncrypt := &mgmtProto.LoginRequest{SetupKey: ValidSetupKey, Meta: meta}
	message, err := encryption.EncryptMessage(serverPubKey, key, msgToEncrypt)
	if err != nil {
		t.Fatalf("failed to encrypt login request: %v", err)
	}

	resp, err := client.Login(context.TODO(), &mgmtProto.EncryptedMessage{
		WgPubKey: key.PublicKey().String(),
		Body:     message,
	})
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}

	loginResp := &mgmtProto.LoginResponse{}
	err = encryption.DecryptMessage(serverPubKey, key, resp.Body, loginResp)
	if err != nil {
		t.Fatalf("failed to decrypt login response: %v", err)
	}
	return loginResp
}

func createRawClient(t *testing.T, addr string) (mgmtProto.ManagementServiceClient, *grpc.ClientConn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    10 * time.Second,
			Timeout: 2 * time.Second,
		}))
	if err != nil {
		t.Fatalf("failed to dial gRPC server: %v", err)
	}

	return mgmtProto.NewManagementServiceClient(conn), conn
}

func startServer(
	t *testing.T,
	config *config.Config,
	dataDir string,
	testFile string,
) (*grpc.Server, net.Listener) {
	t.Helper()
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("failed to listen on a random port: %v", err)
	}
	s := grpc.NewServer()

	str, _, err := store.NewTestStoreFromSQL(context.Background(), testFile, dataDir)
	if err != nil {
		log.Fatalf("failed creating a store: %s: %v", config.Datadir, err)
	}

	eventStore := &activity.InMemoryEventStore{}

	metrics, err := telemetry.NewDefaultAppMetrics(context.Background())
	if err != nil {
		t.Fatalf("failed creating metrics: %v", err)
	}

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	settingsMockManager := settings.NewMockManager(ctrl)
	settingsMockManager.
		EXPECT().
		GetExtraSettings(gomock.Any(), gomock.Any()).
		Return(&types.ExtraSettings{}, nil).
		AnyTimes()
	settingsMockManager.
		EXPECT().
		GetSettings(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&types.Settings{}, nil).
		AnyTimes()

	permissionsManager := permissions.NewManager(str)
	peersManager := peers.NewManager(str, permissionsManager)
	jobManager := job.NewJobManager(nil, str, peersManager)

	ctx := context.Background()
	updateManager := update_channel.NewPeersUpdateManager(metrics)
	requestBuffer := server.NewAccountRequestBuffer(ctx, str)
	networkMapController := controller.NewController(ctx, str, metrics, updateManager, requestBuffer, server.MockIntegratedValidator{}, settingsMockManager, "netbird.selfhosted", port_forwarding.NewControllerMock(), ephemeral_manager.NewEphemeralManager(str, peers.NewManager(str, permissionsManager)), config)

	accountManager, err := server.BuildManager(
		context.Background(),
		nil,
		str,
		networkMapController,
		jobManager,
		nil,
		"",
		eventStore,
		nil,
		false,
		server.MockIntegratedValidator{},
		metrics,
		port_forwarding.NewControllerMock(),
		settingsMockManager,
		permissionsManager,
		false)
	if err != nil {
		t.Fatalf("failed creating an account manager: %v", err)
	}

	groupsManager := groups.NewManager(str, permissionsManager, accountManager)
	secretsManager, err := nbgrpc.NewTimeBasedAuthSecretsManager(updateManager, config.TURNConfig, config.Relay, settingsMockManager, groupsManager)
	if err != nil {
		t.Fatalf("failed creating secrets manager: %v", err)
	}
	mgmtServer, err := nbgrpc.NewServer(
		config,
		accountManager,
		settingsMockManager,
		jobManager,
		secretsManager,
		nil,
		nil,
		server.MockIntegratedValidator{},
		networkMapController,
		nil,
	)
	if err != nil {
		t.Fatalf("failed creating management server: %v", err)
	}

	mgmtProto.RegisterManagementServiceServer(s, mgmtServer)

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("failed to serve gRPC: %v", err)
			return
		}
	}()

	return s, lis
}

func TestIsHealthy(t *testing.T) {
	ts := setupTest(t)
	defer tearDownTest(t, ts)

	healthy, err := ts.client.IsHealthy(context.TODO(), &mgmtProto.Empty{})
	if err != nil {
		t.Fatalf("IsHealthy call returned an error: %v", err)
	}
	if healthy == nil {
		t.Fatal("IsHealthy returned a nil response")
	}
}

func TestSyncNewPeerConfiguration(t *testing.T) {
	ts := setupTest(t)
	defer tearDownTest(t, ts)

	peerKey, _ := wgtypes.GenerateKey()
	loginPeerWithValidSetupKey(t, ts.serverPubKey, peerKey, ts.client)

	syncReq := &mgmtProto.SyncRequest{Meta: &mgmtProto.PeerSystemMeta{}}
	encryptedBytes, err := encryption.EncryptMessage(ts.serverPubKey, peerKey, syncReq)
	if err != nil {
		t.Fatalf("failed to encrypt sync request: %v", err)
	}

	syncStream, err := ts.client.Sync(context.TODO(), &mgmtProto.EncryptedMessage{
		WgPubKey: peerKey.PublicKey().String(),
		Body:     encryptedBytes,
	})
	if err != nil {
		t.Fatalf("failed to call Sync: %v", err)
	}

	encryptedResponse := &mgmtProto.EncryptedMessage{}
	err = syncStream.RecvMsg(encryptedResponse)
	if err != nil {
		t.Fatalf("failed to receive sync response message: %v", err)
	}

	resp := &mgmtProto.SyncResponse{}
	err = encryption.DecryptMessage(ts.serverPubKey, peerKey, encryptedResponse.Body, resp)
	if err != nil {
		t.Fatalf("failed to decrypt sync response: %v", err)
	}

	expectedSignalConfig := &mgmtProto.HostConfig{
		Uri:      "signal.netbird.io:10000",
		Protocol: mgmtProto.HostConfig_HTTP,
	}
	expectedStunsConfig := &mgmtProto.HostConfig{
		Uri:      "stun:stun.netbird.io:3468",
		Protocol: mgmtProto.HostConfig_UDP,
	}
	expectedTRUNHost := &mgmtProto.HostConfig{
		Uri:      "turn:stun.netbird.io:3468",
		Protocol: mgmtProto.HostConfig_UDP,
	}

	expectedRelayHost := &mgmtProto.RelayConfig{
		Urls: []string{"rel://test.com:3535"},
	}

	assert.NotNil(t, resp.NetbirdConfig)
	assert.Equal(t, resp.NetbirdConfig.Signal, expectedSignalConfig)
	assert.Contains(t, resp.NetbirdConfig.Stuns, expectedStunsConfig)
	assert.Equal(t, len(resp.NetbirdConfig.Turns), 1)
	actualTURN := resp.NetbirdConfig.Turns[0]
	assert.Greater(t, len(actualTURN.User), 0)
	assert.Equal(t, actualTURN.HostConfig, expectedTRUNHost)
	assert.Equal(t, len(resp.NetbirdConfig.Relay.Urls), 1)
	assert.Equal(t, resp.NetbirdConfig.Relay.Urls, expectedRelayHost.Urls)
	assert.Equal(t, len(resp.NetworkMap.OfflinePeers), 0)
}

func TestSyncThreePeers(t *testing.T) {
	ts := setupTest(t)
	defer tearDownTest(t, ts)

	peerKey, _ := wgtypes.GenerateKey()
	peerKey1, _ := wgtypes.GenerateKey()
	peerKey2, _ := wgtypes.GenerateKey()

	loginPeerWithValidSetupKey(t, ts.serverPubKey, peerKey, ts.client)
	loginPeerWithValidSetupKey(t, ts.serverPubKey, peerKey1, ts.client)
	loginPeerWithValidSetupKey(t, ts.serverPubKey, peerKey2, ts.client)

	syncReq := &mgmtProto.SyncRequest{Meta: &mgmtProto.PeerSystemMeta{}}
	syncBytes, err := pb.Marshal(syncReq)
	if err != nil {
		t.Fatalf("failed to marshal sync request: %v", err)
	}
	encryptedBytes, err := encryption.Encrypt(syncBytes, ts.serverPubKey, peerKey)
	if err != nil {
		t.Fatalf("failed to encrypt sync request: %v", err)
	}

	syncStream, err := ts.client.Sync(context.TODO(), &mgmtProto.EncryptedMessage{
		WgPubKey: peerKey.PublicKey().String(),
		Body:     encryptedBytes,
	})
	if err != nil {
		t.Fatalf("failed to call Sync: %v", err)
	}

	encryptedResponse := &mgmtProto.EncryptedMessage{}
	err = syncStream.RecvMsg(encryptedResponse)
	if err != nil {
		t.Fatalf("failed to receive sync response: %v", err)
	}

	decryptedBytes, err := encryption.Decrypt(encryptedResponse.Body, ts.serverPubKey, peerKey)
	if err != nil {
		t.Fatalf("failed to decrypt sync response: %v", err)
	}

	resp := &mgmtProto.SyncResponse{}
	err = pb.Unmarshal(decryptedBytes, resp)
	if err != nil {
		t.Fatalf("failed to unmarshal sync response: %v", err)
	}

	if len(resp.GetRemotePeers()) != 2 {
		t.Fatalf("expected 2 remote peers, got %d", len(resp.GetRemotePeers()))
	}

	var found1, found2 bool
	for _, rp := range resp.GetRemotePeers() {
		if rp.WgPubKey == peerKey1.PublicKey().String() {
			found1 = true
		} else if rp.WgPubKey == peerKey2.PublicKey().String() {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Fatalf("did not find the expected peer keys %s, %s among %v",
			peerKey1.PublicKey().String(),
			peerKey2.PublicKey().String(),
			resp.GetRemotePeers())
	}
}

func TestSyncNewPeerUpdate(t *testing.T) {
	ts := setupTest(t)
	defer tearDownTest(t, ts)

	peerKey, _ := wgtypes.GenerateKey()
	loginPeerWithValidSetupKey(t, ts.serverPubKey, peerKey, ts.client)

	syncReq := &mgmtProto.SyncRequest{Meta: &mgmtProto.PeerSystemMeta{}}
	syncBytes, err := pb.Marshal(syncReq)
	if err != nil {
		t.Fatalf("failed to marshal sync request: %v", err)
	}

	encryptedBytes, err := encryption.Encrypt(syncBytes, ts.serverPubKey, peerKey)
	if err != nil {
		t.Fatalf("failed to encrypt sync request: %v", err)
	}

	syncStream, err := ts.client.Sync(context.TODO(), &mgmtProto.EncryptedMessage{
		WgPubKey: peerKey.PublicKey().String(),
		Body:     encryptedBytes,
	})
	if err != nil {
		t.Fatalf("failed to call Sync: %v", err)
	}

	encryptedResponse := &mgmtProto.EncryptedMessage{}
	err = syncStream.RecvMsg(encryptedResponse)
	if err != nil {
		t.Fatalf("failed to receive first sync response: %v", err)
	}

	decryptedBytes, err := encryption.Decrypt(encryptedResponse.Body, ts.serverPubKey, peerKey)
	if err != nil {
		t.Fatalf("failed to decrypt first sync response: %v", err)
	}

	resp := &mgmtProto.SyncResponse{}
	if err := pb.Unmarshal(decryptedBytes, resp); err != nil {
		t.Fatalf("failed to unmarshal first sync response: %v", err)
	}

	if len(resp.GetRemotePeers()) != 0 {
		t.Fatalf("expected 0 remote peers at first sync, got %d", len(resp.GetRemotePeers()))
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		encryptedResponse := &mgmtProto.EncryptedMessage{}
		err = syncStream.RecvMsg(encryptedResponse)
		if err != nil {
			t.Errorf("failed to receive second sync response: %v", err)
			return
		}

		decryptedBytes, err := encryption.Decrypt(encryptedResponse.Body, ts.serverPubKey, peerKey)
		if err != nil {
			t.Errorf("failed to decrypt second sync response: %v", err)
			return
		}
		err = pb.Unmarshal(decryptedBytes, resp)
		if err != nil {
			t.Errorf("failed to unmarshal second sync response: %v", err)
			return
		}
	}()

	newPeerKey, _ := wgtypes.GenerateKey()
	loginPeerWithValidSetupKey(t, ts.serverPubKey, newPeerKey, ts.client)

	wg.Wait()

	if len(resp.GetRemotePeers()) != 1 {
		t.Fatalf("expected exactly 1 remote peer update, got %d", len(resp.GetRemotePeers()))
	}
	if resp.GetRemotePeers()[0].WgPubKey != newPeerKey.PublicKey().String() {
		t.Fatalf("expected new peer key %s, got %s",
			newPeerKey.PublicKey().String(),
			resp.GetRemotePeers()[0].WgPubKey)
	}
}

func TestGetServerKey(t *testing.T) {
	ts := setupTest(t)
	defer tearDownTest(t, ts)

	resp, err := ts.client.GetServerKey(context.TODO(), &mgmtProto.Empty{})
	if err != nil {
		t.Fatalf("GetServerKey returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("GetServerKey returned nil response")
	}
	if resp.Key == "" {
		t.Fatal("GetServerKey returned empty key")
	}
	if resp.ExpiresAt.AsTime().IsZero() {
		t.Fatal("GetServerKey returned 0 for ExpiresAt")
	}

	_, err = wgtypes.ParseKey(resp.Key)
	if err != nil {
		t.Fatalf("GetServerKey returned an invalid WG key: %v", err)
	}
}

func TestLoginInvalidSetupKey(t *testing.T) {
	ts := setupTest(t)
	defer tearDownTest(t, ts)

	peerKey, _ := wgtypes.GenerateKey()
	request := &mgmtProto.LoginRequest{
		SetupKey: "invalid setup key",
		Meta:     &mgmtProto.PeerSystemMeta{},
	}
	encryptedMsg, err := encryption.EncryptMessage(ts.serverPubKey, peerKey, request)
	if err != nil {
		t.Fatalf("failed to encrypt login request: %v", err)
	}

	resp, err := ts.client.Login(context.TODO(), &mgmtProto.EncryptedMessage{
		WgPubKey: peerKey.PublicKey().String(),
		Body:     encryptedMsg,
	})
	if err == nil {
		t.Fatal("expected error for invalid setup key but got nil")
	}
	if resp != nil {
		t.Fatalf("expected nil response for invalid setup key but got: %+v", resp)
	}
}

func TestLoginValidSetupKey(t *testing.T) {
	ts := setupTest(t)
	defer tearDownTest(t, ts)

	peerKey, _ := wgtypes.GenerateKey()
	resp := loginPeerWithValidSetupKey(t, ts.serverPubKey, peerKey, ts.client)
	if resp == nil {
		t.Fatal("loginPeerWithValidSetupKey returned nil, expected a valid response")
	}
}

func TestLoginRegisteredPeer(t *testing.T) {
	ts := setupTest(t)
	defer tearDownTest(t, ts)

	peerKey, _ := wgtypes.GenerateKey()
	regResp := loginPeerWithValidSetupKey(t, ts.serverPubKey, peerKey, ts.client)
	if regResp == nil {
		t.Fatal("registration with valid setup key failed")
	}

	loginReq := &mgmtProto.LoginRequest{Meta: &mgmtProto.PeerSystemMeta{}}
	encryptedLogin, err := encryption.EncryptMessage(ts.serverPubKey, peerKey, loginReq)
	if err != nil {
		t.Fatalf("failed to encrypt login request: %v", err)
	}
	loginRespEnc, err := ts.client.Login(context.TODO(), &mgmtProto.EncryptedMessage{
		WgPubKey: peerKey.PublicKey().String(),
		Body:     encryptedLogin,
	})
	if err != nil {
		t.Fatalf("login call returned an error: %v", err)
	}

	loginResp := &mgmtProto.LoginResponse{}
	err = encryption.DecryptMessage(ts.serverPubKey, peerKey, loginRespEnc.Body, loginResp)
	if err != nil {
		t.Fatalf("failed to decrypt login response: %v", err)
	}

	expectedSignalConfig := &mgmtProto.HostConfig{
		Uri:      "signal.netbird.io:10000",
		Protocol: mgmtProto.HostConfig_HTTP,
	}
	expectedStunsConfig := &mgmtProto.HostConfig{
		Uri:      "stun:stun.netbird.io:3468",
		Protocol: mgmtProto.HostConfig_UDP,
	}
	expectedTurnsConfig := &mgmtProto.ProtectedHostConfig{
		HostConfig: &mgmtProto.HostConfig{
			Uri:      "turn:stun.netbird.io:3468",
			Protocol: mgmtProto.HostConfig_UDP,
		},
		User:     "some_user",
		Password: "some_password",
	}

	assert.NotNil(t, loginResp.GetNetbirdConfig())
	assert.Equal(t, loginResp.GetNetbirdConfig().Signal, expectedSignalConfig)
	assert.Contains(t, loginResp.GetNetbirdConfig().Stuns, expectedStunsConfig)
	assert.Contains(t, loginResp.GetNetbirdConfig().Turns, expectedTurnsConfig)
}

func TestSync10PeersGetUpdates(t *testing.T) {
	ts := setupTest(t)
	defer tearDownTest(t, ts)

	initialPeers := 10
	additionalPeers := 10

	var peers []wgtypes.Key
	for i := 0; i < initialPeers; i++ {
		key, _ := wgtypes.GenerateKey()
		loginPeerWithValidSetupKey(t, ts.serverPubKey, key, ts.client)
		peers = append(peers, key)
	}

	var wg sync.WaitGroup
	wg.Add(initialPeers + initialPeers*additionalPeers)

	var syncClients []mgmtProto.ManagementService_SyncClient
	for _, pk := range peers {
		syncReq := &mgmtProto.SyncRequest{Meta: &mgmtProto.PeerSystemMeta{}}
		msgBytes, err := pb.Marshal(syncReq)
		if err != nil {
			t.Fatalf("failed to marshal SyncRequest: %v", err)
		}
		encBytes, err := encryption.Encrypt(msgBytes, ts.serverPubKey, pk)
		if err != nil {
			t.Fatalf("failed to encrypt SyncRequest: %v", err)
		}

		s, err := ts.client.Sync(context.TODO(), &mgmtProto.EncryptedMessage{
			WgPubKey: pk.PublicKey().String(),
			Body:     encBytes,
		})
		if err != nil {
			t.Fatalf("failed to call Sync for peer: %v", err)
		}
		syncClients = append(syncClients, s)

		go func(pk wgtypes.Key, syncStream mgmtProto.ManagementService_SyncClient) {
			for {
				encMsg := &mgmtProto.EncryptedMessage{}
				err := syncStream.RecvMsg(encMsg)
				if err != nil {
					return
				}
				decryptedBytes, decErr := encryption.Decrypt(encMsg.Body, ts.serverPubKey, pk)
				if decErr != nil {
					t.Errorf("failed to decrypt SyncResponse for peer %s: %v", pk.PublicKey().String(), decErr)
					return
				}
				resp := &mgmtProto.SyncResponse{}
				umErr := pb.Unmarshal(decryptedBytes, resp)
				if umErr != nil {
					t.Errorf("failed to unmarshal SyncResponse for peer %s: %v", pk.PublicKey().String(), umErr)
					return
				}
				// We only count if there's a new peer update
				if len(resp.GetRemotePeers()) > 0 {
					wg.Done()
				}
			}
		}(pk, s)
	}

	time.Sleep(500 * time.Millisecond)
	for i := 0; i < additionalPeers; i++ {
		key, _ := wgtypes.GenerateKey()
		loginPeerWithValidSetupKey(t, ts.serverPubKey, key, ts.client)
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		n := r.Intn(200)
		time.Sleep(time.Duration(n) * time.Millisecond)
	}

	wg.Wait()

	for _, sc := range syncClients {
		err := sc.CloseSend()
		if err != nil {
			t.Fatalf("failed to close sync client: %v", err)
		}
	}
}

func TestConcurrentPeersNoDuplicateIPs(t *testing.T) {
	ts := setupTest(t)
	defer tearDownTest(t, ts)

	initialPeers := 30
	ipChan := make(chan string, initialPeers)

	var wg sync.WaitGroup
	wg.Add(initialPeers)

	for i := 0; i < initialPeers; i++ {
		go func() {
			defer wg.Done()
			key, _ := wgtypes.GenerateKey()
			loginPeerWithValidSetupKey(t, ts.serverPubKey, key, ts.client)

			syncReq := &mgmtProto.SyncRequest{Meta: &mgmtProto.PeerSystemMeta{}}
			encryptedBytes, err := encryption.EncryptMessage(ts.serverPubKey, key, syncReq)
			if err != nil {
				t.Errorf("failed to encrypt sync request: %v", err)
				return
			}

			s, err := ts.client.Sync(context.TODO(), &mgmtProto.EncryptedMessage{
				WgPubKey: key.PublicKey().String(),
				Body:     encryptedBytes,
			})
			if err != nil {
				t.Errorf("failed to call Sync: %v", err)
				return
			}

			encResp := &mgmtProto.EncryptedMessage{}
			if err = s.RecvMsg(encResp); err != nil {
				t.Errorf("failed to receive sync response: %v", err)
				return
			}

			resp := &mgmtProto.SyncResponse{}
			if err = encryption.DecryptMessage(ts.serverPubKey, key, encResp.Body, resp); err != nil {
				t.Errorf("failed to decrypt sync response: %v", err)
				return
			}
			ipChan <- resp.GetPeerConfig().Address
		}()
	}

	wg.Wait()
	close(ipChan)

	ipMap := make(map[string]bool)
	for ip := range ipChan {
		if ipMap[ip] {
			t.Fatalf("found duplicate IP: %s", ip)
		}
		ipMap[ip] = true
	}

	// Ensure we collected all peers
	if len(ipMap) != initialPeers {
		t.Fatalf("expected %d unique IPs, got %d", initialPeers, len(ipMap))
	}
}
