package client

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/server/activity"

	"github.com/netbirdio/netbird/client/system"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/management-integrations/integrations"

	"github.com/netbirdio/netbird/encryption"
	mgmtProto "github.com/netbirdio/netbird/management/proto"
	mgmt "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/mock_server"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/util"
)

const ValidKey = "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"

func TestMain(m *testing.M) {
	_ = util.InitLog("debug", "console")
	code := m.Run()
	os.Exit(code)
}

func startManagement(t *testing.T) (*grpc.Server, net.Listener) {
	t.Helper()
	level, _ := log.ParseLevel("debug")
	log.SetLevel(level)

	testDir := t.TempDir()

	config := &mgmt.Config{}
	_, err := util.ReadJson("../server/testdata/management.json", config)
	if err != nil {
		t.Fatal(err)
	}
	config.Datadir = testDir
	err = util.CopyFileContents("../server/testdata/store.json", filepath.Join(testDir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}

	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	store, cleanUp, err := mgmt.NewTestStoreFromJson(config.Datadir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)

	peersUpdateManager := mgmt.NewPeersUpdateManager(nil)
	eventStore := &activity.InMemoryEventStore{}
	ia, _ := integrations.NewIntegratedValidator(eventStore)
	accountManager, err := mgmt.BuildManager(store, peersUpdateManager, nil, "", "netbird.selfhosted", eventStore, nil, false, ia)
	if err != nil {
		t.Fatal(err)
	}
	turnManager := mgmt.NewTimeBasedAuthSecretsManager(peersUpdateManager, config.TURNConfig)
	mgmtServer, err := mgmt.NewServer(config, accountManager, peersUpdateManager, turnManager, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	mgmtProto.RegisterManagementServiceServer(s, mgmtServer)
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Error(err)
			return
		}
	}()

	return s, lis
}

func startMockManagement(t *testing.T) (*grpc.Server, net.Listener, *mock_server.ManagementServiceServerMock, wgtypes.Key) {
	t.Helper()
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}

	s := grpc.NewServer()

	serverKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	mgmtMockServer := &mock_server.ManagementServiceServerMock{
		GetServerKeyFunc: func(context.Context, *mgmtProto.Empty) (*mgmtProto.ServerKeyResponse, error) {
			response := &mgmtProto.ServerKeyResponse{
				Key: serverKey.PublicKey().String(),
			}
			return response, nil
		},
	}

	mgmtProto.RegisterManagementServiceServer(s, mgmtMockServer)
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Error(err)
			return
		}
	}()

	return s, lis, mgmtMockServer, serverKey
}

func closeManagementSilently(s *grpc.Server, listener net.Listener) {
	s.GracefulStop()
	err := listener.Close()
	if err != nil {
		log.Warnf("error while closing management listener %v", err)
		return
	}
}

func TestClient_GetServerPublicKey(t *testing.T) {
	testKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s, listener := startManagement(t)
	defer closeManagementSilently(s, listener)

	client, err := NewClient(ctx, listener.Addr().String(), testKey, false)
	if err != nil {
		t.Fatal(err)
	}

	key, err := client.GetServerPublicKey()
	if err != nil {
		t.Error("couldn't retrieve management public key")
	}
	if key == nil {
		t.Error("got an empty management public key")
	}
}

func TestClient_LoginUnregistered_ShouldThrow_401(t *testing.T) {
	testKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s, listener := startManagement(t)
	defer closeManagementSilently(s, listener)

	client, err := NewClient(ctx, listener.Addr().String(), testKey, false)
	if err != nil {
		t.Fatal(err)
	}
	key, err := client.GetServerPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	sysInfo := system.GetInfo(context.TODO())
	_, err = client.Login(*key, sysInfo, nil)
	if err == nil {
		t.Error("expecting err on unregistered login, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.PermissionDenied {
		t.Errorf("expecting err code %d denied on unregistered login got %d", codes.PermissionDenied, s.Code())
	}
}

func TestClient_LoginRegistered(t *testing.T) {
	testKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s, listener := startManagement(t)
	defer closeManagementSilently(s, listener)

	client, err := NewClient(ctx, listener.Addr().String(), testKey, false)
	if err != nil {
		t.Fatal(err)
	}

	key, err := client.GetServerPublicKey()
	if err != nil {
		t.Error(err)
	}
	info := system.GetInfo(context.TODO())
	resp, err := client.Register(*key, ValidKey, "", info, nil)
	if err != nil {
		t.Error(err)
	}

	if resp == nil {
		t.Error("expecting non nil response, got nil")
	}
}

func TestClient_Sync(t *testing.T) {
	testKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s, listener := startManagement(t)
	defer closeManagementSilently(s, listener)

	client, err := NewClient(ctx, listener.Addr().String(), testKey, false)
	if err != nil {
		t.Fatal(err)
	}

	serverKey, err := client.GetServerPublicKey()
	if err != nil {
		t.Error(err)
	}

	info := system.GetInfo(context.TODO())
	_, err = client.Register(*serverKey, ValidKey, "", info, nil)
	if err != nil {
		t.Error(err)
	}

	// create and register second peer (we should receive on Sync request)
	remoteKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Error(err)
	}
	remoteClient, err := NewClient(context.TODO(), listener.Addr().String(), remoteKey, false)
	if err != nil {
		t.Fatal(err)
	}

	info = system.GetInfo(context.TODO())
	_, err = remoteClient.Register(*serverKey, ValidKey, "", info, nil)
	if err != nil {
		t.Fatal(err)
	}

	ch := make(chan *mgmtProto.SyncResponse, 1)

	go func() {
		err = client.Sync(context.Background(), func(msg *mgmtProto.SyncResponse) error {
			ch <- msg
			return nil
		})
		if err != nil {
			return
		}
	}()

	select {
	case resp := <-ch:
		if resp.GetPeerConfig() == nil {
			t.Error("expecting non nil PeerConfig got nil")
		}
		if resp.GetWiretrusteeConfig() == nil {
			t.Error("expecting non nil WiretrusteeConfig got nil")
		}
		if len(resp.GetRemotePeers()) != 1 {
			t.Errorf("expecting RemotePeers size %d got %d", 1, len(resp.GetRemotePeers()))
			return
		}
		if resp.GetRemotePeersIsEmpty() == true {
			t.Error("expecting RemotePeers property to be false, got true")
		}
		if resp.GetRemotePeers()[0].GetWgPubKey() != remoteKey.PublicKey().String() {
			t.Errorf("expecting RemotePeer public key %s got %s", remoteKey.PublicKey().String(), resp.GetRemotePeers()[0].GetWgPubKey())
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for test to finish")
	}
}

func Test_SystemMetaDataFromClient(t *testing.T) {
	s, lis, mgmtMockServer, serverKey := startMockManagement(t)
	defer s.GracefulStop()

	testKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	serverAddr := lis.Addr().String()
	ctx := context.Background()

	testClient, err := NewClient(ctx, serverAddr, testKey, false)
	if err != nil {
		t.Fatalf("error while creating testClient: %v", err)
	}

	key, err := testClient.GetServerPublicKey()
	if err != nil {
		t.Fatalf("error while getting server public key from testclient, %v", err)
	}

	var actualMeta *mgmtProto.PeerSystemMeta
	var actualValidKey string
	var wg sync.WaitGroup
	wg.Add(1)

	mgmtMockServer.LoginFunc = func(ctx context.Context, msg *mgmtProto.EncryptedMessage) (*mgmtProto.EncryptedMessage, error) {
		peerKey, err := wgtypes.ParseKey(msg.GetWgPubKey())
		if err != nil {
			log.Warnf("error while parsing peer's Wireguard public key %s on Sync request.", msg.WgPubKey)
			return nil, status.Errorf(codes.InvalidArgument, "provided wgPubKey %s is invalid", msg.WgPubKey)
		}

		loginReq := &mgmtProto.LoginRequest{}
		err = encryption.DecryptMessage(peerKey, serverKey, msg.Body, loginReq)
		if err != nil {
			log.Fatal(err)
		}

		actualMeta = loginReq.GetMeta()
		actualValidKey = loginReq.GetSetupKey()
		wg.Done()

		loginResp := &mgmtProto.LoginResponse{}
		encryptedResp, err := encryption.EncryptMessage(peerKey, serverKey, loginResp)
		if err != nil {
			return nil, err
		}

		return &mgmtProto.EncryptedMessage{
			WgPubKey: serverKey.PublicKey().String(),
			Body:     encryptedResp,
			Version:  0,
		}, nil
	}

	info := system.GetInfo(context.TODO())
	_, err = testClient.Register(*key, ValidKey, "", info, nil)
	if err != nil {
		t.Errorf("error while trying to register client: %v", err)
	}

	wg.Wait()

	protoNetAddr := make([]*mgmtProto.NetworkAddress, 0, len(info.NetworkAddresses))
	for _, addr := range info.NetworkAddresses {
		protoNetAddr = append(protoNetAddr, &mgmtProto.NetworkAddress{
			NetIP: addr.NetIP.String(),
			Mac:   addr.Mac,
		})

	}

	expectedMeta := &mgmtProto.PeerSystemMeta{
		Hostname:           info.Hostname,
		GoOS:               info.GoOS,
		Kernel:             info.Kernel,
		Platform:           info.Platform,
		OS:                 info.OS,
		Core:               info.OSVersion,
		OSVersion:          info.OSVersion,
		WiretrusteeVersion: info.WiretrusteeVersion,
		KernelVersion:      info.KernelVersion,

		NetworkAddresses: protoNetAddr,
		SysSerialNumber:  info.SystemSerialNumber,
		SysProductName:   info.SystemProductName,
		SysManufacturer:  info.SystemManufacturer,
		Environment:      &mgmtProto.Environment{Cloud: info.Environment.Cloud, Platform: info.Environment.Platform},
		Ipv6Supported:      info.Ipv6Supported,
	}

	assert.Equal(t, ValidKey, actualValidKey)
	if !isEqual(expectedMeta, actualMeta) {
		t.Errorf("expected and actual meta are not equal")
	}
}

func isEqual(a, b *mgmtProto.PeerSystemMeta) bool {
	if len(a.NetworkAddresses) != len(b.NetworkAddresses) {
		return false
	}

	for _, addr := range a.GetNetworkAddresses() {
		var found bool
		for _, oAddr := range b.GetNetworkAddresses() {
			if addr.GetMac() == oAddr.GetMac() && addr.GetNetIP() == oAddr.GetNetIP() {
				found = true
				continue
			}
		}
		if !found {
			return false
		}
	}

	log.Infof("------")

	return a.GetHostname() == b.GetHostname() &&
		a.GetGoOS() == b.GetGoOS() &&
		a.GetKernel() == b.GetKernel() &&
		a.GetKernelVersion() == b.GetKernelVersion() &&
		a.GetCore() == b.GetCore() &&
		a.GetPlatform() == b.GetPlatform() &&
		a.GetOS() == b.GetOS() &&
		a.GetOSVersion() == b.GetOSVersion() &&
		a.GetWiretrusteeVersion() == b.GetWiretrusteeVersion() &&
		a.GetUiVersion() == b.GetUiVersion() &&
		a.GetSysSerialNumber() == b.GetSysSerialNumber() &&
		a.GetSysProductName() == b.GetSysProductName() &&
		a.GetSysManufacturer() == b.GetSysManufacturer() &&
		a.GetEnvironment().Cloud == b.GetEnvironment().Cloud &&
		a.GetEnvironment().Platform == b.GetEnvironment().Platform
}

func Test_GetDeviceAuthorizationFlow(t *testing.T) {
	s, lis, mgmtMockServer, serverKey := startMockManagement(t)
	defer s.GracefulStop()

	testKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	serverAddr := lis.Addr().String()
	ctx := context.Background()

	client, err := NewClient(ctx, serverAddr, testKey, false)
	if err != nil {
		t.Fatalf("error while creating testClient: %v", err)
	}

	expectedFlowInfo := &mgmtProto.DeviceAuthorizationFlow{
		Provider:       0,
		ProviderConfig: &mgmtProto.ProviderConfig{ClientID: "client"},
	}

	mgmtMockServer.GetDeviceAuthorizationFlowFunc = func(ctx context.Context, req *mgmtProto.EncryptedMessage) (*mgmtProto.EncryptedMessage, error) {
		encryptedResp, err := encryption.EncryptMessage(serverKey, client.key, expectedFlowInfo)
		if err != nil {
			return nil, err
		}

		return &mgmtProto.EncryptedMessage{
			WgPubKey: serverKey.PublicKey().String(),
			Body:     encryptedResp,
			Version:  0,
		}, nil
	}

	flowInfo, err := client.GetDeviceAuthorizationFlow(serverKey)
	if err != nil {
		t.Error("error while retrieving device auth flow information")
	}

	assert.Equal(t, expectedFlowInfo.Provider, flowInfo.Provider, "provider should match")
	assert.Equal(t, expectedFlowInfo.ProviderConfig.ClientID, flowInfo.ProviderConfig.ClientID, "provider configured client ID should match")
}

func Test_GetPKCEAuthorizationFlow(t *testing.T) {
	s, lis, mgmtMockServer, serverKey := startMockManagement(t)
	defer s.GracefulStop()

	testKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	serverAddr := lis.Addr().String()
	ctx := context.Background()

	client, err := NewClient(ctx, serverAddr, testKey, false)
	if err != nil {
		t.Fatalf("error while creating testClient: %v", err)
	}

	expectedFlowInfo := &mgmtProto.PKCEAuthorizationFlow{
		ProviderConfig: &mgmtProto.ProviderConfig{
			ClientID:     "client",
			ClientSecret: "secret",
		},
	}

	mgmtMockServer.GetPKCEAuthorizationFlowFunc = func(ctx context.Context, req *mgmtProto.EncryptedMessage) (*mgmtProto.EncryptedMessage, error) {
		encryptedResp, err := encryption.EncryptMessage(serverKey, client.key, expectedFlowInfo)
		if err != nil {
			return nil, err
		}

		return &mgmtProto.EncryptedMessage{
			WgPubKey: serverKey.PublicKey().String(),
			Body:     encryptedResp,
			Version:  0,
		}, nil
	}

	flowInfo, err := client.GetPKCEAuthorizationFlow(serverKey)
	if err != nil {
		t.Error("error while retrieving pkce auth flow information")
	}

	assert.Equal(t, expectedFlowInfo.ProviderConfig.ClientID, flowInfo.ProviderConfig.ClientID, "provider configured client ID should match")
	assert.Equal(t, expectedFlowInfo.ProviderConfig.ClientSecret, flowInfo.ProviderConfig.ClientSecret, "provider configured client secret should match")
}
