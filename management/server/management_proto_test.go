package server

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/netbirdio/netbird/encryption"
	mgmtProto "github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/util"
)

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

const (
	TestValidSetupKey = "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"
)

// registerPeers registers peersNum peers on the management service and returns their Wireguard keys
func registerPeers(peersNum int, client mgmtProto.ManagementServiceClient) ([]*wgtypes.Key, error) {
	peers := []*wgtypes.Key{}
	for i := 0; i < peersNum; i++ {
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}

		_, err = loginPeerWithValidSetupKey(key, client)
		if err != nil {
			return nil, err
		}

		peers = append(peers, &key)
	}

	return peers, nil
}

// getServerKey gets Management Service Wireguard public key
func getServerKey(client mgmtProto.ManagementServiceClient) (*wgtypes.Key, error) {
	keyResp, err := client.GetServerKey(context.TODO(), &mgmtProto.Empty{})
	if err != nil {
		return nil, err
	}

	serverKey, err := wgtypes.ParseKey(keyResp.Key)
	if err != nil {
		return nil, err
	}

	return &serverKey, nil
}

func Test_SyncProtocol(t *testing.T) {
	dir := t.TempDir()
	err := util.CopyFileContents("testdata/store_with_expired_peers.json", filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.Remove(filepath.Join(dir, "store.json")) //nolint
	}()
	mgmtServer, mgmtAddr, err := startManagement(t, &Config{
		Stuns: []*Host{{
			Proto: "udp",
			URI:   "stun:stun.wiretrustee.com:3468",
		}},
		TURNConfig: &TURNConfig{
			TimeBasedCredentials: false,
			CredentialsTTL:       util.Duration{},
			Secret:               "whatever",
			Turns: []*Host{{
				Proto: "udp",
				URI:   "turn:stun.wiretrustee.com:3468",
			}},
		},
		Signal: &Host{
			Proto: "http",
			URI:   "signal.wiretrustee.com:10000",
		},
		Datadir:    dir,
		HttpConfig: nil,
	})
	if err != nil {
		t.Fatal(err)
		return
	}
	defer mgmtServer.GracefulStop()

	client, clientConn, err := createRawClient(mgmtAddr)
	if err != nil {
		t.Fatal(err)
		return
	}

	defer clientConn.Close()

	// there are two peers already in the store, add two more
	peers, err := registerPeers(2, client)
	if err != nil {
		t.Fatal(err)
		return
	}

	serverKey, err := getServerKey(client)
	if err != nil {
		t.Fatal(err)
		return
	}

	// take the first registered peer as a base for the test. Total four.
	key := *peers[0]

	message, err := encryption.EncryptMessage(*serverKey, key, &mgmtProto.SyncRequest{})
	if err != nil {
		t.Fatal(err)
		return
	}

	sync, err := client.Sync(context.TODO(), &mgmtProto.EncryptedMessage{
		WgPubKey: key.PublicKey().String(),
		Body:     message,
	})
	if err != nil {
		t.Fatal(err)
		return
	}

	resp := &mgmtProto.EncryptedMessage{}
	err = sync.RecvMsg(resp)
	if err != nil {
		t.Fatal(err)
		return
	}

	syncResp := &mgmtProto.SyncResponse{}
	err = encryption.DecryptMessage(*serverKey, key, resp.Body, syncResp)
	if err != nil {
		t.Fatal(err)
		return
	}

	wiretrusteeConfig := syncResp.GetWiretrusteeConfig()
	if wiretrusteeConfig == nil {
		t.Fatal("expecting SyncResponse to have non-nil WiretrusteeConfig")
	}

	if wiretrusteeConfig.GetSignal() == nil {
		t.Fatal("expecting SyncResponse to have WiretrusteeConfig with non-nil Signal config")
	}

	expectedSignalConfig := &mgmtProto.HostConfig{
		Uri:      "signal.wiretrustee.com:10000",
		Protocol: mgmtProto.HostConfig_HTTP,
	}

	if wiretrusteeConfig.GetSignal().GetUri() != expectedSignalConfig.GetUri() {
		t.Fatalf("expecting SyncResponse to have WiretrusteeConfig with expected Signal URI: %v, actual: %v",
			expectedSignalConfig.GetUri(),
			wiretrusteeConfig.GetSignal().GetUri())
	}

	if wiretrusteeConfig.GetSignal().GetProtocol() != expectedSignalConfig.GetProtocol() {
		t.Fatalf("expecting SyncResponse to have WiretrusteeConfig with expected Signal Protocol: %v, actual: %v",
			expectedSignalConfig.GetProtocol().String(),
			wiretrusteeConfig.GetSignal().GetProtocol())
	}

	expectedStunsConfig := &mgmtProto.HostConfig{
		Uri:      "stun:stun.wiretrustee.com:3468",
		Protocol: mgmtProto.HostConfig_UDP,
	}

	if wiretrusteeConfig.GetStuns()[0].GetUri() != expectedStunsConfig.GetUri() {
		t.Fatalf("expecting SyncResponse to have WiretrusteeConfig with expected STUN URI: %v, actual: %v",
			expectedStunsConfig.GetUri(),
			wiretrusteeConfig.GetStuns()[0].GetUri())
	}

	if wiretrusteeConfig.GetStuns()[0].GetProtocol() != expectedStunsConfig.GetProtocol() {
		t.Fatalf("expecting SyncResponse to have WiretrusteeConfig with expected STUN Protocol: %v, actual: %v",
			expectedStunsConfig.GetProtocol(),
			wiretrusteeConfig.GetStuns()[0].GetProtocol())
	}

	expectedTRUNHost := &mgmtProto.HostConfig{
		Uri:      "turn:stun.wiretrustee.com:3468",
		Protocol: mgmtProto.HostConfig_UDP,
	}

	if wiretrusteeConfig.GetTurns()[0].GetHostConfig().GetUri() != expectedTRUNHost.GetUri() {
		t.Fatalf("expecting SyncResponse to have WiretrusteeConfig with expected TURN URI: %v, actual: %v",
			expectedTRUNHost.GetUri(),
			wiretrusteeConfig.GetTurns()[0].GetHostConfig().GetUri())
	}

	if wiretrusteeConfig.GetTurns()[0].GetHostConfig().GetProtocol() != expectedTRUNHost.GetProtocol() {
		t.Fatalf("expecting SyncResponse to have WiretrusteeConfig with expected TURN Protocol: %v, actual: %v",
			expectedTRUNHost.GetProtocol().String(),
			wiretrusteeConfig.GetTurns()[0].GetHostConfig().GetProtocol())
	}

	// ensure backward compatibility

	if syncResp.GetRemotePeers() == nil {
		t.Fatal("expecting SyncResponse to have non-nil RemotePeers for backward compatibility")
	}

	if syncResp.GetPeerConfig() == nil {
		t.Fatal("expecting SyncResponse to have non-nil PeerConfig for backward compatibility")
	}

	// new field - NetworkMap
	networkMap := syncResp.GetNetworkMap()
	if networkMap == nil {
		t.Fatal("expecting SyncResponse to have non-nil NetworkMap")
	}

	if len(networkMap.GetRemotePeers()) != 3 {
		t.Fatalf("expecting SyncResponse to have NetworkMap with 3 remote peers, got %d", len(networkMap.GetRemotePeers()))
	}

	// expired peers come separately.
	if len(networkMap.GetOfflinePeers()) != 1 {
		t.Fatal("expecting SyncResponse to have NetworkMap with 1 offline peer")
	}

	expiredPeerPubKey := "RlSy2vzoG2HyMBTUImXOiVhCBiiBa5qD5xzMxkiFDW4="
	if networkMap.GetOfflinePeers()[0].WgPubKey != expiredPeerPubKey {
		t.Fatalf("expecting SyncResponse to have NetworkMap with 1 offline peer with a key %s", expiredPeerPubKey)
	}

	if networkMap.GetPeerConfig() == nil {
		t.Fatal("expecting SyncResponse to have NetworkMap with a non-nil PeerConfig")
	}

	expectedIPNet := net.IPNet{IP: net.ParseIP("100.64.0.0"), Mask: net.IPMask{255, 192, 0, 0}}
	ip, _, _ := net.ParseCIDR(networkMap.GetPeerConfig().GetAddress())
	if !expectedIPNet.Contains(ip) {
		t.Fatalf("expecting SyncResponse to have NetworkMap with a PeerConfig having valid IP address %s", networkMap.GetPeerConfig().GetAddress())
	}

	if networkMap.GetSerial() <= 0 {
		t.Fatalf("expecting SyncResponse to have NetworkMap with a positive Network CurrentSerial, actual %d", networkMap.GetSerial())
	}
}

func loginPeerWithValidSetupKey(key wgtypes.Key, client mgmtProto.ManagementServiceClient) (*mgmtProto.LoginResponse, error) {
	serverKey, err := getServerKey(client)
	if err != nil {
		return nil, err
	}

	meta := &mgmtProto.PeerSystemMeta{
		Hostname:           key.PublicKey().String(),
		GoOS:               runtime.GOOS,
		OS:                 runtime.GOOS,
		Core:               "core",
		Platform:           "platform",
		Kernel:             "kernel",
		WiretrusteeVersion: "",
	}
	message, err := encryption.EncryptMessage(*serverKey, key, &mgmtProto.LoginRequest{SetupKey: TestValidSetupKey, Meta: meta})
	if err != nil {
		return nil, err
	}

	resp, err := client.Login(context.TODO(), &mgmtProto.EncryptedMessage{
		WgPubKey: key.PublicKey().String(),
		Body:     message,
	})
	if err != nil {
		return nil, err
	}

	loginResp := &mgmtProto.LoginResponse{}
	err = encryption.DecryptMessage(*serverKey, key, resp.Body, loginResp)
	if err != nil {
		return nil, err
	}

	return loginResp, nil
}

func TestServer_GetDeviceAuthorizationFlow(t *testing.T) {
	testingServerKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Errorf("unable to generate server wg key for testing GetDeviceAuthorizationFlow, error: %v", err)
	}

	testingClientKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Errorf("unable to generate client wg key for testing GetDeviceAuthorizationFlow, error: %v", err)
	}

	testCases := []struct {
		name                   string
		inputFlow              *DeviceAuthorizationFlow
		expectedFlow           *mgmtProto.DeviceAuthorizationFlow
		expectedErrFunc        require.ErrorAssertionFunc
		expectedErrMSG         string
		expectedComparisonFunc require.ComparisonAssertionFunc
		expectedComparisonMSG  string
	}{
		{
			name:            "Testing No Device Flow Config",
			inputFlow:       nil,
			expectedErrFunc: require.Error,
			expectedErrMSG:  "should return error",
		},
		{
			name: "Testing Invalid Device Flow Provider Config",
			inputFlow: &DeviceAuthorizationFlow{
				Provider: "NoNe",
				ProviderConfig: ProviderConfig{
					ClientID: "test",
				},
			},
			expectedErrFunc: require.Error,
			expectedErrMSG:  "should return error",
		},
		{
			name: "Testing Full Device Flow Config",
			inputFlow: &DeviceAuthorizationFlow{
				Provider: "hosted",
				ProviderConfig: ProviderConfig{
					ClientID: "test",
				},
			},
			expectedFlow: &mgmtProto.DeviceAuthorizationFlow{
				Provider: 0,
				ProviderConfig: &mgmtProto.ProviderConfig{
					ClientID: "test",
				},
			},
			expectedErrFunc:        require.NoError,
			expectedErrMSG:         "should not return error",
			expectedComparisonFunc: require.Equal,
			expectedComparisonMSG:  "should match",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mgmtServer := &GRPCServer{
				wgKey: testingServerKey,
				config: &Config{
					DeviceAuthorizationFlow: testCase.inputFlow,
				},
			}

			message := &mgmtProto.DeviceAuthorizationFlowRequest{}

			encryptedMSG, err := encryption.EncryptMessage(testingClientKey.PublicKey(), mgmtServer.wgKey, message)
			require.NoError(t, err, "should be able to encrypt message")

			resp, err := mgmtServer.GetDeviceAuthorizationFlow(
				context.TODO(),
				&mgmtProto.EncryptedMessage{
					WgPubKey: testingClientKey.PublicKey().String(),
					Body:     encryptedMSG,
				},
			)
			testCase.expectedErrFunc(t, err, testCase.expectedErrMSG)
			if testCase.expectedComparisonFunc != nil {
				flowInfoResp := &mgmtProto.DeviceAuthorizationFlow{}

				err = encryption.DecryptMessage(mgmtServer.wgKey.PublicKey(), testingClientKey, resp.Body, flowInfoResp)
				require.NoError(t, err, "should be able to decrypt")

				testCase.expectedComparisonFunc(t, testCase.expectedFlow.Provider, flowInfoResp.Provider, testCase.expectedComparisonMSG)
				testCase.expectedComparisonFunc(t, testCase.expectedFlow.ProviderConfig.ClientID, flowInfoResp.ProviderConfig.ClientID, testCase.expectedComparisonMSG)
			}
		})
	}
}

func startManagement(t *testing.T, config *Config) (*grpc.Server, string, error) {
	t.Helper()
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, "", err
	}
	s := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	store, cleanUp, err := NewTestStoreFromJson(config.Datadir)
	if err != nil {
		return nil, "", err
	}
	t.Cleanup(cleanUp)

	peersUpdateManager := NewPeersUpdateManager(nil)
	eventStore := &activity.InMemoryEventStore{}
	accountManager, err := BuildManager(store, peersUpdateManager, nil, "", "netbird.selfhosted",
		eventStore, nil, false, MocIntegratedValidator{})
	if err != nil {
		return nil, "", err
	}
	turnManager := NewTimeBasedAuthSecretsManager(peersUpdateManager, config.TURNConfig)

	ephemeralMgr := NewEphemeralManager(store, accountManager)
	mgmtServer, err := NewServer(config, accountManager, peersUpdateManager, turnManager, nil, ephemeralMgr)
	if err != nil {
		return nil, "", err
	}
	mgmtProto.RegisterManagementServiceServer(s, mgmtServer)

	go func() {
		if err = s.Serve(lis); err != nil {
			t.Errorf("failed to serve: %v", err)
		}
	}()

	return s, lis.Addr().String(), nil
}

func createRawClient(addr string) (mgmtProto.ManagementServiceClient, *grpc.ClientConn, error) {
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
		return nil, nil, err
	}

	return mgmtProto.NewManagementServiceClient(conn), conn, nil
}
