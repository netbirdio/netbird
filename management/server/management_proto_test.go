package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/formatter"
	mgmtProto "github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/util"
)

type TestingT interface {
	require.TestingT
	Helper()
	Cleanup(func())
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
	mgmtServer, _, mgmtAddr, err := startManagementForTest(t, &Config{
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

	syncReq := &mgmtProto.SyncRequest{Meta: &mgmtProto.PeerSystemMeta{}}
	message, err := encryption.EncryptMessage(*serverKey, key, syncReq)
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

func startManagementForTest(t TestingT, config *Config) (*grpc.Server, *DefaultAccountManager, string, error) {
	t.Helper()
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, nil, "", err
	}
	s := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	store, cleanUp, err := NewTestStoreFromJson(context.Background(), config.Datadir)
	if err != nil {
		return nil, nil, "", err
	}
	t.Cleanup(cleanUp)

	peersUpdateManager := NewPeersUpdateManager(nil)
	eventStore := &activity.InMemoryEventStore{}

	ctx := context.WithValue(context.Background(), formatter.ExecutionContextKey, formatter.SystemSource) //nolint:staticcheck

	metrics, err := telemetry.NewDefaultAppMetrics(context.Background())
	require.NoError(t, err)

	accountManager, err := BuildManager(ctx, store, peersUpdateManager, nil, "", "netbird.selfhosted",
		eventStore, nil, false, MocIntegratedValidator{}, metrics)

	if err != nil {
		return nil, nil, "", err
	}

	secretsManager := NewTimeBasedAuthSecretsManager(peersUpdateManager, config.TURNConfig, config.Relay)

	ephemeralMgr := NewEphemeralManager(store, accountManager)
	mgmtServer, err := NewServer(context.Background(), config, accountManager, peersUpdateManager, secretsManager, nil, ephemeralMgr)
	if err != nil {
		return nil, nil, "", err
	}
	mgmtProto.RegisterManagementServiceServer(s, mgmtServer)

	go func() {
		if err = s.Serve(lis); err != nil {
			t.Errorf("failed to serve: %v", err)
		}
	}()

	return s, accountManager, lis.Addr().String(), nil
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
func Test_SyncStatusRace(t *testing.T) {
	if os.Getenv("CI") == "true" && os.Getenv("NETBIRD_STORE_ENGINE") == "postgres" {
		t.Skip("Skipping on CI and Postgres store")
	}
	for i := 0; i < 500; i++ {
		t.Run(fmt.Sprintf("TestRun-%d", i), func(t *testing.T) {
			testSyncStatusRace(t)
		})
	}
}
func testSyncStatusRace(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	err := util.CopyFileContents("testdata/store_with_expired_peers.json", filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.Remove(filepath.Join(dir, "store.json")) //nolint
	}()

	mgmtServer, am, mgmtAddr, err := startManagementForTest(t, &Config{
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

	concurrentPeerKey2 := peers[1]
	t.Log("Public key of concurrent peer: ", concurrentPeerKey2.PublicKey().String())

	syncReq2 := &mgmtProto.SyncRequest{Meta: &mgmtProto.PeerSystemMeta{}}
	message2, err := encryption.EncryptMessage(*serverKey, *concurrentPeerKey2, syncReq2)
	if err != nil {
		t.Fatal(err)
		return
	}

	ctx2, cancelFunc2 := context.WithCancel(context.Background())

	sync2, err := client.Sync(ctx2, &mgmtProto.EncryptedMessage{
		WgPubKey: concurrentPeerKey2.PublicKey().String(),
		Body:     message2,
	})
	if err != nil {
		t.Fatal(err)
		return
	}

	resp2 := &mgmtProto.EncryptedMessage{}
	err = sync2.RecvMsg(resp2)
	if err != nil {
		t.Fatal(err)
		return
	}

	peerWithInvalidStatus := peers[0]
	t.Log("Public key of peer with invalid status: ", peerWithInvalidStatus.PublicKey().String())

	syncReq := &mgmtProto.SyncRequest{Meta: &mgmtProto.PeerSystemMeta{}}
	message, err := encryption.EncryptMessage(*serverKey, *peerWithInvalidStatus, syncReq)
	if err != nil {
		t.Fatal(err)
		return
	}

	ctx, cancelFunc := context.WithCancel(context.Background())

	// client.
	sync, err := client.Sync(ctx, &mgmtProto.EncryptedMessage{
		WgPubKey: peerWithInvalidStatus.PublicKey().String(),
		Body:     message,
	})
	if err != nil {
		t.Fatal(err)
		return
	}

	// take the first registered peer as a base for the test. Total four.

	resp := &mgmtProto.EncryptedMessage{}
	err = sync.RecvMsg(resp)
	if err != nil {
		t.Fatal(err)
		return
	}

	cancelFunc2()
	time.Sleep(1 * time.Millisecond)
	cancelFunc()
	time.Sleep(10 * time.Millisecond)

	ctx, cancelFunc = context.WithCancel(context.Background())
	defer cancelFunc()
	sync, err = client.Sync(ctx, &mgmtProto.EncryptedMessage{
		WgPubKey: peerWithInvalidStatus.PublicKey().String(),
		Body:     message,
	})
	if err != nil {
		t.Fatal(err)
		return
	}

	resp = &mgmtProto.EncryptedMessage{}
	err = sync.RecvMsg(resp)
	if err != nil {
		t.Fatal(err)
		return
	}

	time.Sleep(10 * time.Millisecond)
	peer, err := am.Store.GetPeerByPeerPubKey(context.Background(), LockingStrengthShare, peerWithInvalidStatus.PublicKey().String())
	if err != nil {
		t.Fatal(err)
		return
	}
	if !peer.Status.Connected {
		t.Fatal("Peer should be connected")
	}
}

func Test_LoginPerformance(t *testing.T) {
	if os.Getenv("CI") == "true" || runtime.GOOS == "windows" {
		t.Skip("Skipping test on CI or Windows")
	}

	t.Setenv("NETBIRD_STORE_ENGINE", "sqlite")

	benchCases := []struct {
		name     string
		peers    int
		accounts int
	}{
		// {"XXS", 5, 1},
		// {"XS", 10, 1},
		// {"S", 100, 1},
		// {"M", 250, 1},
		// {"L", 500, 1},
		// {"XL", 750, 1},
		{"XXL", 5000, 1},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for _, bc := range benchCases {
		t.Run(bc.name, func(t *testing.T) {
			t.Helper()
			dir := t.TempDir()
			err := util.CopyFileContents("testdata/store_with_expired_peers.json", filepath.Join(dir, "store.json"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				os.Remove(filepath.Join(dir, "store.json")) //nolint
			}()

			mgmtServer, am, _, err := startManagementForTest(t, &Config{
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

			t.Logf("management setup complete, start registering peers")

			var counter int32
			var counterStart int32
			var wgAccount sync.WaitGroup
			var mu sync.Mutex
			messageCalls := []func() error{}
			for j := 0; j < bc.accounts; j++ {
				wgAccount.Add(1)
				var wgPeer sync.WaitGroup
				go func(j int, counter *int32, counterStart *int32) {
					defer wgAccount.Done()

					account, err := createAccount(am, fmt.Sprintf("account-%d", j), fmt.Sprintf("user-%d", j), fmt.Sprintf("domain-%d", j))
					if err != nil {
						t.Logf("account creation failed: %v", err)
						return
					}

					setupKey, err := am.CreateSetupKey(context.Background(), account.Id, fmt.Sprintf("key-%d", j), SetupKeyReusable, time.Hour, nil, 0, fmt.Sprintf("user-%d", j), false)
					if err != nil {
						t.Logf("error creating setup key: %v", err)
						return
					}

					startTime := time.Now()
					for i := 0; i < bc.peers; i++ {
						wgPeer.Add(1)
						key, err := wgtypes.GeneratePrivateKey()
						if err != nil {
							t.Logf("failed to generate key: %v", err)
							return
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

						peerLogin := PeerLogin{
							WireGuardPubKey: key.String(),
							SSHKey:          "random",
							Meta:            extractPeerMeta(context.Background(), meta),
							SetupKey:        setupKey.Key,
							ConnectionIP:    net.IP{1, 1, 1, 1},
						}

						login := func() error {
							_, _, _, err = am.LoginPeer(context.Background(), peerLogin)
							if err != nil {
								t.Logf("failed to login peer: %v", err)
								return err
							}
							atomic.AddInt32(counter, 1)
							if *counter%100 == 0 {
								t.Logf("finished %d login calls", *counter)
							}
							return nil
						}

						mu.Lock()
						messageCalls = append(messageCalls, login)
						mu.Unlock()

						go func(peerLogin PeerLogin, counterStart *int32) {
							defer wgPeer.Done()
							_, _, _, err = am.LoginPeer(context.Background(), peerLogin)
							if err != nil {
								t.Logf("failed to login peer: %v", err)
								return
							}

							atomic.AddInt32(counterStart, 1)
							if *counterStart%100 == 0 {
								t.Logf("registered %d peers", *counterStart)
							}
						}(peerLogin, counterStart)

					}
					wgPeer.Wait()

					t.Logf("Time for registration: %s", time.Since(startTime))
				}(j, &counter, &counterStart)
			}

			wgAccount.Wait()

			t.Logf("prepared %d login calls", len(messageCalls))
			testLoginPerformance(t, messageCalls)

		})
	}
}

func testLoginPerformance(t *testing.T, loginCalls []func() error) {
	t.Helper()
	wgSetup := sync.WaitGroup{}
	startChan := make(chan struct{})

	wgDone := sync.WaitGroup{}
	durations := []time.Duration{}
	l := sync.Mutex{}

	for i, function := range loginCalls {
		wgSetup.Add(1)
		wgDone.Add(1)
		go func(function func() error, i int) {
			defer wgDone.Done()
			wgSetup.Done()

			<-startChan
			start := time.Now()

			err := function()
			if err != nil {
				t.Logf("Error: %v", err)
				return
			}

			duration := time.Since(start)
			l.Lock()
			durations = append(durations, duration)
			l.Unlock()
		}(function, i)
	}

	wgSetup.Wait()
	t.Logf("starting login calls")
	close(startChan)
	wgDone.Wait()
	var tMin, tMax, tSum time.Duration
	for i, d := range durations {
		if i == 0 {
			tMin = d
			tMax = d
			tSum = d
			continue
		}
		if d < tMin {
			tMin = d
		}
		if d > tMax {
			tMax = d
		}
		tSum += d
	}
	tAvg := tSum / time.Duration(len(durations))
	t.Logf("Min: %v, Max: %v, Avg: %v", tMin, tMax, tAvg)
}
