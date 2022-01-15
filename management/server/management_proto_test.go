package server

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/encryption"
	mgmtProto "github.com/wiretrustee/wiretrustee/management/proto"
	"github.com/wiretrustee/wiretrustee/util"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"
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

	var peers = []*wgtypes.Key{}
	for i := 0; i < peersNum; i++ {
		key, err := wgtypes.GenerateKey()
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
	err := util.CopyFileContents("testdata/store.json", filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}

	mgmtServer, err := startManagement(33071, &Config{
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
	defer mgmtServer.Stop()

	client, clientConn, err := createRawClient("localhost:33071")
	if err != nil {
		t.Fatal(err)
		return
	}

	defer clientConn.Close()

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

	// take the first registered peer as a base for the test
	key := *peers[0]

	message, err := encryption.EncryptMessage(*serverKey, key, &mgmtProto.SyncRequest{})
	if err != nil {
		t.Fatal(err)
		return
	}

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

	/*networkMap := syncResp.GetNetworkMap()
	if networkMap == nil {
		t.Fatal("expecting SyncResponse to have non-nil NetworkMap")
	}

	if len(networkMap.GetRemotePeers()) != 1 {
		t.Fatal("expecting SyncResponse to have NetworkMap with 1 remote peer")
	}

	if networkMap.GetPeerConfig() == nil {
		t.Fatal("expecting SyncResponse to have NetworkMap with a non-nil PeerConfig")
	}

	if networkMap.GetPeerConfig().GetAddress() != "100.64.0.1/24" {
		t.Fatal("expecting SyncResponse to have NetworkMap with a PeerConfig having valid Address")
	}*/

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

func startManagement(port int, config *Config) (*grpc.Server, error) {

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return nil, err
	}
	s := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	store, err := NewStore(config.Datadir)
	if err != nil {
		return nil, err
	}
	peersUpdateManager := NewPeersUpdateManager()
	accountManager := NewManager(store, peersUpdateManager)
	turnManager := NewTimeBasedAuthSecretsManager(peersUpdateManager, config.TURNConfig)
	mgmtServer, err := NewServer(config, accountManager, peersUpdateManager, turnManager)
	if err != nil {
		return nil, err
	}
	mgmtProto.RegisterManagementServiceServer(s, mgmtServer)
	go func() {
		if err = s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	return s, nil
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
