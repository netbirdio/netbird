package internal

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	mgmt "github.com/wiretrustee/wiretrustee/management/client"
	mgmtProto "github.com/wiretrustee/wiretrustee/management/proto"
	"github.com/wiretrustee/wiretrustee/management/server"
	signal "github.com/wiretrustee/wiretrustee/signal/client"
	"github.com/wiretrustee/wiretrustee/signal/proto"
	signalServer "github.com/wiretrustee/wiretrustee/signal/server"
	"github.com/wiretrustee/wiretrustee/util"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
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

func TestEngine_Serial(t *testing.T) {

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// feed updates to Engine via mocked Management client
	updates := make(chan *mgmtProto.SyncResponse)
	defer close(updates)
	syncFunc := func(msgHandler func(msg *mgmtProto.SyncResponse) error) error {

		for msg := range updates {
			err := msgHandler(msg)
			if err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}

	engine := NewEngine(&signal.MockClient{}, &mgmt.MockClient{SyncFunc: syncFunc}, &EngineConfig{
		WgIfaceName:  "utun100",
		WgAddr:       "100.64.0.1/24",
		WgPrivateKey: key,
		WgPort:       33100,
	}, cancel, ctx)

	defer func() {
		err := engine.Stop()
		if err != nil {
			return
		}
	}()

	err = engine.Start()
	if err != nil {
		t.Fatal(err)
		return
	}

	peer1 := &mgmtProto.RemotePeerConfig{
		WgPubKey:   "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		AllowedIps: []string{"100.64.0.10/24"},
	}
	// 1st update with just 1 peer and serial larger than the current serial of the engine => apply update
	updates <- &mgmtProto.SyncResponse{
		NetworkMap: &mgmtProto.NetworkMap{
			Serial:             1,
			PeerConfig:         nil,
			RemotePeers:        []*mgmtProto.RemotePeerConfig{peer1},
			RemotePeersIsEmpty: false,
		},
	}

	timeout := time.After(time.Second * 2)
	for {
		select {
		case <-timeout:
			t.Fatalf("timeout while waiting for test to finish")
		default:
		}

		if len(engine.GetPeers()) == 1 && engine.networkSerial == 1 {
			break
		}
	}

	// 2nd update with just 2 peers and serial larger than the current serial of the engine => apply update
	peer2 := &mgmtProto.RemotePeerConfig{
		WgPubKey:   "LLHf3Ma6z6mdLbriAJbqhX9+nM/B71lgw2+91q3LlhU=",
		AllowedIps: []string{"100.64.0.11/24"},
	}
	updates <- &mgmtProto.SyncResponse{
		NetworkMap: &mgmtProto.NetworkMap{
			Serial:             2,
			PeerConfig:         nil,
			RemotePeers:        []*mgmtProto.RemotePeerConfig{peer1, peer2},
			RemotePeersIsEmpty: false,
		},
	}

	timeout = time.After(time.Second * 2)
	for {
		select {
		case <-timeout:
			t.Fatalf("timeout while waiting for test to finish")
		default:
		}

		if len(engine.GetPeers()) == 2 && engine.networkSerial == 2 {
			break
		}
	}

	// 3rd update with just  3 peers and serial lower than the current serial of the engine => ignore update
	peer3 := &mgmtProto.RemotePeerConfig{
		WgPubKey:   "KKHf3Ma6z6mdLbriAJbqhX9+nM/B71lgw2+91q3LlhU=",
		AllowedIps: []string{"100.64.0.12/24"},
	}
	updates <- &mgmtProto.SyncResponse{
		NetworkMap: &mgmtProto.NetworkMap{
			Serial:             1,
			PeerConfig:         nil,
			RemotePeers:        []*mgmtProto.RemotePeerConfig{peer1, peer2, peer3},
			RemotePeersIsEmpty: false,
		},
	}

	timeout = time.After(time.Second * 2)
	for {
		select {
		case <-timeout:
			t.Fatalf("timeout while waiting for test to finish")
		default:
		}

		if len(engine.GetPeers()) == 2 && engine.networkSerial == 2 {
			break
		}
	}

	// 4th update with no peers => apply update removing all peers
	// 3rd update with just  3 peers and serial lower than the current serial of the engine => ignore update
	updates <- &mgmtProto.SyncResponse{
		NetworkMap: &mgmtProto.NetworkMap{
			Serial:             4,
			RemotePeersIsEmpty: true,
		},
	}

	timeout = time.After(time.Second * 2)
	for {
		select {
		case <-timeout:
			t.Fatalf("timeout while waiting for test to finish")
		default:
		}

		if len(engine.GetPeers()) == 0 && engine.networkSerial == 4 {
			break
		}
	}

}

func TestEngine_MultiplePeers(t *testing.T) {

	//log.SetLevel(log.DebugLevel)

	dir := t.TempDir()

	err := util.CopyFileContents("../testdata/store.json", filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = os.Remove(filepath.Join(dir, "store.json")) //nolint
		if err != nil {
			t.Fatal(err)
			return
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sport := 10010
	sigServer, err := startSignal(sport)
	if err != nil {
		t.Fatal(err)
		return
	}
	defer sigServer.Stop()
	mport := 33081
	mgmtServer, err := startManagement(mport, dir)
	if err != nil {
		t.Fatal(err)
		return
	}
	defer mgmtServer.Stop()

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
			engine, err := createEngine(ctx, cancel, setupKey, j, mport, sport)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			engine.Start() //nolint
			engines = append(engines, engine)
			wg.Done()
		}()
	}

	// wait until all have been created and started
	wg.Wait()
	// check whether all the peer have expected peers connected

	expectedConnected := numPeers * (numPeers - 1)
	// adjust according to timeouts
	timeout := 50 * time.Second
	timeoutChan := time.After(timeout)
	for {
		select {
		case <-timeoutChan:
			t.Fatalf("waiting for expected connections timeout after %s", timeout.String())
			return
		default:
		}
		time.Sleep(time.Second)
		totalConnected := 0
		for _, engine := range engines {
			totalConnected = totalConnected + len(engine.GetConnectedPeers())
		}
		if totalConnected == expectedConnected {
			log.Debugf("total connected=%d", totalConnected)
			break
		}
		log.Infof("total connected=%d", totalConnected)
	}

	// cleanup test
	for _, peerEngine := range engines {
		errStop := peerEngine.Stop()
		if errStop != nil {
			log.Infoln("got error trying to close testing peers engine: ", errStop)
		}
	}
}

func createEngine(ctx context.Context, cancel context.CancelFunc, setupKey string, i int, mport int, sport int) (*Engine, error) {

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	mgmtClient, err := mgmt.NewClient(ctx, fmt.Sprintf("localhost:%d", mport), key, false)
	if err != nil {
		return nil, err
	}
	signalClient, err := signal.NewClient(ctx, fmt.Sprintf("localhost:%d", sport), key, false)
	if err != nil {
		return nil, err
	}

	publicKey, err := mgmtClient.GetServerPublicKey()
	if err != nil {
		return nil, err
	}

	resp, err := mgmtClient.Register(*publicKey, setupKey)
	if err != nil {
		return nil, err
	}

	var ifaceName string
	if runtime.GOOS == "darwin" {
		ifaceName = fmt.Sprintf("utun1%d", i)
	} else {
		ifaceName = fmt.Sprintf("wt%d", i)
	}

	conf := &EngineConfig{
		WgIfaceName:  ifaceName,
		WgAddr:       resp.PeerConfig.Address,
		WgPrivateKey: key,
		WgPort:       33100 + i,
	}

	return NewEngine(signalClient, mgmtClient, conf, cancel, ctx), nil
}

func startSignal(port int) (*grpc.Server, error) {
	s := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	proto.RegisterSignalExchangeServer(s, signalServer.NewServer())

	go func() {
		if err = s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	return s, nil
}

func startManagement(port int, dataDir string) (*grpc.Server, error) {

	config := &server.Config{
		Stuns:      []*server.Host{},
		TURNConfig: &server.TURNConfig{},
		Signal: &server.Host{
			Proto: "http",
			URI:   "localhost:10000",
		},
		Datadir:    dataDir,
		HttpConfig: nil,
	}

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return nil, err
	}
	s := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	store, err := server.NewStore(config.Datadir)
	if err != nil {
		log.Fatalf("failed creating a store: %s: %v", config.Datadir, err)
	}
	peersUpdateManager := server.NewPeersUpdateManager()
	accountManager := server.NewManager(store, peersUpdateManager)
	turnManager := server.NewTimeBasedAuthSecretsManager(peersUpdateManager, config.TURNConfig)
	mgmtServer, err := server.NewServer(config, accountManager, peersUpdateManager, turnManager)
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
