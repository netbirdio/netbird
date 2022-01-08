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
	"net/http"
	_ "net/http/pprof"
	"path/filepath"
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

func TestEngine_Stress(t *testing.T) {

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	//log.SetLevel(log.DebugLevel)

	dir := t.TempDir()

	err := util.CopyFileContents("../testdata/store.json", filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalServer, err := startSignal(10000)
	if err != nil {
		t.Fatal(err)
		return
	}
	defer signalServer.Stop()

	mgmtServer, err := startManagement(33071, &server.Config{
		Stuns:      []*server.Host{},
		TURNConfig: &server.TURNConfig{},
		Signal: &server.Host{
			Proto: "http",
			URI:   "localhost:10000",
		},
		Datadir:    dir,
		HttpConfig: nil,
	})
	if err != nil {
		t.Fatal(err)
		return
	}
	defer mgmtServer.Stop()

	setupKey := "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"

	mu := sync.Mutex{}
	engines := []*Engine{}
	numPeers := 20
	wg := sync.WaitGroup{}
	wg.Add(numPeers)
	// create and start peers
	for i := 0; i < numPeers; i++ {
		j := i
		go func() {
			engine, err := createEngine(ctx, cancel, setupKey, j)
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
	for {
		time.Sleep(500 * time.Millisecond)
		totalConnected := 0
		for _, engine := range engines {
			totalConnected = totalConnected + len(engine.GetConnectedPeers())
		}
		if totalConnected == expectedConnected {
			break
		}
	}
}

func createEngine(ctx context.Context, cancel context.CancelFunc, setupKey string, i int) (*Engine, error) {

	key, err := wgtypes.GenerateKey()
	if err != nil {
		return nil, err
	}
	mgmtClient, err := mgmt.NewClient(ctx, "localhost:33071", key, false)
	if err != nil {
		return nil, err
	}
	signalClient, err := signal.NewClient(ctx, "localhost:10000", key, false)
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

	conf := &EngineConfig{
		WgIface:      fmt.Sprintf("wt%d", i),
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

func startManagement(port int, config *server.Config) (*grpc.Server, error) {

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
