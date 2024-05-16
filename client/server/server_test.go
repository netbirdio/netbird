package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/netbirdio/management-integrations/integrations"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/peer"
	mgmtProto "github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/signal/proto"
	signalServer "github.com/netbirdio/netbird/signal/server"
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

// TestConnectWithRetryRuns checks that the connectWithRetry function runs and runs the retries according to the times specified via environment variables
// we will use a management server started via to simulate the server and capture the number of retries
func TestConnectWithRetryRuns(t *testing.T) {
	// start the signal server
	_, signalAddr, err := startSignal()
	if err != nil {
		t.Fatalf("failed to start signal server: %v", err)
	}

	counter := 0
	// start the management server
	_, mgmtAddr, err := startManagement(t, signalAddr, &counter)
	if err != nil {
		t.Fatalf("failed to start management server: %v", err)
	}

	ctx := internal.CtxInitState(context.Background())

	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(30*time.Second))
	defer cancel()
	// create new server
	s := New(ctx, t.TempDir()+"/config.json", "debug")
	s.latestConfigInput.ManagementURL = "http://" + mgmtAddr
	config, err := internal.UpdateOrCreateConfig(s.latestConfigInput)
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}
	s.config = config

	s.statusRecorder = peer.NewRecorder(config.ManagementURL.String())
	t.Setenv(retryInitialIntervalVar, "1s")
	t.Setenv(maxRetryIntervalVar, "2s")
	t.Setenv(maxRetryTimeVar, "5s")
	t.Setenv(retryMultiplierVar, "1")

	s.connectWithRetryRuns(ctx, config, s.statusRecorder, s.mgmProbe, s.signalProbe, s.relayProbe, s.wgProbe)
	if counter < 3 {
		t.Fatalf("expected counter > 2, got %d", counter)
	}
}

type mockServer struct {
	mgmtProto.ManagementServiceServer
	counter *int
}

func (m *mockServer) Login(ctx context.Context, req *mgmtProto.EncryptedMessage) (*mgmtProto.EncryptedMessage, error) {
	*m.counter++
	return m.ManagementServiceServer.Login(ctx, req)
}

func startManagement(t *testing.T, signalAddr string, counter *int) (*grpc.Server, string, error) {
	t.Helper()
	dataDir := t.TempDir()

	config := &server.Config{
		Stuns:      []*server.Host{},
		TURNConfig: &server.TURNConfig{},
		Signal: &server.Host{
			Proto: "http",
			URI:   signalAddr,
		},
		Datadir:    dataDir,
		HttpConfig: nil,
	}

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, "", err
	}
	s := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	store, cleanUp, err := server.NewTestStoreFromJson(config.Datadir)
	if err != nil {
		return nil, "", err
	}
	t.Cleanup(cleanUp)

	peersUpdateManager := server.NewPeersUpdateManager(nil)
	eventStore := &activity.InMemoryEventStore{}
	if err != nil {
		return nil, "", err
	}
	ia, _ := integrations.NewIntegratedValidator(eventStore)
	accountManager, err := server.BuildManager(store, peersUpdateManager, nil, "", "netbird.selfhosted", eventStore, nil, false, ia)
	if err != nil {
		return nil, "", err
	}
	turnManager := server.NewTimeBasedAuthSecretsManager(peersUpdateManager, config.TURNConfig)
	mgmtServer, err := server.NewServer(config, accountManager, peersUpdateManager, turnManager, nil, nil)
	if err != nil {
		return nil, "", err
	}
	mock := &mockServer{
		ManagementServiceServer: mgmtServer,
		counter:                 counter,
	}
	mgmtProto.RegisterManagementServiceServer(s, mock)
	go func() {
		if err = s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	return s, lis.Addr().String(), nil
}

func startSignal() (*grpc.Server, string, error) {
	s := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	proto.RegisterSignalExchangeServer(s, signalServer.NewServer())

	go func() {
		if err = s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	return s, lis.Addr().String(), nil
}
