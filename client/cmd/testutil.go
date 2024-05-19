package cmd

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/server/activity"

	"github.com/netbirdio/netbird/util"

	"google.golang.org/grpc"

	"github.com/netbirdio/management-integrations/integrations"

	clientProto "github.com/netbirdio/netbird/client/proto"
	client "github.com/netbirdio/netbird/client/server"
	mgmtProto "github.com/netbirdio/netbird/management/proto"
	mgmt "github.com/netbirdio/netbird/management/server"
	sigProto "github.com/netbirdio/netbird/signal/proto"
	sig "github.com/netbirdio/netbird/signal/server"
)

func startTestingServices(t *testing.T) string {
	t.Helper()
	config := &mgmt.Config{}
	_, err := util.ReadJson("../testdata/management.json", config)
	if err != nil {
		t.Fatal(err)
	}
	testDir := t.TempDir()
	config.Datadir = testDir
	err = util.CopyFileContents("../testdata/store.json", filepath.Join(testDir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}

	_, signalLis := startSignal(t)
	signalAddr := signalLis.Addr().String()
	config.Signal.URI = signalAddr

	_, mgmLis := startManagement(t, config)
	mgmAddr := mgmLis.Addr().String()
	return mgmAddr
}

func startSignal(t *testing.T) (*grpc.Server, net.Listener) {
	t.Helper()
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	sigProto.RegisterSignalExchangeServer(s, sig.NewServer())
	go func() {
		if err := s.Serve(lis); err != nil {
			panic(err)
		}
	}()

	return s, lis
}

func startManagement(t *testing.T, config *mgmt.Config) (*grpc.Server, net.Listener) {
	t.Helper()
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
	if err != nil {
		return nil, nil
	}
	iv, _ := integrations.NewIntegratedValidator(eventStore)
	accountManager, err := mgmt.BuildManager(store, peersUpdateManager, nil, "", "netbird.selfhosted", eventStore, nil, false, iv)
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
		}
	}()

	return s, lis
}

func startClientDaemon(
	t *testing.T, ctx context.Context, managementURL, configPath string,
) (*grpc.Server, net.Listener) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()

	server := client.New(ctx,
		configPath, "")
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	clientProto.RegisterDaemonServiceServer(s, server)
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Error(err)
		}
	}()

	time.Sleep(time.Second)

	return s, lis
}
