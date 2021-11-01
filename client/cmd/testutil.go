package cmd

import (
	mgmtProto "github.com/wiretrustee/wiretrustee/management/proto"
	mgmt "github.com/wiretrustee/wiretrustee/management/server"
	"github.com/wiretrustee/wiretrustee/signal/peer"
	sigProto "github.com/wiretrustee/wiretrustee/signal/proto"
	sig "github.com/wiretrustee/wiretrustee/signal/server"
	"google.golang.org/grpc"
	"net"
	"testing"
)

func startSignal(t *testing.T) (*grpc.Server, net.Listener) {
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	sigProto.RegisterSignalExchangeServer(s, sig.NewServer(peer.NewRegistry()))
	go func() {
		if err := s.Serve(lis); err != nil {
			panic(err)
		}
	}()

	return s, lis
}

func startManagement(config *mgmt.Config, t *testing.T) (*grpc.Server, net.Listener) {
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	store, err := mgmt.NewStore(config.Datadir)
	if err != nil {
		t.Fatal(err)
	}

	peersUpdateManager := mgmt.NewPeersUpdateManager()
	accountManager := mgmt.NewManager(store, peersUpdateManager)
	turnManager := mgmt.NewTimeBasedAuthSecretsManager(peersUpdateManager, config.TURNConfig)
	mgmtServer, err := mgmt.NewServer(config, accountManager, peersUpdateManager, turnManager)
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
