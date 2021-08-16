package client

import (
	"context"
	log "github.com/sirupsen/logrus"
	mgmtProto "github.com/wiretrustee/wiretrustee/management/proto"
	mgmt "github.com/wiretrustee/wiretrustee/management/server"
	"github.com/wiretrustee/wiretrustee/util"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net"
	"path/filepath"
	"testing"
)

var tested *Client

func Test_Start(t *testing.T) {
	level, _ := log.ParseLevel("debug")
	log.SetLevel(level)

	testKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	testDir := t.TempDir()
	ctx := context.Background()
	config := &mgmt.Config{}
	_, err = util.ReadJson("../server/testdata/management.json", config)
	config.Datadir = testDir
	err = util.CopyFileContents("../server/testdata/store.json", filepath.Join(testDir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, listener := startManagement(config, t)

	tested, err = NewClient(ctx, listener.Addr().String(), testKey, false)
	if err != nil {
		t.Fatal(err)
	}
}

func startManagement(config *mgmt.Config, t *testing.T) (*grpc.Server, net.Listener) {
	lis, err := net.Listen("tcp", ":0")
	s := grpc.NewServer()
	store, err := mgmt.NewStore(config.Datadir)
	if err != nil {
		t.Fatal(err)
	}

	accountManager := mgmt.NewManager(store)
	mgmtServer, err := mgmt.NewServer(config, accountManager)
	if err != nil {
		t.Fatal(err)
	}
	mgmtProto.RegisterManagementServiceServer(s, mgmtServer)
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Fatal(err)
		}
	}()

	return s, lis
}

func TestClient_GetServerPublicKey(t *testing.T) {

	key, err := tested.GetServerPublicKey()
	if err != nil {
		t.Error(err)
	}

	if key == nil {
		t.Error("expecting non nil server key got nil")
	}
}

func TestClient_LoginUnregistered_ShouldThrow_401(t *testing.T) {
	key, err := tested.GetServerPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = tested.Login(*key)
	if err == nil {
		t.Error("expecting err on unregistered login, got nil")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.PermissionDenied {
		t.Errorf("expecting err code %d denied on on unregistered login got %d", codes.PermissionDenied, s.Code())
	}
}

func TestClient_LoginRegistered(t *testing.T) {
	key, err := tested.GetServerPublicKey()
	if err != nil {
		t.Error(err)
	}
	resp, err := tested.Register(*key, "a2c8e62b-38f5-4553-b31e-dd66c696cebb")
	if err != nil {
		t.Error(err)
	}

	if resp == nil {
		t.Error("expecting non nil response, got nil")
	}
}
