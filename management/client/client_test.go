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
	"time"
)

var tested *Client
var serverAddr string

const ValidKey = "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"

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
	if err != nil {
		t.Fatal(err)
	}
	config.Datadir = testDir
	err = util.CopyFileContents("../server/testdata/store.json", filepath.Join(testDir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, listener := startManagement(config, t)
	serverAddr = listener.Addr().String()
	tested, err = NewClient(ctx, serverAddr, testKey, false)
	if err != nil {
		t.Fatal(err)
	}
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
	accountManager := mgmt.NewManager(store, peersUpdateManager, nil)
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
	resp, err := tested.Register(*key, ValidKey)
	if err != nil {
		t.Error(err)
	}

	if resp == nil {
		t.Error("expecting non nil response, got nil")
	}
}

func TestClient_Sync(t *testing.T) {
	serverKey, err := tested.GetServerPublicKey()
	if err != nil {
		t.Error(err)
	}

	_, err = tested.Register(*serverKey, ValidKey)
	if err != nil {
		t.Error(err)
	}

	// create and register second peer (we should receive on Sync request)
	remoteKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Error(err)
	}
	remoteClient, err := NewClient(context.TODO(), serverAddr, remoteKey, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = remoteClient.Register(*serverKey, ValidKey)
	if err != nil {
		t.Fatal(err)
	}

	ch := make(chan *mgmtProto.SyncResponse, 1)

	go func() {
		err = tested.Sync(func(msg *mgmtProto.SyncResponse) error {
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
