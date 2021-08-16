package internal

import (
	"context"
	"fmt"
	"github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/iface"
	mgmClient "github.com/wiretrustee/wiretrustee/management/client"
	mgmtProto "github.com/wiretrustee/wiretrustee/management/proto"
	mgmt "github.com/wiretrustee/wiretrustee/management/server"
	signalClient "github.com/wiretrustee/wiretrustee/signal/client"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"net"
	"testing"
	"time"
)

var engine *Engine
var testKey wgtypes.Key
var testPeer Peer

const ifaceName = "utun9991"

func Test_Start(t *testing.T) {
	level, _ := log.ParseLevel("Debug")
	log.SetLevel(level)

	var err error
	testKey, err = wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	iceUrl, err := ice.ParseURL("stun:stun.wiretrustee.com:3468")
	if err != nil {
		t.Fatal(err)
	}
	var stunURLs = []*ice.URL{iceUrl}

	iFaceBlackList := make(map[string]struct{})

	listener := startManagement(t)

	signal, err := signalClient.NewClient(ctx, "signal.wiretrustee.com:10000", testKey, false)
	if err != nil {
		t.Fatal(err)
	}

	mgm, err := mgmClient.NewClient(ctx, listener.Addr().String(), testKey, false)
	if err != nil {
		t.Fatal(err)
	}
	conf := &EngineConfig{
		StunsTurns:     stunURLs,
		WgIface:        ifaceName,
		WgAddr:         "10.99.91.1/24",
		WgPrivateKey:   testKey,
		IFaceBlackList: iFaceBlackList,
	}

	engine = NewEngine(signal, mgm, conf)
	err = engine.Start()

	if err != nil {
		t.Fatal(err)
	}
	wg, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()

	_, err = wg.Device(ifaceName)
	if err != nil {
		t.Fatal(err)
	}
}

func startManagement(t *testing.T) net.Listener {
	testDir := t.TempDir()
	config := &mgmt.Config{
		Stuns:      []*mgmt.Host{},
		Turns:      []*mgmt.Host{},
		Signal:     &mgmt.Host{},
		Datadir:    testDir,
		HttpConfig: nil,
	}
	config.Datadir = testDir

	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	store, err := mgmt.NewStore(config.Datadir)
	if err != nil {
		t.Fatal(err)
	}
	setupKeys := map[string]*mgmt.SetupKey{}
	setupKeys["a2c8e62b-38f5-4553-b31e-dd66c696cebb"] = &mgmt.SetupKey{Key: "a2c8e62b-38f5-4553-b31e-dd66c696cebb"}
	err = store.SaveAccount(&mgmt.Account{
		Id:        "bf1c8084-ba50-4ce7-9439-34653001fc3b",
		SetupKeys: setupKeys,
		Network: &mgmt.Network{
			Id:  "bf1c8084-ba50-fdfd-9439-34653001fc3b",
			Net: net.IPNet{IP: net.ParseIP("100.64.0.1"), Mask: net.IPMask{255, 255, 0, 0}},
			Dns: "",
		},
		Peers: make(map[string]*mgmt.Peer),
	})

	if err != nil {
		return nil
	}

	accountManager := mgmt.NewManager(store)
	mgmtServer, err := mgmt.NewServer(config, accountManager)
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

	return lis
}

func TestEngine_InitializePeerWithoutRemote(t *testing.T) {
	tmpKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	testPeer = Peer{
		tmpKey.PublicKey().String(),
		"10.99.91.2/32",
	}
	go engine.initializePeer(testPeer)
	// Let the connections initialize
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		status := engine.GetPeerConnectionStatus(testPeer.WgPubKey)
		err = ctx.Err()
		if (status != nil && *status == StatusConnecting) || err != nil {
			if err != nil {
				t.Fatal(err)
			}
			//success
			break
		}
	}
}

func TestEngine_Initialize2PeersWithoutRemote(t *testing.T) {
	tmpKey1, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tmpKey2, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	testPeer1 := Peer{
		tmpKey1.PublicKey().String(),
		"10.99.91.2/32",
	}
	testPeer2 := Peer{
		tmpKey2.PublicKey().String(),
		"10.99.91.3/32",
	}
	go engine.initializePeer(testPeer1)
	go engine.initializePeer(testPeer2)
	// Let the connections initialize
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		status1 := engine.GetPeerConnectionStatus(testPeer1.WgPubKey)
		status2 := engine.GetPeerConnectionStatus(testPeer2.WgPubKey)
		err = ctx.Err()
		if (status1 != nil && status2 != nil) || err != nil {
			if err != nil {
				t.Fatal(err)
			}
			if *status1 == StatusConnecting && *status2 == StatusConnecting {
				//success
				break
			}
		}
	}
}

func TestEngine_RemovePeerConnectionWithoutRemote(t *testing.T) {

	// Let the connections initialize
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		status := engine.GetPeerConnectionStatus(testPeer.WgPubKey)
		err := ctx.Err()
		if (status != nil && *status == StatusConnecting) || err != nil {
			if err != nil {
				t.Fatal(err)
			}
			break
		}
	}

	// Let the connections close
	err := engine.removePeerConnection(testPeer.WgPubKey)
	if err != nil {
		t.Fatal(err)
	}

	status := engine.GetPeerConnectionStatus(testPeer.WgPubKey)
	if status != nil {
		t.Fatal(fmt.Errorf("wrong status %v", status))
	}
}

func Test_CloseInterface(t *testing.T) {
	err := iface.Close()
	if err != nil {
		t.Fatal(err)
	}
}
