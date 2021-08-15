package internal

import (
	"context"
	"fmt"
	"github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/iface"
	mgmClient "github.com/wiretrustee/wiretrustee/management/client"
	signalClient "github.com/wiretrustee/wiretrustee/signal/client"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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

	ctx := context.Background()

	iceUrl, err := ice.ParseURL("stun:stun.wiretrustee.com:3468")
	if err != nil {
		t.Fatal(err)
	}
	var stunURLs = []*ice.URL{iceUrl}

	iFaceBlackList := make(map[string]struct{})

	signal, err := signalClient.NewClient(ctx, "signal.wiretrustee.com:10000", testKey, false)
	if err != nil {
		t.Fatal(err)
	}

	mgm, err := mgmClient.NewClient(ctx, "app.wiretrustee.com:33073", testKey, true)
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
