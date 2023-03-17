package iface

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"testing"
	"time"
)

// keep darwin compability
const (
	WgIntNumber = 2000
)

var (
	key        string
	peerPubKey string
)

func init() {
	log.SetLevel(log.DebugLevel)
	privateKey, _ := wgtypes.GeneratePrivateKey()
	key = privateKey.String()
	peerPrivateKey, _ := wgtypes.GeneratePrivateKey()
	peerPubKey = peerPrivateKey.PublicKey().String()
}

func TestWGIface_UpdateAddr(t *testing.T) {
	ifaceName := fmt.Sprintf("utun%d", WgIntNumber+4)
	addr := "100.64.0.1/8"
	iface, err := NewWGIFace(ifaceName, addr, DefaultMTU, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = iface.Create()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = iface.Close()
		if err != nil {
			t.Error(err)
		}
	}()
	port, err := getListenPortByName(ifaceName)
	if err != nil {
		t.Fatal(err)
	}
	err = iface.Configure(key, port)
	if err != nil {
		t.Fatal(err)
	}

	addrs, err := getIfaceAddrs(ifaceName)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, addr, addrs[0].String())

	//update WireGuard address
	addr = "100.64.0.2/8"
	err = iface.UpdateAddr(addr)
	if err != nil {
		t.Fatal(err)
	}

	addrs, err = getIfaceAddrs(ifaceName)
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, addr, addrs[0].String())

}

func getIfaceAddrs(ifaceName string) ([]net.Addr, error) {
	ief, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	addrs, err := ief.Addrs()
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

func Test_CreateInterface(t *testing.T) {
	ifaceName := fmt.Sprintf("utun%d", WgIntNumber+1)
	wgIP := "10.99.99.1/32"
	iface, err := NewWGIFace(ifaceName, wgIP, DefaultMTU, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = iface.Create()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = iface.Close()
		if err != nil {
			t.Error(err)
		}
	}()
	wg, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = wg.Close()
		if err != nil {
			t.Error(err)
		}
	}()
}

func Test_Close(t *testing.T) {
	ifaceName := fmt.Sprintf("utun%d", WgIntNumber+2)
	wgIP := "10.99.99.2/32"
	iface, err := NewWGIFace(ifaceName, wgIP, DefaultMTU, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = iface.Create()
	if err != nil {
		t.Fatal(err)
	}
	wg, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = wg.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	err = iface.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func Test_ConfigureInterface(t *testing.T) {
	ifaceName := fmt.Sprintf("utun%d", WgIntNumber+3)
	wgIP := "10.99.99.5/30"
	iface, err := NewWGIFace(ifaceName, wgIP, DefaultMTU, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = iface.Create()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = iface.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	port, err := getListenPortByName(ifaceName)
	if err != nil {
		t.Fatal(err)
	}
	err = iface.Configure(key, port)
	if err != nil {
		t.Fatal(err)
	}

	wg, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = wg.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	wgDevice, err := wg.Device(ifaceName)
	if err != nil {
		t.Fatal(err)
	}
	if wgDevice.PrivateKey.String() != key {
		t.Fatalf("Private keys don't match after configure: %s != %s", key, wgDevice.PrivateKey.String())
	}
}

func Test_UpdatePeer(t *testing.T) {
	ifaceName := fmt.Sprintf("utun%d", WgIntNumber+4)
	wgIP := "10.99.99.9/30"
	iface, err := NewWGIFace(ifaceName, wgIP, DefaultMTU, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = iface.Create()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = iface.Close()
		if err != nil {
			t.Error(err)
		}
	}()
	port, err := getListenPortByName(ifaceName)
	if err != nil {
		t.Fatal(err)
	}
	err = iface.Configure(key, port)
	if err != nil {
		t.Fatal(err)
	}
	keepAlive := 15 * time.Second
	allowedIP := "10.99.99.10/32"
	endpoint, err := net.ResolveUDPAddr("udp", "127.0.0.1:9900")
	if err != nil {
		t.Fatal(err)
	}
	err = iface.UpdatePeer(peerPubKey, allowedIP, keepAlive, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := iface.configurer.getPeer(ifaceName, peerPubKey)
	if err != nil {
		t.Fatal(err)
	}
	if peer.PersistentKeepaliveInterval != keepAlive {
		t.Fatal("configured peer with mismatched keepalive interval value")
	}

	if peer.Endpoint.String() != endpoint.String() {
		t.Fatal("configured peer with mismatched endpoint")
	}

	var foundAllowedIP bool
	for _, aip := range peer.AllowedIPs {
		if aip.String() == allowedIP {
			foundAllowedIP = true
			break
		}
	}
	if !foundAllowedIP {
		t.Fatal("configured peer with mismatched Allowed IPs")
	}
}

func Test_RemovePeer(t *testing.T) {
	ifaceName := fmt.Sprintf("utun%d", WgIntNumber+4)
	wgIP := "10.99.99.13/30"
	iface, err := NewWGIFace(ifaceName, wgIP, DefaultMTU, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = iface.Create()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = iface.Close()
		if err != nil {
			t.Error(err)
		}
	}()
	port, err := getListenPortByName(ifaceName)
	if err != nil {
		t.Fatal(err)
	}
	err = iface.Configure(key, port)
	if err != nil {
		t.Fatal(err)
	}
	keepAlive := 15 * time.Second
	allowedIP := "10.99.99.14/32"

	err = iface.UpdatePeer(peerPubKey, allowedIP, keepAlive, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = iface.RemovePeer(peerPubKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = iface.configurer.getPeer(ifaceName, peerPubKey)
	if err.Error() != "peer not found" {
		t.Fatal(err)
	}
}

func Test_ConnectPeers(t *testing.T) {
	peer1ifaceName := fmt.Sprintf("utun%d", WgIntNumber+400)
	peer1wgIP := "10.99.99.17/30"
	peer1Key, _ := wgtypes.GeneratePrivateKey()

	peer2ifaceName := "utun500"
	peer2wgIP := "10.99.99.18/30"
	peer2Key, _ := wgtypes.GeneratePrivateKey()

	keepAlive := 1 * time.Second

	iface1, err := NewWGIFace(peer1ifaceName, peer1wgIP, DefaultMTU, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = iface1.Create()
	if err != nil {
		t.Fatal(err)
	}
	peer1Port, err := getListenPortByName(peer1ifaceName)
	if err != nil {
		t.Fatal(err)
	}
	peer1endpoint, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", peer1Port))
	if err != nil {
		t.Fatal(err)
	}

	iface2, err := NewWGIFace(peer2ifaceName, peer2wgIP, DefaultMTU, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = iface2.Create()
	if err != nil {
		t.Fatal(err)
	}
	peer2Port, err := getListenPortByName(peer2ifaceName)
	if err != nil {
		t.Fatal(err)
	}
	peer2endpoint, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", peer2Port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = iface1.Close()
		if err != nil {
			t.Error(err)
		}
		err = iface2.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	err = iface1.Configure(peer1Key.String(), peer1Port)
	if err != nil {
		t.Fatal(err)
	}
	err = iface2.Configure(peer2Key.String(), peer2Port)
	if err != nil {
		t.Fatal(err)
	}

	err = iface1.UpdatePeer(peer2Key.PublicKey().String(), peer2wgIP, keepAlive, peer2endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = iface2.UpdatePeer(peer1Key.PublicKey().String(), peer1wgIP, keepAlive, peer1endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	// todo: investigate why in some tests execution we need 30s
	timeout := 30 * time.Second
	timeoutChannel := time.After(timeout)
	for {
		select {
		case <-timeoutChannel:
			t.Fatalf("waiting for peer handshake timeout after %s", timeout.String())
		default:
		}
		peer, gpErr := iface1.configurer.getPeer(peer1ifaceName, peer2Key.PublicKey().String())
		if gpErr != nil {
			t.Fatal(gpErr)
		}
		if !peer.LastHandshakeTime.IsZero() {
			t.Log("peers successfully handshake")
			break
		}
	}

}

func getListenPortByName(name string) (int, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return 0, err
	}
	defer wg.Close()

	d, err := wg.Device(name)
	if err != nil {
		return 0, err
	}

	return d.ListenPort, nil
}
