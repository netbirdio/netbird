package iface

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"testing"
	"time"
)

// keep darwin compability
const (
	key        = "0PMI6OkB5JmB+Jj/iWWHekuQRx+bipZirWCWKFXexHc="
	peerPubKey = "Ok0mC0qlJyXEPKh2UFIpsI2jG0L7LRpC3sLAusSJ5CQ="
	WgPort     = 51820
)

func init() {
	log.SetLevel(log.DebugLevel)
}

//
func Test_CreateInterface(t *testing.T) {
	ifaceName := "utun999"
	wgIP := "10.99.99.1/24"
	err := Create(ifaceName, wgIP)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = Close(WgPort)
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
func Test_ConfigureInterface(t *testing.T) {
	ifaceName := "utun1000"
	wgIP := "10.99.99.10/24"
	err := Create(ifaceName, wgIP)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = Close(WgPort)
		if err != nil {
			t.Error(err)
		}
	}()

	err = Configure(ifaceName, key, WgPort)
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
	ifaceName := "utun1001"
	wgIP := "10.99.99.20/24"
	err := Create(ifaceName, wgIP)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = Close(WgPort)
		if err != nil {
			t.Error(err)
		}
	}()
	err = Configure(ifaceName, key, WgPort)
	if err != nil {
		t.Fatal(err)
	}
	keepAlive := 15 * time.Second
	allowedIP := "10.99.99.2/32"
	endpoint := "127.0.0.1:9900"
	err = UpdatePeer(ifaceName, peerPubKey, allowedIP, keepAlive, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := getPeer(ifaceName, t)
	if err != nil {
		t.Fatal(err)
	}
	if peer.PersistentKeepaliveInterval != keepAlive {
		t.Fatal("configured peer with mismatched keepalive interval value")
	}

	resolvedEndpoint, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if peer.Endpoint.String() != resolvedEndpoint.String() {
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

func Test_UpdatePeerEndpoint(t *testing.T) {
	ifaceName := "utun1002"
	wgIP := "10.99.99.30/24"
	err := Create(ifaceName, wgIP)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = Close(WgPort)
		if err != nil {
			t.Error(err)
		}
	}()
	err = Configure(ifaceName, key, WgPort)
	if err != nil {
		t.Fatal(err)
	}
	keepAlive := 15 * time.Second
	allowedIP := "10.99.99.2/32"
	endpoint := "127.0.0.1:9900"
	err = UpdatePeer(ifaceName, peerPubKey, allowedIP, keepAlive, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	newEndpoint := "127.0.0.1:9999"
	err = UpdatePeerEndpoint(ifaceName, peerPubKey, newEndpoint)
	if err != nil {
		t.Fatal(err)
	}

	peer, err := getPeer(ifaceName, t)
	if err != nil {
		t.Fatal(err)
	}

	if peer.Endpoint.String() != newEndpoint {
		t.Fatal("configured peer with mismatched endpoint")
	}
}

func Test_RemovePeer(t *testing.T) {
	ifaceName := "utun1003"
	wgIP := "10.99.99.40/24"
	err := Create(ifaceName, wgIP)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = Close(WgPort)
		if err != nil {
			t.Error(err)
		}
	}()
	err = Configure(ifaceName, key, WgPort)
	if err != nil {
		t.Fatal(err)
	}
	keepAlive := 15 * time.Second
	allowedIP := "10.99.99.2/32"
	endpoint := "127.0.0.1:9900"
	err = UpdatePeer(ifaceName, peerPubKey, allowedIP, keepAlive, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = RemovePeer(ifaceName, peerPubKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = getPeer(ifaceName, t)
	if err.Error() != "peer not found" {
		t.Fatal(err)
	}
}
func Test_Close(t *testing.T) {
	ifaceName := "utun1004"
	wgIP := "10.99.99.50/24"
	err := Create(ifaceName, wgIP)
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

	err = Close(WgPort)
	if err != nil {
		t.Fatal(err)
	}
}
func getPeer(ifaceName string, t *testing.T) (wgtypes.Peer, error) {
	emptyPeer := wgtypes.Peer{}
	wg, err := wgctrl.New()
	if err != nil {
		return emptyPeer, err
	}
	defer func() {
		err = wg.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	wgDevice, err := wg.Device(ifaceName)
	if err != nil {
		return emptyPeer, err
	}
	for _, peer := range wgDevice.Peers {
		if peer.PublicKey.String() == peerPubKey {
			return peer, nil
		}
	}
	return emptyPeer, fmt.Errorf("peer not found")
}
