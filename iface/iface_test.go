package iface

import (
	"fmt"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"testing"
	"time"
)

// keep darwin compability
const (
	ifaceName  = "utun99"
	key        = "0PMI6OkB5JmB+Jj/iWWHekuQRx+bipZirWCWKFXexHc="
	pubKey     = "+qso2I3q952FOPTka+97S1F40qjGlrpAqW1cf3w64W8="
	peerPubKey = "Ok0mC0qlJyXEPKh2UFIpsI2jG0L7LRpC3sLAusSJ5CQ="
)

func Test_CreateInterface(t *testing.T) {
	wgIP := "10.99.99.1/24"
	err := Create(ifaceName, wgIP)
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

func Test_ConfigureInterface(t *testing.T) {
	err := Configure(ifaceName, key)
	if err != nil {
		t.Fatal(err)
	}

	wg, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()

	wgDevice, err := wg.Device(ifaceName)
	if err != nil {
		t.Fatal(err)
	}
	if wgDevice.PrivateKey.String() != key {
		t.Fatal("Private keys don't match after configure")
	}
}

func Test_UpdatePeer(t *testing.T) {
	keepAlive := 15 * time.Second
	allowedIP := "10.99.99.2/32"
	endpoint := "127.0.0.1:9900"
	err := UpdatePeer(ifaceName, peerPubKey, allowedIP, keepAlive, endpoint)
	if err != nil {
		t.Fatal(err)
	}

	peer, err := getPeer()
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
	newEndpoint := "127.0.0.1:9999"
	err := UpdatePeerEndpoint(ifaceName, peerPubKey, newEndpoint)
	if err != nil {
		t.Fatal(err)
	}

	peer, err := getPeer()
	if err != nil {
		t.Fatal(err)
	}

	if peer.Endpoint.String() != newEndpoint {
		t.Fatal("configured peer with mismatched endpoint")
	}
}

func Test_RemovePeer(t *testing.T) {
	err := RemovePeer(ifaceName, peerPubKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = getPeer()
	if err.Error() != "peer not found" {
		t.Fatal(err)
	}
}

func getPeer() (wgtypes.Peer, error) {
	emptyPeer := wgtypes.Peer{}
	wg, err := wgctrl.New()
	if err != nil {
		return emptyPeer, err
	}
	defer wg.Close()

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
