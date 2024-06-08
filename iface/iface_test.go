package iface

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/transport/v3/stdnet"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// keep darwin compatibility
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
	wgPort := 33100
	newNet, err := stdnet.NewNet()
	if err != nil {
		t.Fatal(err)
	}

	iface, err := NewWGIFace(ifaceName, addr, "", wgPort, key, DefaultMTU, newNet, nil)
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

	_, err = iface.Up()
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

	var found bool
	for _, a := range addrs {
		prefix, err := netip.ParsePrefix(a.String())
		assert.NoError(t, err)
		if prefix.Addr().Is4() {
			found = true
			assert.Equal(t, addr, prefix.String())
		}
	}

	if !found {
		t.Fatal("v4 address not found")
	}
}

func TestWGIface_UpdateAddr6(t *testing.T) {
	if !SupportsIPv6() {
		t.Skip("Environment does not support IPv6, skipping IPv6 test...")
	}

	ifaceName := fmt.Sprintf("utun%d", WgIntNumber+4)

	addr := "100.64.0.1/8"
	addr6 := "2001:db8:1234:abcd::42/64"
	wgPort := 33100
	newNet, err := stdnet.NewNet()
	if err != nil {
		t.Fatal(err)
	}

	iface, err := NewWGIFace(ifaceName, addr, addr6, wgPort, key, DefaultMTU, newNet, nil)
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

	_, err = iface.Up()
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

	assert.Equal(t, addr6, addrs[1].String())

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
	newNet, err := stdnet.NewNet()
	if err != nil {
		t.Fatal(err)
	}
	iface, err := NewWGIFace(ifaceName, wgIP, "", 33100, key, DefaultMTU, newNet, nil)
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

func Test_CreateInterface6(t *testing.T) {
	if !SupportsIPv6() {
		t.Skip("Environment does not support IPv6, skipping IPv6 test...")
	}

	ifaceName := fmt.Sprintf("utun%d", WgIntNumber+1)
	wgIP := "10.99.99.1/32"
	wgIP6 := "2001:db8:1234:abcd::43/64"
	newNet, err := stdnet.NewNet()
	if err != nil {
		t.Fatal(err)
	}
	iface, err := NewWGIFace(ifaceName, wgIP, wgIP6, 33100, key, DefaultMTU, newNet, nil)
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
	wgPort := 33100
	newNet, err := stdnet.NewNet()
	if err != nil {
		t.Fatal(err)
	}

	iface, err := NewWGIFace(ifaceName, wgIP, "", wgPort, key, DefaultMTU, newNet, nil)
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

func Test_Close6(t *testing.T) {
	if !SupportsIPv6() {
		t.Skip("Environment does not support IPv6, skipping IPv6 test...")
	}

	ifaceName := fmt.Sprintf("utun%d", WgIntNumber+2)
	wgIP := "10.99.99.2/32"
	wgIP6 := "2001:db8:1234:abcd::44/64"
	wgPort := 33100
	newNet, err := stdnet.NewNet()
	if err != nil {
		t.Fatal(err)
	}

	iface, err := NewWGIFace(ifaceName, wgIP, wgIP6, wgPort, key, DefaultMTU, newNet, nil)
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
	wgPort := 33100
	newNet, err := stdnet.NewNet()
	if err != nil {
		t.Fatal(err)
	}
	iface, err := NewWGIFace(ifaceName, wgIP, "", wgPort, key, DefaultMTU, newNet, nil)
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

	_, err = iface.Up()
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
	newNet, err := stdnet.NewNet()
	if err != nil {
		t.Fatal(err)
	}

	iface, err := NewWGIFace(ifaceName, wgIP, "", 33100, key, DefaultMTU, newNet, nil)
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

	_, err = iface.Up()
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
	peer, err := getPeer(ifaceName, peerPubKey)
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

func Test_UpdatePeer6(t *testing.T) {
	if !SupportsIPv6() {
		t.Skip("Environment does not support IPv6, skipping IPv6 test...")
	}

	ifaceName := fmt.Sprintf("utun%d", WgIntNumber+4)
	wgIP := "10.99.99.9/30"
	wgIP6 := "2001:db8:1234:abcd::45/64"
	newNet, err := stdnet.NewNet()
	if err != nil {
		t.Fatal(err)
	}

	iface, err := NewWGIFace(ifaceName, wgIP, wgIP6, 33100, key, DefaultMTU, newNet, nil)
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

	_, err = iface.Up()
	if err != nil {
		t.Fatal(err)
	}
	keepAlive := 15 * time.Second
	allowedIP := "10.99.99.10/32"
	allowedIP6 := "2001:db8:1234:abcd::46/128"
	endpoint, err := net.ResolveUDPAddr("udp", "127.0.0.1:9900")
	if err != nil {
		t.Fatal(err)
	}
	err = iface.UpdatePeer(peerPubKey, allowedIP+","+allowedIP6, keepAlive, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := getPeer(ifaceName, peerPubKey)
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
		if aip.String() == allowedIP6 {
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
	newNet, err := stdnet.NewNet()
	if err != nil {
		t.Fatal(err)
	}

	iface, err := NewWGIFace(ifaceName, wgIP, "", 33100, key, DefaultMTU, newNet, nil)
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

	_, err = iface.Up()
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

	_, err = getPeer(ifaceName, peerPubKey)
	if err.Error() != "peer not found" {
		t.Fatal(err)
	}
}

func Test_ConnectPeers(t *testing.T) {
	peer1ifaceName := fmt.Sprintf("utun%d", WgIntNumber+400)
	peer1wgIP := "10.99.99.17/30"
	peer1Key, _ := wgtypes.GeneratePrivateKey()
	peer1wgPort := 33100

	peer2ifaceName := "utun500"
	peer2wgIP := "10.99.99.18/30"
	peer2Key, _ := wgtypes.GeneratePrivateKey()
	peer2wgPort := 33200

	keepAlive := 1 * time.Second
	newNet, err := stdnet.NewNet()
	if err != nil {
		t.Fatal(err)
	}

	iface1, err := NewWGIFace(peer1ifaceName, peer1wgIP, "", peer1wgPort, peer1Key.String(), DefaultMTU, newNet, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = iface1.Create()
	if err != nil {
		t.Fatal(err)
	}

	_, err = iface1.Up()
	if err != nil {
		t.Fatal(err)
	}

	peer1endpoint, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", peer1wgPort))
	if err != nil {
		t.Fatal(err)
	}

	newNet, err = stdnet.NewNet()
	if err != nil {
		t.Fatal(err)
	}
	iface2, err := NewWGIFace(peer2ifaceName, peer2wgIP, "", peer2wgPort, peer2Key.String(), DefaultMTU, newNet, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = iface2.Create()
	if err != nil {
		t.Fatal(err)
	}

	_, err = iface2.Up()
	if err != nil {
		t.Fatal(err)
	}

	peer2endpoint, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", peer2wgPort))
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

		peer, gpErr := getPeer(peer1ifaceName, peer2Key.PublicKey().String())
		if gpErr != nil {
			t.Fatal(gpErr)
		}
		if !peer.LastHandshakeTime.IsZero() {
			t.Log("peers successfully handshake")
			break
		}
	}

}

func Test_ConnectPeers6(t *testing.T) {
	if !SupportsIPv6() {
		t.Skip("Environment does not support IPv6, skipping IPv6 test...")
	}

	peer1ifaceName := fmt.Sprintf("utun%d", WgIntNumber+400)
	peer1wgIP := "10.99.99.17/30"
	peer1wgIP6 := "2001:db8:1234:abcd::47/64"
	peer1Key, _ := wgtypes.GeneratePrivateKey()
	peer1wgPort := 33100

	peer2ifaceName := "utun500"
	peer2wgIP := "10.99.99.18/30"
	peer2wgIP6 := "2001:db8:1234:abcd::48/64"
	peer2Key, _ := wgtypes.GeneratePrivateKey()
	peer2wgPort := 33200

	keepAlive := 1 * time.Second
	newNet, err := stdnet.NewNet()
	if err != nil {
		t.Fatal(err)
	}

	iface1, err := NewWGIFace(peer1ifaceName, peer1wgIP, peer1wgIP6, peer1wgPort, peer1Key.String(), DefaultMTU, newNet, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = iface1.Create()
	if err != nil {
		t.Fatal(err)
	}

	_, err = iface1.Up()
	if err != nil {
		t.Fatal(err)
	}

	peer1endpoint, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", peer1wgPort))
	if err != nil {
		t.Fatal(err)
	}

	newNet, err = stdnet.NewNet()
	if err != nil {
		t.Fatal(err)
	}
	iface2, err := NewWGIFace(peer2ifaceName, peer2wgIP, peer2wgIP6, peer2wgPort, peer2Key.String(), DefaultMTU, newNet, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = iface2.Create()
	if err != nil {
		t.Fatal(err)
	}

	_, err = iface2.Up()
	if err != nil {
		t.Fatal(err)
	}

	peer2endpoint, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", peer2wgPort))
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

		peer, gpErr := getPeer(peer1ifaceName, peer2Key.PublicKey().String())
		if gpErr != nil {
			t.Fatal(gpErr)
		}
		if !peer.LastHandshakeTime.IsZero() {
			t.Log("peers successfully handshake")
			break
		}
	}

}

func getPeer(ifaceName, peerPubKey string) (wgtypes.Peer, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return wgtypes.Peer{}, err
	}
	defer func() {
		err = wg.Close()
		if err != nil {
			log.Errorf("got error while closing wgctl: %v", err)
		}
	}()

	wgDevice, err := wg.Device(ifaceName)
	if err != nil {
		return wgtypes.Peer{}, err
	}
	for _, peer := range wgDevice.Peers {
		if peer.PublicKey.String() == peerPubKey {
			return peer, nil
		}
	}
	return wgtypes.Peer{}, fmt.Errorf("peer not found")
}
