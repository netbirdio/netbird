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
	//WgPort      = 51000
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

//
func Test_CreateInterface(t *testing.T) {
	ifaceName := fmt.Sprintf("utun%d", WgIntNumber+1)
	wgIP := "10.99.99.1/32"
	iface, err := NewWGIface(ifaceName, wgIP, DefaultMTU)
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
	iface, err := NewWGIface(ifaceName, wgIP, DefaultMTU)
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
	iface, err := NewWGIface(ifaceName, wgIP, DefaultMTU)
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

	port, err := iface.GetListenPort()
	if err != nil {
		t.Fatal(err)
	}
	err = iface.Configure(key, *port)
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
	iface, err := NewWGIface(ifaceName, wgIP, DefaultMTU)
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
	port, err := iface.GetListenPort()
	if err != nil {
		t.Fatal(err)
	}
	err = iface.Configure(key, *port)
	if err != nil {
		dynPort, listening, devs, socks := debug(iface, *port)
		t.Fatalf("got error %v and was listening? %t, int is listening to port %d and devs %v and socks %v", err, listening, dynPort, devs, socks)
		//t.Fatal(err)
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
	peer, err := getPeer(ifaceName, peerPubKey, t)
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
	iface, err := NewWGIface(ifaceName, wgIP, DefaultMTU)
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
	port, err := iface.GetListenPort()
	if err != nil {
		t.Fatal(err)
	}
	err = iface.Configure(key, *port)
	if err != nil {
		dynPort, listening, devs, socks := debug(iface, *port)
		t.Fatalf("got error %v and was listening? %t, int is listening to port %d and devs %v and socks %v", err, listening, dynPort, devs, socks)
		//t.Fatal(err)
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
	_, err = getPeer(ifaceName, peerPubKey, t)
	if err.Error() != "peer not found" {
		t.Fatal(err)
	}
}

func Test_ConnectPeers(t *testing.T) {
	peer1ifaceName := fmt.Sprintf("utun%d", WgIntNumber+400)
	peer1wgIP := "10.99.99.17/30"
	peer1Key, _ := wgtypes.GeneratePrivateKey()
	//peer1Port := WgPort + 4

	peer2ifaceName := fmt.Sprintf("utun%d", 500)
	peer2wgIP := "10.99.99.18/30"
	peer2Key, _ := wgtypes.GeneratePrivateKey()
	//peer2Port := WgPort + 5

	keepAlive := 1 * time.Second

	iface1, err := NewWGIface(peer1ifaceName, peer1wgIP, DefaultMTU)
	if err != nil {
		t.Fatal(err)
	}
	err = iface1.Create()
	if err != nil {
		t.Fatal(err)
	}
	peer1Port, err := iface1.GetListenPort()
	if err != nil {
		t.Fatal(err)
	}
	peer1endpoint, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", *peer1Port))
	if err != nil {
		t.Fatal(err)
	}

	iface2, err := NewWGIface(peer2ifaceName, peer2wgIP, DefaultMTU)
	if err != nil {
		t.Fatal(err)
	}
	err = iface2.Create()
	if err != nil {
		t.Fatal(err)
	}
	peer2Port, err := iface2.GetListenPort()
	if err != nil {
		t.Fatal(err)
	}
	peer2endpoint, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", *peer2Port))
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

	err = iface1.Configure(peer1Key.String(), *peer1Port)
	if err != nil {
		port, listening, devs, socks := debug(iface1, *peer1Port)
		t.Fatalf("got error %v and was listening? %t, int is listening to port %d and devs %v and socks %v", err, listening, port, devs, socks)
	}
	err = iface2.Configure(peer2Key.String(), *peer2Port)
	if err != nil {
		port, listening, devs, socks := debug(iface2, *peer2Port)
		t.Fatalf("got error %v and was listening? %t, int is listening to port %d and devs %v and socks %v", err, listening, port, devs, socks)
	}

	err = iface1.UpdatePeer(peer2Key.PublicKey().String(), peer2wgIP, keepAlive, peer2endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = iface2.UpdatePeer(peer1Key.PublicKey().String(), peer1wgIP, keepAlive, peer1endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	timeout := 10 * time.Second
	timeoutChannel := time.After(timeout)
	for {
		select {
		case <-timeoutChannel:
			t.Fatalf("waiting for peer handshake timeout after %s", timeout.String())
		default:
		}
		peer, gpErr := getPeer(peer1ifaceName, peer2Key.PublicKey().String(), t)
		if gpErr != nil {
			t.Fatal(gpErr)
		}
		if !peer.LastHandshakeTime.IsZero() {
			t.Log("peers successfully handshake")
			break
		}
	}

}
func debug(iface WGIface, port int) (int, bool, []wgtypes.Device, map[string]string) {
	var listening bool
	//socks, err := netstat.UDPSocks(func(s *netstat.SockTabEntry) bool {
	//	return s.LocalAddr.Port == uint16(port)
	//})
	sockMap := make(map[string]string)
	//for _, sock := range socks {
	//	sockMap[sock.LocalAddr.String()] = sock.Process.String()
	//}
	wg, _ := wgctrl.New()
	devlist, _ := wg.Devices()
	defer wg.Close()
	var devs []wgtypes.Device
	for _, d := range devlist {
		if d.ListenPort == port {
			devs = append(devs, wgtypes.Device{
				Name:         d.Name,
				ListenPort:   d.ListenPort,
				Type:         d.Type,
				FirewallMark: d.FirewallMark,
			})
		}
	}
	l, err := net.Listen("udp", fmt.Sprintf(":%d", port))

	if err != nil {
		listening = true
	}
	if l != nil {
		defer l.Close()
	}
	lport, _ := iface.GetListenPort()
	return *lport, listening, devs, sockMap
}

func getPeer(ifaceName, peerPubKey string, t *testing.T) (wgtypes.Peer, error) {
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
