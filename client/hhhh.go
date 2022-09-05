package main

/*
import (
	"flag"
	"github.com/netbirdio/netbird/iface"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"net/http"
	_ "net/http/pprof"
	"time"
)

var name = flag.String("name", "wg0", "WireGuard interface name")
var addr = flag.String("addr", "100.64.0.1/24", "interface WireGuard IP addr")
var key = flag.String("key", "100.64.0.1/24", "WireGuard private key")
var port = flag.Int("port", 51820, "WireGuard port")

var remoteKey = flag.String("remote-key", "", "remote WireGuard public key")
var remoteAddr = flag.String("remote-addr", "100.64.0.2/32", "remote WireGuard IP addr")
var remoteEndpoint = flag.String("remote-endpoint", "127.0.0.1:51820", "remote WireGuard endpoint")

func fff() {

	flag.Parse()

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	myKey, err := wgtypes.ParseKey(*key)
	if err != nil {
		log.Error(err)
		return
	}

	log.Infof("public key and addr [%s] [%s] ", myKey.PublicKey().String(), *addr)

	wgIFace, err := iface.NewWGIFace(*name, *addr, 1280)
	if err != nil {
		log.Error(err)
		return
	}
	defer wgIFace.Close()

	// todo wrap into UDPMux
	sharedSock, _, err := listenNet("udp4", *port)
	if err != nil {
		log.Error(err)
		return
	}
	defer sharedSock.Close()

	//	err = wgIFace.Create()
	err = wgIFace.CreateNew(sharedSock)
	if err != nil {
		log.Errorf("failed to create interface %s %v", *name, err)
		return
	}

	err = wgIFace.Configure(*key, *port)
	if err != nil {
		log.Errorf("failed to configure interface %s %v", *name, err)
		return
	}

	ip, err := net.ResolveUDPAddr("udp4", *remoteEndpoint)
	if err != nil {
		// handle error
	}

	err = wgIFace.UpdatePeer(*remoteKey, *remoteAddr, 20*time.Second, ip, nil)
	if err != nil {
		log.Errorf("failed to configure remote peer %s %v", *remoteKey, err)
		return
	}

	select {}

}

func listenNet(network string, port int) (*net.UDPConn, int, error) {
	conn, err := net.ListenUDP(network, &net.UDPAddr{Port: port})
	if err != nil {
		return nil, 0, err
	}

	// Retrieve port.
	laddr := conn.LocalAddr()
	uaddr, err := net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		return nil, 0, err
	}
	return conn, uaddr.Port, nil
}*/
