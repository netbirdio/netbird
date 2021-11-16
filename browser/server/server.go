package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/wiretrustee/wiretrustee/browser/conn"
	"github.com/wiretrustee/wiretrustee/signal/client"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

//my private key qJi7zSrgdokeoXE27fbca2hvMlgg1NQIW6KbrTJhhmc=
//remote private key KLuBc6tM/NRV1071bfPiNUxZmMhGBCXfxoDg+A+J7ns=
func main() {

	keyFlag := flag.String("key", "", "a Wireguard private key")
	remoteKeyFlag := flag.String("remote-key", "", "a Wireguard remote peer public key")
	signalEndpoint := flag.String("signal-endpoint", "ws://apitest.wiretrustee.com:80/signal", "a Signal service Websocket endpoint")

	flag.Parse()

	key, err := wgtypes.ParseKey(*keyFlag)
	if err != nil {
		panic(err)
	}

	log.Printf("my public key: %s", key.PublicKey().String())

	remoteKey, err := wgtypes.ParseKey(*remoteKeyFlag)

	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	time.Sleep(5 * time.Second)

	signal, err := client.NewWebsocketClient(ctx, *signalEndpoint, key)

	tun, tnet, err := netstack.CreateNetTUN(
		[]net.IP{net.ParseIP("10.100.0.2")},
		[]net.IP{net.ParseIP("8.8.8.8")},
		1420)

	b := conn.NewWebRTCBind("chann-1", signal, key.PublicKey().String(), remoteKey.String())
	dev := device.NewDevice(tun, b, device.NewLogger(device.LogLevelVerbose, ""))
	err = dev.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\npersistent_keepalive_interval=10\nendpoint=webrtc://datachannel\nallowed_ip=0.0.0.0/0",
		hex.EncodeToString(key[:]),
		hex.EncodeToString(remoteKey[:]),
	))

	dev.Up()

	if err != nil {
		panic(err)
	}

	listener, err := tnet.ListenTCP(&net.TCPAddr{Port: 80})
	if err != nil {
		log.Panicln(err)
	}
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		log.Printf("> %s - %s - %s", request.RemoteAddr, request.URL.String(), request.UserAgent())
		io.WriteString(writer, "Hello from userspace TCP!")
	})
	err = http.Serve(listener, nil)
	if err != nil {
		log.Panicln(err)
	}

	select {}

}
