package main

import (
	"bytes"
	"context"
	"encoding/hex"
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

	key, err := wgtypes.ParseKey("qJi7zSrgdokeoXE27fbca2hvMlgg1NQIW6KbrTJhhmc=")
	if err != nil {
		panic(err)
	}

	log.Printf("my public key: %s", key.PublicKey().String())

	remoteKey, err := wgtypes.ParseKey("RFuT84MDhIvmgQndwMkxQPjG195poq713EMJZv1XPEw=")

	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	signal, err := client.NewWebsocketClient(ctx, "ws://localhost:80/signal", key)

	time.Sleep(5 * time.Second)

	tun, tnet, err := netstack.CreateNetTUN(
		[]net.IP{net.ParseIP("1s00.0.2.2")},
		[]net.IP{net.ParseIP("8.8.8.8")},
		1420)

	b := conn.NewWebRTCBind("chann-1", signal, key.PublicKey().String(), remoteKey.String())
	dev := device.NewDevice(tun, b, device.NewLogger(device.LogLevelVerbose, ""))

	err = dev.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\npersistent_keepalive_interval=5\nendpoint=webrtc://datachannel\nallowed_ip=0.0.0.0/0",
		hex.EncodeToString(key[:]),
		hex.EncodeToString(remoteKey[:]),
	))

	dev.Up()

	if err != nil {
		panic(err)
	}

	client := http.Client{
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
	}
	time.Sleep(5 * time.Second)

	//go func() {
	log.Printf("request")
	req, _ := http.NewRequest("POST", "http://100.0.2.1", bytes.NewBufferString("fdffffffffffffffffffffffffffffffdsdfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
	req.Header.Set("js.fetch:mode", "no-cors")
	resp, err := client.Do(req)
	if err != nil {
		log.Panic(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Panic(err)
	}
	log.Printf(string(body))
	log.Printf(resp.Status)
	//}()

	select {}

}
