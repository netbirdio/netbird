package main

import (
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
	"syscall/js"
	"time"
)

func handleError(err error) {
	fmt.Printf("Unexpected error. Check console.")
	panic(err)
}

func getElementByID(id string) js.Value {
	return js.Global().Get("document").Call("getElementById", id)
}

func main() {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	connectToSignal := func(key wgtypes.Key, remoteKey wgtypes.Key) {
		signalClient, err := client.NewWebsocketClient(ctx, "ws://apitest.wiretrustee.com:80/signal", key)
		if err != nil {
			return
		}

		time.Sleep(5 * time.Second)

		tun, tnet, err := netstack.CreateNetTUN(
			[]net.IP{net.ParseIP("10.100.0.2")},
			[]net.IP{net.ParseIP("8.8.8.8")},
			1420)

		b := conn.NewWebRTCBind("chann-1", signalClient, key.PublicKey().String(), remoteKey.String())
		dev := device.NewDevice(tun, b, device.NewLogger(device.LogLevelVerbose, ""))

		err = dev.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\npersistent_keepalive_interval=10\nendpoint=webrtc://datachannel\nallowed_ip=0.0.0.0/0",
			hex.EncodeToString(key[:]),
			hex.EncodeToString(remoteKey[:]),
		))
		log.Println("4")

		if err != nil {
			log.Panic(err)
		}
		err = dev.Up()
		if err != nil {
			log.Panic(err)
		}

		log.Printf("device started")

		client := http.Client{
			Transport: &http.Transport{
				DialContext: tnet.DialContext,
			},
		}
		req, _ := http.NewRequest("GET", "http://apitest.wiretrustee.com:9090/", nil)
		req.Header.Set("js.fetch:mode", "no-cors")
		resp, err := client.Do(req)
		if err != nil {
			log.Panic(err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Panic(err)
		}
		log.Println(string(body))

		select {}
	}

	js.Global().Set("generateWireguardKey", js.FuncOf(func(this js.Value, args []js.Value) interface{} {

		key, err := wgtypes.GenerateKey()
		if err != nil {
			return nil
		}

		js.Global().Get("document").Call("getElementById", "wgPrivateKey").Set("value", key.String())

		log.Printf("Wireguard Public key %s", key.PublicKey().String())
		js.Global().Get("document").Call("getElementById", "publicKey").Set("value", key.PublicKey().String())

		return nil
	}))

	js.Global().Set("connect", js.FuncOf(func(this js.Value, args []js.Value) interface{} {

		wgPrivateKey := js.Global().Get("document").Call("getElementById", "wgPrivateKey").Get("value").String()
		key, err := wgtypes.ParseKey(wgPrivateKey)
		if err != nil {
			return err
		}

		remotePublicKey := js.Global().Get("document").Call("getElementById", "peerKey").Get("value").String()
		remoteKey, err := wgtypes.ParseKey(remotePublicKey)
		if err != nil {
			return err
		}

		log.Printf("Remote Wireguard Public key %s", remoteKey.String())
		log.Printf("Our Wireguard Public key %s", key.PublicKey().String())
		go connectToSignal(key, remoteKey)
		return nil
	}))

	select {}
}
