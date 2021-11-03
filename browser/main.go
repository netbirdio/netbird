package main

import (
	"context"
	"github.com/wiretrustee/wiretrustee/signal/client"
	"github.com/wiretrustee/wiretrustee/signal/proto"
	"time"

	/*	"context"
		"github.com/wiretrustee/wiretrustee/signal/client"
		"github.com/wiretrustee/wiretrustee/signal/proto"*/
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"log"
	"syscall/js"
	/*	"time"*/)

func main() {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	connectToSignal := func(key wgtypes.Key, remoteKey wgtypes.Key) {
		signalClient, err := client.NewWebsocketClient(ctx, "ws://localhost:80/signal", key)
		if err != nil {
			return
		}

		log.Printf("connected to signal")

		go func() {
			signalClient.Receive(func(msg *proto.Message) error {
				log.Printf("received a message from %v -> %v", msg.RemoteKey, msg.Body.Payload)
				return nil
			})
		}()

		time.Sleep(5 * time.Second)

		log.Printf("sending msg to signal")

		err = signalClient.Send(&proto.Message{
			Key:       key.PublicKey().String(),
			RemoteKey: remoteKey.String(),
			Body: &proto.Body{
				Type:    0,
				Payload: "hello",
			},
		})
		if err != nil {
			return
		}
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

	/*tun, tnet, err := netstack.CreateNetTUN(
		[]net.IP{net.ParseIP("10.100.0.2")},
		[]net.IP{net.ParseIP("8.8.8.8")},
		1420)
	if err != nil {
		log.Panic(err)
	}
	log.Println("1")
	clientKey,_ := wgtypes.ParseKey("WI+uoQD9jGi+nyifmFwmswQu5r0uWFH31WeSmfU0snI=")
	serverKey,_ := wgtypes.ParseKey("kLpbgt+g2+g8x556VmsLYyhTh77WmKfaFB0x+LcVyWY=")
	publicServerkey := serverKey.PublicKey()
	log.Println("2")*/

	/*/*stunURL, err := ice.ParseURL("stun:stun.wiretrustee.com:5555")
	if err != nil {
		log.Panic(err)
	}

	agent, err := ice.NewAgent(&ice.AgentConfig{
		NetworkTypes:   []ice.NetworkType{ice.NetworkTypeUDP4},
		Urls:           []*ice.URL{stunURL},
		CandidateTypes: []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive, ice.CandidateTypeRelay},
	})
	if err != nil {
		log.Panic(err)
	}*/

	/*sig, err := signal.NewClient(context.Background(), "localhost:10000", clientKey, false)
	if err != nil {
		log.Printf("%v", err)
		return
	}

	sig.Receive(func(msg *proto.Message) error {
		log.Printf("%v", msg)
		return nil
	})

	sig.WaitConnected()
	log.Println("3")
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))

	err = dev.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\npersistent_keepalive_interval=5\nendpoint=65.108.52.126:50000\nallowed_ip=0.0.0.0/0",
		hex.EncodeToString(clientKey[:]),
		hex.EncodeToString(publicServerkey[:]),
	))
	log.Println("4")

	if err != nil {
		log.Panic(err)
	}
	err = dev.Up()
	if err != nil {
		log.Panic(err)
	}

	client := http.Client{
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
	}
	resp, err := client.Get("https://www.zx2c4.com/ip")
	if err != nil {
		log.Panic(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Panic(err)
	}
	log.Println(string(body))
	time.Sleep(30 * time.Second)*/
}
