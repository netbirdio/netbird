package main

import (
	"encoding/hex"
	"fmt"
	conn2 "golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
)

func main() {
	tun, _, err := netstack.CreateNetTUN(
		[]net.IP{net.ParseIP("10.100.0.2")},
		[]net.IP{net.ParseIP("8.8.8.8")},
		1420)

	if err != nil {
		return
	}

	clientKey, _ := wgtypes.ParseKey("WI+uoQD9jGi+nyifmFwmswQu5r0uWFH31WeSmfU0snI=")
	serverKey, _ := wgtypes.ParseKey("kLpbgt+g2+g8x556VmsLYyhTh77WmKfaFB0x+LcVyWY=")
	publicServerkey := serverKey.PublicKey()

	dev := device.NewDevice(tun, conn2.NewStdNetBind(), device.NewLogger(device.LogLevelVerbose, ""))

	err = dev.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\npersistent_keepalive_interval=5\nendpoint=65.108.52.126:50000\nallowed_ip=0.0.0.0/0",
		hex.EncodeToString(clientKey[:]),
		hex.EncodeToString(publicServerkey[:]),
	))

	if err != nil {
		return
	}

	select {}
}
