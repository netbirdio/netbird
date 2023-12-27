package iface

import (
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

func openUAPI(deviceName string) (net.Listener, error) {
	return ipc.UAPIListen(deviceName)
}
