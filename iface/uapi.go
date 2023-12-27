//go:build !windows

package iface

import (
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

func openUAPI(deviceName string) (net.Listener, error) {
	uapiSock, err := ipc.UAPIOpen(deviceName)
	if err != nil {
		log.Errorf("failed to open uapi socket: %v", err)
		return nil
	}

	return ipc.UAPIListen(deviceName, uapiSock)
}
