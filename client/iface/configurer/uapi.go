//go:build !windows && !js

package configurer

import (
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

func openUAPI(deviceName string) (net.Listener, error) {
	uapiSock, err := ipc.UAPIOpen(deviceName)
	if err != nil {
		return nil, err
	}

	listener, err := ipc.UAPIListen(deviceName, uapiSock)
	if err != nil {
		_ = uapiSock.Close()
		return nil, err
	}

	return listener, nil
}
