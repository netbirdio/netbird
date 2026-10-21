//go:build !windows && !js

package configurer

import (
	"net"

	"github.com/netbirdio/netbird/client/iface/wgbackend"
)

func openUAPI(deviceName string) (net.Listener, error) {
	uapiSock, err := wgbackend.UAPIOpen(deviceName)
	if err != nil {
		return nil, err
	}

	listener, err := wgbackend.UAPIListen(deviceName, uapiSock)
	if err != nil {
		_ = uapiSock.Close()
		return nil, err
	}

	return listener, nil
}
