//go:build !windows

package iface

import (
	"net"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/ipc"
)

func openUAPI(deviceName string) (net.Listener, error) {
	uapiSock, err := ipc.UAPIOpen(deviceName)
	if err != nil {
		log.Errorf("failed to open uapi socket: %v", err)
		return nil, err
	}

	listener, err := ipc.UAPIListen(deviceName, uapiSock)
	if err != nil {
		log.Errorf("failed to listen on uapi socket: %v", err)
		return nil, err
	}

	return listener, nil
}
