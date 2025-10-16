//go:build !windows && !js

package configurer

import (
	"net"

	"github.com/amnezia-vpn/amneziawg-go/ipc"
	log "github.com/sirupsen/logrus"
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
