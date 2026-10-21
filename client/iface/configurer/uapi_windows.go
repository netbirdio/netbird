package configurer

import (
	"net"

	"github.com/netbirdio/wireguard-go/ipc"
)

func openUAPI(deviceName string) (net.Listener, error) {
	return ipc.UAPIListen(deviceName)
}
