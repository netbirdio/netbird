package configurer

import (
	"net"

	"github.com/amnezia-vpn/amneziawg-go/ipc"
)

func openUAPI(deviceName string) (net.Listener, error) {
	return ipc.UAPIListen(deviceName)
}
