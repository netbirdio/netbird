package configurer

import (
	"net"

	"github.com/netbirdio/netbird/client/iface/wgbackend"
)

func openUAPI(deviceName string) (net.Listener, error) {
	return wgbackend.UAPIListen(deviceName)
}
