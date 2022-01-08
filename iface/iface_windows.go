package iface

import (
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"net"
)

// Create Creates a new Wireguard interface, sets a given IP and brings it up.
func Create(iface string, address string) error {
	return CreateWithUserspace(iface, address)
}

// assignAddr Adds IP address to the tunnel interface and network route based on the range provided
func assignAddr(address string, ifaceName string) error {

	nativeTunDevice := tunIface.(*tun.NativeTun)
	luid := winipcfg.LUID(nativeTunDevice.LUID())

	ip, ipnet, _ := net.ParseCIDR(address)

	log.Debugf("adding address %s to interface: %s", address, ifaceName)
	err := luid.SetIPAddresses([]net.IPNet{{ip, ipnet.Mask}})
	if err != nil {
		return err
	}

	log.Debugf("adding Routes to interface: %s", ifaceName)
	err = luid.SetRoutes([]*winipcfg.RouteData{{*ipnet, ipnet.IP, 0}})
	if err != nil {
		return err
	}
	return nil
}

// getUAPI returns a Listener
func getUAPI(iface string) (net.Listener, error) {
	return ipc.UAPIListen(iface)
}

// Closes the tunnel interface
func Close(port int) error {
	return CloseWithUserspace()
}
