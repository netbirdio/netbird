package iface

import (
	log "github.com/sirupsen/logrus"
	"net"

	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/elevate"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// assignAddr Adds IP address to the tunnel interface and network route based on the range provided
func assignAddr(address string, tunDevice tun.Device) error {
	ifaceName, err := tunDevice.Name()
	nativeTunDevice := tunDevice.(*tun.NativeTun)
	luid := winipcfg.LUID(nativeTunDevice.LUID())

	ip, ipnet, _ := net.ParseCIDR(address)

	log.Debugf("adding address %s to interface: %s", address, ifaceName)
	err = luid.SetIPAddresses([]net.IPNet{{ip, ipnet.Mask}})
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

// createIface creates a tun device
func createIface(iface string, defaultMTU int) (tun.Device, error) {

	var tunDevice tun.Device
	err := elevate.DoAsSystem(func() error {
		var err error
		tunDevice, err = tun.CreateTUNWithRequestedGUID(iface, &windows.GUID{12, 12, 12, [8]byte{12, 12, 12, 12, 12, 12, 12, 12}}, defaultMTU)
		return err
	})
	if err != nil {
		log.Errorln("Failed to create the tunnel device: ", err)
		return nil, err
	}
	return tunDevice, err
}

// getUAPI returns a Listener
func getUAPI(iface string) (net.Listener, error) {
	return ipc.UAPIListen(iface)
}
