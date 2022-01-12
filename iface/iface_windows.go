package iface

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc"
	"time"

	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"net"
)

var (
	WintunTunnelType          = "WireGuard"
	luid                      winipcfg.LUID
	adapter                   *driver.Adapter
	err                       error
	WintunStaticRequestedGUID windows.GUID
)

// Create Creates a new Wireguard interface, sets a given IP and brings it up.
func Create(iface string, address string) error {

	WintunStaticRequestedGUID, _ = windows.GenerateGUID()
	adapter, err = driver.CreateAdapter(iface, WintunTunnelType, &WintunStaticRequestedGUID)
	if err != nil {
		err = fmt.Errorf("error creating adapter: %w", err)
		return err
	}
	luid = adapter.LUID()
	err = adapter.SetLogging(driver.AdapterLogOn)
	if err != nil {
		err = fmt.Errorf("Error enabling adapter logging: %w", err)
		return err
	}
	err = adapter.SetAdapterState(driver.AdapterStateUp)
	if err != nil {
		return err
	}
	state, _ := luid.GUID()
	log.Debugln("device guid: ", state.String())
	time.Sleep(3 * time.Second)
	return assignAddr(address, iface)
}

// assignAddr Adds IP address to the tunnel interface and network route based on the range provided
func assignAddr(address string, ifaceName string) error {

	ip, ipnet, _ := net.ParseCIDR(address)

	log.Debugf("adding address %s to interface: %s", address, ifaceName)
	err := luid.SetIPAddresses([]net.IPNet{{ip, ipnet.Mask}})
	if err != nil {
		return err
	}
	//
	//log.Debugf("adding Routes to interface: %s", ifaceName)
	//err = luid.SetRoutes([]*winipcfg.RouteData{{*ipnet, ipnet.IP, 0}})
	//if err != nil {
	//	return err
	//}
	return nil
}

// getUAPI returns a Listener
func getUAPI(iface string) (net.Listener, error) {
	return ipc.UAPIListen(iface)
}

// Closes the tunnel interface
func Close(iFace string) error {
	return adapter.Close()
}
