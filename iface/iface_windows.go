package iface

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/pion/transport/v3"

	"github.com/netbirdio/netbird/iface/netstack"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(iFaceName string, address string, address6 string, wgPort int, wgPrivKey string, mtu int, transportNet transport.Net, args *MobileIFaceArguments) (*WGIface, error) {
	if address6 != "" {
		log.Errorf("Attempted to configure IPv6 address %s on unsupported operating system", address6)
	}
	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return nil, err
	}

	wgIFace := &WGIface{
		userspaceBind: true,
	}

	if netstack.IsEnabled() {
		wgIFace.tun = newTunNetstackDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, transportNet, netstack.ListenAddr())
		return wgIFace, nil
	}

	wgIFace.tun = newTunDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, transportNet)
	return wgIFace, nil
}

// CreateOnAndroid this function make sense on mobile only
func (w *WGIface) CreateOnAndroid([]string, string, []string) error {
	return fmt.Errorf("this function has not implemented on non mobile")
}

// GetInterfaceGUIDString returns an interface GUID. This is useful on Windows only
func (w *WGIface) GetInterfaceGUIDString() (string, error) {
	return w.tun.(*tunDevice).getInterfaceGUIDString()
}

func SupportsIPv6() bool {
	return false
}
