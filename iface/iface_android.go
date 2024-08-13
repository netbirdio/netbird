package iface

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/pion/transport/v3"
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
		tun:           newTunDevice(wgAddress, wgPort, wgPrivKey, mtu, transportNet, args.TunAdapter),
		userspaceBind: true,
	}
	return wgIFace, nil
}

// CreateOnAndroid creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
func (w *WGIface) CreateOnAndroid(routes []string, dns string, searchDomains []string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	cfgr, err := w.tun.Create(routes, dns, searchDomains)
	if err != nil {
		return err
	}
	w.configurer = cfgr
	return nil
}

// Create this function make sense on mobile only
func (w *WGIface) Create() error {
	return fmt.Errorf("this function has not implemented on this platform")
}

func SupportsIPv6() bool {
	return false
}
