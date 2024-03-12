//go:build !android
// +build !android

package iface

import (
	"fmt"
	"github.com/netbirdio/netbird/iface/netstack"
	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/nettest"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(iFaceName string, address string, address6 string, wgPort int, wgPrivKey string, mtu int, transportNet transport.Net, args *MobileIFaceArguments) (*WGIface, error) {
	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return nil, err
	}

	wgIFace := &WGIface{}

	if netstack.IsEnabled() || !WireGuardModuleIsLoaded() && address6 != "" {
		log.Errorf("Attempted to configure IPv6 address %s on unsupported device implementation (netstack or tun).", address6)
	}

	// move the kernel/usp/netstack preference evaluation to upper layer
	if netstack.IsEnabled() {
		wgIFace.tun = newTunNetstackDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, transportNet, netstack.ListenAddr())
		wgIFace.userspaceBind = true
		return wgIFace, nil
	}

	if WireGuardModuleIsLoaded() {

		var wgAddress6 *WGAddress = nil
		if address6 != "" {
			tmpWgAddress6, err := parseWGAddress(address6)
			wgAddress6 = &tmpWgAddress6
			if err != nil {
				return wgIFace, err
			}
		}
		wgIFace.tun = newTunDevice(iFaceName, wgAddress, wgAddress6, wgPort, wgPrivKey, mtu, transportNet)
		wgIFace.userspaceBind = false
		return wgIFace, nil
	}

	if !tunModuleIsLoaded() {
		return nil, fmt.Errorf("couldn't check or load tun module")
	}
	wgIFace.tun = newTunUSPDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, transportNet)
	wgIFace.userspaceBind = true
	return wgIFace, nil
}

// CreateOnAndroid this function make sense on mobile only
func (w *WGIface) CreateOnAndroid([]string, string, []string) error {
	return fmt.Errorf("this function has not implemented on this platform")
}

func SupportsIPv6() bool {
	return nettest.SupportsIPv6() && WireGuardModuleIsLoaded() && !netstack.IsEnabled()
}
