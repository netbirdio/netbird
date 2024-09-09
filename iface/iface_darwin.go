//go:build !ios

package iface

import (
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/pion/transport/v3"

	"github.com/netbirdio/netbird/iface/bind"
	"github.com/netbirdio/netbird/iface/netstack"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(iFaceName string, address string, wgPort int, wgPrivKey string, mtu int, transportNet transport.Net, _ *MobileIFaceArguments, filterFn bind.FilterFn) (*WGIface, error) {
	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return nil, err
	}

	wgIFace := &WGIface{
		userspaceBind: true,
	}

	if netstack.IsEnabled() {
		wgIFace.tun = newTunNetstackDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, transportNet, netstack.ListenAddr(), filterFn)
		return wgIFace, nil
	}

	wgIFace.tun = newTunDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, transportNet, filterFn)

	return wgIFace, nil
}

// CreateOnAndroid this function make sense on mobile only
func (w *WGIface) CreateOnAndroid([]string, string, []string) error {
	return fmt.Errorf("this function has not implemented on this platform")
}

// Create creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
// this function is different on Android
func (w *WGIface) Create() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	backOff := &backoff.ExponentialBackOff{
		InitialInterval: 20 * time.Millisecond,
		MaxElapsedTime:  500 * time.Millisecond,
		Clock:           backoff.SystemClock,
	}

	operation := func() error {
		cfgr, err := w.tun.Create()
		if err != nil {
			return err
		}
		w.configurer = cfgr
		return nil
	}

	return backoff.Retry(operation, backOff)
}
