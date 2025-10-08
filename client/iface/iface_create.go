//go:build (!android && !darwin) || ios

package iface

import "fmt"

// Create creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
// this function is different on Android
func (w *WGIface) Create() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	cfgr, err := w.tun.Create()
	if err != nil {
		return err
	}

	w.configurer = cfgr
	return nil
}

// CreateOnAndroid this function make sense on mobile only
func (w *WGIface) CreateOnAndroid([]string, string, []string) error {
	return fmt.Errorf("this function has not implemented on non mobile")
}

func (w *WGIface) RenewTun(fd int) error {
	return fmt.Errorf("this function has not been implemented on non-android")
}
