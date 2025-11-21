package iface

import (
	"fmt"
)

// CreateOnAndroid creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
// todo: review does this function really necessary or can we merge it with iOS
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

func (w *WGIface) RenewTun(fd int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.tun.RenewTun(fd)
}
