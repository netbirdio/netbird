package iface

import "fmt"

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
	w.batcher = NewWGBatcher(cfgr)
	return nil
}

// Create this function make sense on mobile only
func (w *WGIface) Create() error {
	return fmt.Errorf("this function has not implemented on this platform")
}
