//go:build !android && !darwin

package iface

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
