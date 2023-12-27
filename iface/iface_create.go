//go:build !android
// +build !android

package iface

import log "github.com/sirupsen/logrus"

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
	log.Infof("using userspace bind mode: %s", w.tun.UdpMux().LocalAddr().String())

	w.configurer = cfgr
	return nil
}
