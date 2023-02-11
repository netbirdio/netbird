package iface

import (
	"os/exec"

	log "github.com/sirupsen/logrus"
)

// Create Creates a new Wireguard interface, sets a given IP and brings it up.
func (w *WGIface) Create() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.createWithUserspace()
}

// assignAddr Adds IP address to the tunnel interface and network route based on the range provided
func (w *WGIface) assignAddr() error {
	cmd := exec.Command("ifconfig", w.name, "inet", w.address.IP.String(), w.address.IP.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof(`adding addreess command "%v" failed with output %s and error: `, cmd.String(), out)
		return err
	}

	routeCmd := exec.Command("route", "add", "-net", w.address.Network.String(), "-interface", w.name)
	if out, err := routeCmd.CombinedOutput(); err != nil {
		log.Printf(`adding route command "%v" failed with output %s and error: `, routeCmd.String(), out)
		return err
	}

	return nil
}
