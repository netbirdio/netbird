package iface

import (
	"os/exec"

	log "github.com/sirupsen/logrus"
)

func (c *tunDevice) Create() error {
	var err error
	c.netInterface, err = c.createWithUserspace()
	if err != nil {
		return err
	}

	return c.assignAddr()
}

// assignAddr Adds IP address to the tunnel interface and network route based on the range provided
func (c *tunDevice) assignAddr() error {
	cmd := exec.Command("ifconfig", c.name, "inet", c.address.IP.String(), c.address.IP.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof(`adding addreess command "%v" failed with output %s and error: `, cmd.String(), out)
		return err
	}

	routeCmd := exec.Command("route", "add", "-net", c.address.Network.String(), "-interface", c.name)
	if out, err := routeCmd.CombinedOutput(); err != nil {
		log.Printf(`adding route command "%v" failed with output %s and error: `, routeCmd.String(), out)
		return err
	}

	return nil
}
