package iface

import (
	log "github.com/sirupsen/logrus"
	"net"
	"os/exec"
	"strings"
)

// Create Creates a new Wireguard interface, sets a given IP and brings it up.
func Create(iface string, address string) error {
	return CreateWithUserspace(iface, address)
}

// assignAddr Adds IP address to the tunnel interface and network route based on the range provided
func assignAddr(address string, ifaceName string) error {
	ip := strings.Split(address, "/")
	cmd := exec.Command("ifconfig", ifaceName, "inet", address, ip[0])
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("Command: %v failed with output %s and error: ", cmd.String(), out)
		return err
	}
	_, resolvedNet, err := net.ParseCIDR(address)
	err = addRoute(ifaceName, resolvedNet)
	if err != nil {
		log.Infoln("Adding route failed with error:", err)
	}
	return nil
}

// addRoute Adds network route based on the range provided
func addRoute(iface string, ipNet *net.IPNet) error {
	cmd := exec.Command("route", "add", "-net", ipNet.String(), "-interface", iface)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Command: %v failed with output %s and error: ", cmd.String(), out)
		return err
	}
	return nil
}
