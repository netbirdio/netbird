//go:build darwin || windows
// +build darwin windows

package routemanager

import (
	log "github.com/sirupsen/logrus"
	"net/netip"
	"os/exec"
	"runtime"
)

func addToRouteTable(prefix netip.Prefix, addr string) error {
	cmd := exec.Command("route", "add", prefix.String(), addr)
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	log.Debugf(string(out))
	return nil
}

func removeFromRouteTable(prefix netip.Prefix) error {
	cmd := exec.Command("route", "delete", prefix.String())
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	log.Debugf(string(out))
	return nil
}

func enableIPForwarding() error {
	log.Debugf("enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}
