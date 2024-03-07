//go:build !linux
// +build !linux

package routemanager

import (
	"net/netip"
	"os/exec"
	"runtime"

	log "github.com/sirupsen/logrus"
)

func addToRouteTable(prefix netip.Prefix, addr string, devName string) error {
	// devName is ignored here, the route interface is automatically determined based on the gateway address.
	// TODO connecting via IPv6 to other peers on windows doesn't work - route configuration issue?
	cmd := exec.Command("route", "add", prefix.String(), addr)
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	log.Debugf(string(out))
	return nil
}

func removeFromRouteTable(prefix netip.Prefix, addr string, devName string) error {
	args := []string{"delete", prefix.String()}
	if runtime.GOOS == "darwin" {
		args = append(args, addr)
	}
	cmd := exec.Command("route", args...)
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	log.Debugf(string(out))
	return nil
}

func enableIPForwarding(forV6 bool) error {
	log.Infof("enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}
