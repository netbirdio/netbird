//go:build (darwin && !ios) || dragonfly || freebsd || netbsd || openbsd

package systemops

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"

	nbnet "github.com/netbirdio/netbird/util/net"
)

func (r *SysOps) SetupRouting(initAddresses []net.IP) (nbnet.AddHookFunc, nbnet.RemoveHookFunc, error) {
	return r.setupRefCounter(initAddresses)
}

func (r *SysOps) CleanupRouting() error {
	return r.cleanupRefCounter()
}

func (r *SysOps) addToRouteTable(prefix netip.Prefix, nexthop Nexthop) error {
	return r.routeCmd("add", prefix, nexthop)
}

func (r *SysOps) removeFromRouteTable(prefix netip.Prefix, nexthop Nexthop) error {
	return r.routeCmd("delete", prefix, nexthop)
}

func (r *SysOps) routeCmd(action string, prefix netip.Prefix, nexthop Nexthop) error {
	inet := "-inet"
	if prefix.Addr().Is6() {
		inet = "-inet6"
	}

	network := prefix.String()
	if prefix.IsSingleIP() {
		network = prefix.Addr().String()
	}

	args := []string{"-n", action, inet, network}
	if nexthop.IP.IsValid() {
		args = append(args, nexthop.IP.Unmap().String())
	} else if nexthop.Intf != nil {
		args = append(args, "-interface", nexthop.Intf.Name)
	}

	if err := retryRouteCmd(args); err != nil {
		return fmt.Errorf("failed to %s route for %s: %w", action, prefix, err)
	}
	return nil
}

func retryRouteCmd(args []string) error {
	operation := func() error {
		out, err := exec.Command("route", args...).CombinedOutput()
		log.Tracef("route %s: %s", strings.Join(args, " "), out)
		// https://github.com/golang/go/issues/45736
		if err != nil && strings.Contains(string(out), "sysctl: cannot allocate memory") {
			return err
		} else if err != nil {
			return backoff.Permanent(err)
		}
		return nil
	}

	expBackOff := backoff.NewExponentialBackOff()
	expBackOff.InitialInterval = 50 * time.Millisecond
	expBackOff.MaxInterval = 500 * time.Millisecond
	expBackOff.MaxElapsedTime = 1 * time.Second

	err := backoff.Retry(operation, expBackOff)
	if err != nil {
		return fmt.Errorf("route cmd retry failed: %w", err)
	}
	return nil
}
