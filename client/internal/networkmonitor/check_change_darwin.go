//go:build darwin && !ios

package networkmonitor

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

// todo: refactor to not use static functions

func checkChange(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
	fd, err := unix.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("open routing socket: %v", err)
	}

	defer func() {
		err := unix.Close(fd)
		if err != nil && !errors.Is(err, unix.EBADF) {
			log.Warnf("Network monitor: failed to close routing socket: %v", err)
		}
	}()

	routeChanged := make(chan struct{})
	go func() {
		routeCheck(ctx, fd, nexthopv4, nexthopv6)
		close(routeChanged)
	}()

	wakeUp := make(chan struct{})
	go func() {
		wakeUpListen(ctx)
		close(wakeUp)
	}()

	gatewayChanged := make(chan string)
	go func() {
		gatewayPoll(ctx, nexthopv4, nexthopv6, gatewayChanged)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-routeChanged:
		log.Infof("route change detected via routing socket")
		return nil
	case <-wakeUp:
		log.Infof("wakeup detected via sleep hash change")
		return nil
	case reason := <-gatewayChanged:
		log.Infof("gateway change detected via polling: %s", reason)
		return nil
	}
}

func routeCheck(ctx context.Context, fd int, nexthopv4 systemops.Nexthop, nexthopv6 systemops.Nexthop) {
	for {
		if ctx.Err() != nil {
			return
		}

		buf := make([]byte, 2048)
		n, err := unix.Read(fd, buf)
		if err != nil {
			if !errors.Is(err, unix.EBADF) && !errors.Is(err, unix.EINVAL) {
				log.Warnf("Network monitor: failed to read from routing socket: %v", err)
			}
			continue
		}
		if n < unix.SizeofRtMsghdr {
			log.Debugf("Network monitor: read from routing socket returned less than expected: %d bytes", n)
			continue
		}

		msg := (*unix.RtMsghdr)(unsafe.Pointer(&buf[0]))

		switch msg.Type {
		// handle route changes
		case unix.RTM_ADD, syscall.RTM_DELETE:
			route, err := parseRouteMessage(buf[:n])
			if err != nil {
				log.Debugf("Network monitor: error parsing routing message: %v", err)
				continue
			}

			if route.Dst.Bits() != 0 {
				continue
			}

			intf := "<nil>"
			if route.Interface != nil {
				intf = route.Interface.Name
			}
			switch msg.Type {
			case unix.RTM_ADD:
				log.Infof("Network monitor: default route changed: via %s, interface %s", route.Gw, intf)
				return
			case unix.RTM_DELETE:
				if nexthopv4.Intf != nil && route.Gw.Compare(nexthopv4.IP) == 0 || nexthopv6.Intf != nil && route.Gw.Compare(nexthopv6.IP) == 0 {
					log.Infof("Network monitor: default route removed: via %s, interface %s", route.Gw, intf)
					return
				}
			}
		}
	}
}

func parseRouteMessage(buf []byte) (*systemops.Route, error) {
	msgs, err := route.ParseRIB(route.RIBTypeRoute, buf)
	if err != nil {
		return nil, fmt.Errorf("parse RIB: %v", err)
	}

	if len(msgs) != 1 {
		return nil, fmt.Errorf("unexpected RIB message msgs: %v", msgs)
	}

	msg, ok := msgs[0].(*route.RouteMessage)
	if !ok {
		return nil, fmt.Errorf("unexpected RIB message type: %T", msgs[0])
	}

	return systemops.MsgToRoute(msg)
}

func wakeUpListen(ctx context.Context) {
	log.Infof("start to watch for system wakeups")
	var (
		initialHash uint32
		err         error
	)

	// Keep retrying until initial sysctl succeeds or context is canceled
	for {
		select {
		case <-ctx.Done():
			log.Info("exit from wakeUpListen initial hash detection due to context cancellation")
			return
		default:
			initialHash, err = readSleepTimeHash()
			if err != nil {
				log.Errorf("failed to detect initial sleep time: %v", err)
				select {
				case <-ctx.Done():
					log.Info("exit from wakeUpListen initial hash detection due to context cancellation")
					return
				case <-time.After(3 * time.Second):
					continue
				}
			}
			log.Infof("initial wakeup hash: %d", initialHash)
			break
		}
		break
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	lastCheck := time.Now()
	const maxTickerDrift = 1 * time.Minute

	for {
		select {
		case <-ctx.Done():
			log.Info("context canceled, stopping wakeUpListen")
			return

		case <-ticker.C:
			now := time.Now()
			elapsed := now.Sub(lastCheck)

			// If more time passed than expected, system likely slept (informational only)
			if elapsed > maxTickerDrift {
				upOut, err := exec.Command("uptime").Output()
				if err != nil {
					log.Errorf("failed to run uptime command: %v", err)
					upOut = []byte("unknown")
				}
				log.Infof("Time drift detected (potential wakeup): expected ~5s, actual %s, uptime: %s", elapsed, upOut)

				currentV4, errV4 := systemops.GetNextHop(netip.IPv4Unspecified())
				currentV6, errV6 := systemops.GetNextHop(netip.IPv6Unspecified())
				if errV4 == nil {
					log.Infof("Current IPv4 default gateway: %s via %s", currentV4.IP, currentV4.Intf.Name)
				} else {
					log.Debugf("No IPv4 default gateway: %v", errV4)
				}
				if errV6 == nil {
					log.Infof("Current IPv6 default gateway: %s via %s", currentV6.IP, currentV6.Intf.Name)
				} else {
					log.Debugf("No IPv6 default gateway: %v", errV6)
				}
			}

			newHash, err := readSleepTimeHash()
			if err != nil {
				log.Errorf("failed to read sleep time hash: %v", err)
				lastCheck = now
				continue
			}

			if newHash == initialHash {
				log.Debugf("no wakeup detected (hash unchanged: %d, time drift: %s)", initialHash, elapsed)
				lastCheck = now
				continue
			}

			upOut, err := exec.Command("uptime").Output()
			if err != nil {
				log.Errorf("failed to run uptime command: %v", err)
				upOut = []byte("unknown")
			}
			log.Infof("Wakeup detected via hash change: %d -> %d, uptime: %s", initialHash, newHash, upOut)

			currentV4, errV4 := systemops.GetNextHop(netip.IPv4Unspecified())
			currentV6, errV6 := systemops.GetNextHop(netip.IPv6Unspecified())
			if errV4 == nil {
				log.Infof("Current IPv4 default gateway after wakeup: %s via %s", currentV4.IP, currentV4.Intf.Name)
			} else {
				log.Debugf("No IPv4 default gateway after wakeup: %v", errV4)
			}
			if errV6 == nil {
				log.Infof("Current IPv6 default gateway after wakeup: %s via %s", currentV6.IP, currentV6.Intf.Name)
			} else {
				log.Debugf("No IPv6 default gateway after wakeup: %v", errV6)
			}

			return
		}
	}
}

func readSleepTimeHash() (uint32, error) {
	cmd := exec.Command("sysctl", "kern.sleeptime")
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to run sysctl: %w", err)
	}

	h, err := hash(out)
	if err != nil {
		return 0, fmt.Errorf("failed to compute hash: %w", err)
	}

	return h, nil
}

func hash(data []byte) (uint32, error) {
	hasher := fnv.New32a()
	if _, err := hasher.Write(data); err != nil {
		return 0, err
	}
	return hasher.Sum32(), nil
}

// gatewayPoll polls the default gateway every 5 seconds to detect changes that might be missed by routing socket or wake-up detection.
func gatewayPoll(ctx context.Context, initialV4, initialV6 systemops.Nexthop, changed chan<- string) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	log.Infof("Gateway polling started - initial v4: %s via %v, v6: %s via %v",
		initialV4.IP, initialV4.Intf, initialV6.IP, initialV6.Intf)

	for {
		select {
		case <-ctx.Done():
			log.Debug("context canceled, stopping gateway polling")
			return

		case <-ticker.C:
			currentV4, errV4 := systemops.GetNextHop(netip.IPv4Unspecified())
			currentV6, errV6 := systemops.GetNextHop(netip.IPv6Unspecified())

			var reason string

			if errV4 == nil && initialV4.IP.IsValid() {
				if currentV4.IP.Compare(initialV4.IP) != 0 {
					reason = fmt.Sprintf("IPv4 gateway changed from %s to %s", initialV4.IP, currentV4.IP)
					log.Infof("Gateway poll detected change: %s", reason)
					changed <- reason
					return
				}
				if initialV4.Intf != nil && currentV4.Intf != nil && currentV4.Intf.Name != initialV4.Intf.Name {
					reason = fmt.Sprintf("IPv4 interface changed from %s to %s", initialV4.Intf.Name, currentV4.Intf.Name)
					log.Infof("Gateway poll detected change: %s", reason)
					changed <- reason
					return
				}
			} else if errV4 == nil && !initialV4.IP.IsValid() {
				reason = "IPv4 gateway appeared"
				log.Infof("Gateway poll detected change: %s (new: %s)", reason, currentV4.IP)
				changed <- reason
				return
			} else if errV4 != nil && initialV4.IP.IsValid() {
				reason = "IPv4 gateway disappeared"
				log.Infof("Gateway poll detected change: %s", reason)
				changed <- reason
				return
			}

			if errV6 == nil && initialV6.IP.IsValid() {
				if currentV6.IP.Compare(initialV6.IP) != 0 {
					reason = fmt.Sprintf("IPv6 gateway changed from %s to %s", initialV6.IP, currentV6.IP)
					log.Infof("Gateway poll detected change: %s", reason)
					changed <- reason
					return
				}
				if initialV6.Intf != nil && currentV6.Intf != nil && currentV6.Intf.Name != initialV6.Intf.Name {
					reason = fmt.Sprintf("IPv6 interface changed from %s to %s", initialV6.Intf.Name, currentV6.Intf.Name)
					log.Infof("Gateway poll detected change: %s", reason)
					changed <- reason
					return
				}
			} else if errV6 == nil && !initialV6.IP.IsValid() {
				reason = "IPv6 gateway appeared"
				log.Infof("Gateway poll detected change: %s (new: %s)", reason, currentV6.IP)
				changed <- reason
				return
			} else if errV6 != nil && initialV6.IP.IsValid() {
				reason = "IPv6 gateway disappeared"
				log.Infof("Gateway poll detected change: %s", reason)
				changed <- reason
				return
			}

			log.Debugf("Gateway poll: no change detected")
		}
	}
}
