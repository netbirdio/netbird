//go:build (darwin && !ios) || dragonfly || freebsd || netbsd || openbsd

package systemops

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
	"unsafe"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/statemanager"
	nbnet "github.com/netbirdio/netbird/util/net"
)

func (r *SysOps) SetupRouting(initAddresses []net.IP, stateManager *statemanager.Manager) (nbnet.AddHookFunc, nbnet.RemoveHookFunc, error) {
	return r.setupRefCounter(initAddresses, stateManager)
}

func (r *SysOps) CleanupRouting(stateManager *statemanager.Manager) error {
	return r.cleanupRefCounter(stateManager)
}

func (r *SysOps) addToRouteTable(prefix netip.Prefix, nexthop Nexthop) error {
	return r.routeSocket("add", prefix, nexthop)
}

func (r *SysOps) removeFromRouteTable(prefix netip.Prefix, nexthop Nexthop) error {
	return r.routeSocket("delete", prefix, nexthop)
}

func (r *SysOps) routeSocket(action string, prefix netip.Prefix, nexthop Nexthop) error {
	operation := func() error {
		fd, err := unix.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
		if err != nil {
			return fmt.Errorf("open routing socket: %w", err)
		}
		defer func() {
			if closeErr := unix.Close(fd); closeErr != nil && !errors.Is(closeErr, unix.EBADF) {
				log.Warnf("failed to close routing socket: %v", closeErr)
			}
		}()

		msg, err := r.buildRouteMessage(action, prefix, nexthop)
		if err != nil {
			return fmt.Errorf("build route message: %w", err)
		}

		msgBytes, err := msg.Marshal()
		if err != nil {
			return fmt.Errorf("marshal route message: %w", err)
		}

		_, err = unix.Write(fd, msgBytes)
		if err != nil {
			// Check for common transient errors that warrant retry
			if errors.Is(err, unix.ENOBUFS) || errors.Is(err, unix.EAGAIN) {
				return err
			}
			return backoff.Permanent(fmt.Errorf("write route message: %w", err))
		}

		// Read response to check for errors
		respBuf := make([]byte, 2048)
		n, err := unix.Read(fd, respBuf)
		if err != nil && !errors.Is(err, unix.EAGAIN) {
			return backoff.Permanent(fmt.Errorf("read route response: %w", err))
		}

		if n > 0 {
			if err := r.parseRouteResponse(respBuf[:n]); err != nil {
				return backoff.Permanent(err)
			}
		}

		return nil
	}

	expBackOff := backoff.NewExponentialBackOff()
	expBackOff.InitialInterval = 50 * time.Millisecond
	expBackOff.MaxInterval = 500 * time.Millisecond
	expBackOff.MaxElapsedTime = 1 * time.Second

	err := backoff.Retry(operation, expBackOff)
	if err != nil {
		return fmt.Errorf("failed to %s route for %s: %w", action, prefix, err)
	}
	return nil
}

func (r *SysOps) buildRouteMessage(action string, prefix netip.Prefix, nexthop Nexthop) (*route.RouteMessage, error) {
	var rtmType int
	switch action {
	case "add":
		rtmType = unix.RTM_ADD
	case "delete":
		rtmType = unix.RTM_DELETE
	default:
		return nil, fmt.Errorf("unsupported route action: %s", action)
	}

	msg := &route.RouteMessage{
		Type:    rtmType,
		Flags:   unix.RTF_UP,
		Version: unix.RTM_VERSION,
		Seq:     1,
	}

	// Set destination
	if prefix.IsSingleIP() {
		msg.Flags |= unix.RTF_HOST
		if prefix.Addr().Is4() {
			msg.Addrs = append(msg.Addrs, &route.Inet4Addr{IP: prefix.Addr().As4()})
		} else {
			msg.Addrs = append(msg.Addrs, &route.Inet6Addr{IP: prefix.Addr().As16()})
		}
	} else {
		// Network route - need destination and netmask
		if prefix.Addr().Is4() {
			msg.Addrs = append(msg.Addrs, &route.Inet4Addr{IP: prefix.Addr().As4()})
			// Calculate netmask for IPv4
			mask := net.CIDRMask(prefix.Bits(), 32)
			var maskAddr [4]byte
			copy(maskAddr[:], mask)
			msg.Addrs = append(msg.Addrs, &route.Inet4Addr{IP: maskAddr})
		} else {
			msg.Addrs = append(msg.Addrs, &route.Inet6Addr{IP: prefix.Addr().As16()})
			// Calculate netmask for IPv6
			mask := net.CIDRMask(prefix.Bits(), 128)
			var maskAddr [16]byte
			copy(maskAddr[:], mask)
			msg.Addrs = append(msg.Addrs, &route.Inet6Addr{IP: maskAddr})
		}
	}

	// Set gateway/interface
	if nexthop.IP.IsValid() {
		msg.Flags |= unix.RTF_GATEWAY
		if nexthop.IP.Is4() {
			msg.Addrs = append(msg.Addrs, &route.Inet4Addr{IP: nexthop.IP.Unmap().As4()})
		} else {
			msg.Addrs = append(msg.Addrs, &route.Inet6Addr{IP: nexthop.IP.As16()})
		}
	} else if nexthop.Intf != nil {
		// Interface route
		msg.Index = nexthop.Intf.Index
	}

	return msg, nil
}

func (r *SysOps) parseRouteResponse(buf []byte) error {
	if len(buf) < int(unsafe.Sizeof(unix.RtMsghdr{})) {
		return nil // No error to report for short messages
	}

	rtMsg := (*unix.RtMsghdr)(unsafe.Pointer(&buf[0]))
	if rtMsg.Errno != 0 {
		return fmt.Errorf("route operation failed with errno %d", rtMsg.Errno)
	}

	return nil
}
