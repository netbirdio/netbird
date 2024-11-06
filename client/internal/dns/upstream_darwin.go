package dns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func makeRouteMessageQuery(ipStr string) (*route.RouteMessage, error) {
	ipAddr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse addr: %s", err)
	}
	if !ipAddr.Is4() {
		return nil, fmt.Errorf("not an ipv4 address: %#v", ipAddr)
	}

	return &route.RouteMessage{
		Type:  unix.RTM_GET,
		Flags: syscall.RTF_UP | syscall.RTF_GATEWAY | syscall.RTF_STATIC, // route that is up, and was manually added
		ID:    uintptr(os.Getpid()),
		Seq:   1,
		Addrs: []route.Addr{
			&route.Inet4Addr{IP: ipAddr.As4()},
			nil, // Gateway (not specified)
			nil, // Netmask (not specified)
			nil, // Genmask (not specified)
		},
	}, nil
}

func getRouteMessageResponse(rtmQuery *route.RouteMessage) (*route.RouteMessage, error) {
	msgBytes, err := rtmQuery.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshaling RouteMessage: %s", err)
	}

	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC) // unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open routing socket: %v", err)
	}
	defer func() {
		err := unix.Close(fd)
		if err != nil && !errors.Is(err, unix.EBADF) {
			log.Errorf("failed to close routing socket: %v", err)
		}
	}()

	// Send the message over the routing socket
	_, err = unix.Write(fd, msgBytes)
	if err != nil {
		return nil, fmt.Errorf("writing to AF_ROUTE socket: %s", err)
	}

	var buf [2 << 10]byte
	n, err := unix.Read(fd, buf[:])
	if err != nil {
		return nil, fmt.Errorf("reading from AF_ROUTE socket: %s", err)
	}

	if int(buf[3]) != unix.RTM_GET {
		return nil, fmt.Errorf("expected GET msg got: %#v", buf[3])
	}

	// Parse the response messages
	msgs, err := route.ParseRIB(route.RIBTypeRoute, buf[:n])
	if err != nil {
		return nil, fmt.Errorf("parsing RIB: %s", err)
	}

	rtmResponse, ok := msgs[0].(*route.RouteMessage)
	if !ok {
		return nil, fmt.Errorf("route message is invalid")
	}

	return rtmResponse, nil
}

func isIPForwardedVia(ip string, iface string) bool {
	rtMsgQuery, err := makeRouteMessageQuery(ip)
	if err != nil {
		log.Errorf("failed to construct route message query")
		return false
	}

	rtm, err := getRouteMessageResponse(rtMsgQuery)
	if err != nil {
		log.Errorf("failed to run query for VPN route: %s", err)
		return false
	}

	la, ok := rtm.Addrs[1].(*route.LinkAddr)
	if !ok {
		log.Errorf("destination for %s not iface: %s", ip, iface)
		return false
	}
	log.Infof("upstream %s routed via %s", ip, la.Name)
	return (la.Name == iface)
}

func (u *upstreamResolverBase) probeAvailability() {
	if u.areNameServersAllPrivate(u.upstreamServers) {
		u.probeViaRouteMsg()
		return
	}
	u.probeViaResolution()
}

// probeViaRouteMsg enable/disables upstream servers
// test to see if servers are routed via iface
func (u *upstreamResolverBase) probeViaRouteMsg() {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	select {
	case <-u.ctx.Done():
		return
	default:
	}

	var errors *multierror.Error
	var success bool

	for _, upstream := range u.upstreamServers {
		upstream := upstream
		// Split the address into IP and port
		ip, _, err := net.SplitHostPort(upstream)
		if err != nil {
			log.Errorf("Error splitting address: %s", err)
			continue
		}

		isReachableViaWgIface := isIPForwardedVia(ip, u.statusRecorder.GetWgIface())
		if isReachableViaWgIface {
			success = true
			break
		}
		err = fmt.Errorf("upstream nameserver %s not reachable via %s", upstream, u.statusRecorder.GetWgIface())
		log.Warnf(err.Error())
		errors = multierror.Append(err, errors)
	}

	// didn't find a working upstream server, let's disable and try later
	if !success {
		u.disable(errors.ErrorOrNil())
		return
	}

	if !u.disabled.Load() {
		return
	}
	log.Infof("upstreams %s should be available again. Adding them back to system", u.upstreamServers)
	u.reactivate()
	u.disabled.Store(false)
}
