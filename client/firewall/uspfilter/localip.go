package uspfilter

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
)

// localIPSnapshot is an immutable snapshot of local IP addresses, swapped
// atomically so reads are lock-free.
type localIPSnapshot struct {
	ips map[netip.Addr]struct{}
}

type localIPManager struct {
	snapshot atomic.Pointer[localIPSnapshot]
}

func newLocalIPManager() *localIPManager {
	m := &localIPManager{}
	m.snapshot.Store(&localIPSnapshot{
		ips: make(map[netip.Addr]struct{}),
	})
	return m
}

func processInterface(iface net.Interface, ips map[netip.Addr]struct{}, addresses *[]netip.Addr) {
	addrs, err := iface.Addrs()
	if err != nil {
		log.Debugf("get addresses for interface %s failed: %v", iface.Name, err)
		return
	}

	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}

		parsed, ok := netip.AddrFromSlice(ip)
		if !ok {
			log.Warnf("invalid IP address %s in interface %s", ip.String(), iface.Name)
			continue
		}

		parsed = parsed.Unmap()
		ips[parsed] = struct{}{}
		*addresses = append(*addresses, parsed)
	}
}

// UpdateLocalIPs rebuilds the local IP snapshot and swaps it in atomically.
func (m *localIPManager) UpdateLocalIPs(iface common.IFaceMapper) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	ips := make(map[netip.Addr]struct{})
	var addresses []netip.Addr

	// loopback
	ips[netip.AddrFrom4([4]byte{127, 0, 0, 1})] = struct{}{}
	ips[netip.IPv6Loopback()] = struct{}{}

	if iface != nil {
		ip := iface.Address().IP
		ips[ip] = struct{}{}
		addresses = append(addresses, ip)
		if v6 := iface.Address().IPv6; v6.IsValid() {
			ips[v6] = struct{}{}
			addresses = append(addresses, v6)
		}
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Warnf("failed to get interfaces: %v", err)
	} else {
		// TODO: filter out down interfaces (net.FlagUp). Also handle the reverse
		// case where an interface comes up between refreshes.
		for _, intf := range interfaces {
			processInterface(intf, ips, &addresses)
		}
	}

	m.snapshot.Store(&localIPSnapshot{ips: ips})

	log.Debugf("Local IP addresses: %v", addresses)
	return nil
}

// IsLocalIP checks if the given IP is a local address. Lock-free on the read path.
func (m *localIPManager) IsLocalIP(ip netip.Addr) bool {
	s := m.snapshot.Load()

	if ip.Is4() && ip.As4()[0] == 127 {
		return true
	}

	_, found := s.ips[ip]
	return found
}
