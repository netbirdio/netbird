// Package stdnet is an extension of the pion's stdnet.
// With it the list of the interface can come from external source.
// More info: https://github.com/golang/go/issues/40569
package stdnet

import (
	"fmt"
	"golang.zx2c4.com/wireguard/wgctrl"
	"net"
	"strings"

	"github.com/pion/transport/v2"
	"github.com/pion/transport/v2/stdnet"
	log "github.com/sirupsen/logrus"
)

// Net is an implementation of the net.Net interface
// based on functions of the standard net package.
type Net struct {
	stdnet.Net
	interfaces []*transport.Interface
	// interfaceFilter should return true if the given interfaceName is allowed
	interfaceFilter func(interfaceName string) bool
}

// NewNet creates a new StdNet instance.
// iFaceDiscover and disallowList can be nil.
// iFaceDiscover
func NewNet(iFaceDiscover IFaceDiscover, disallowList []string) (*Net, error) {
	n := &Net{interfaceFilter: InterfaceFilter(disallowList)}
	return n, n.UpdateInterfaces(iFaceDiscover)
}

func (n *Net) filterInterfaces(interfaces []*transport.Interface) []*transport.Interface {
	if n.interfaceFilter == nil {
		return interfaces
	}
	result := []*transport.Interface{}
	for _, iface := range interfaces {
		if n.interfaceFilter(iface.Name) {
			result = append(result, iface)
		}
	}
	return result
}

// UpdateInterfaces updates the internal list of network interfaces
// and associated addresses filtering them by name.
// The interfaces are discovered by an external iFaceDiscover function or by a default discoverer if the external one
// wasn't specified.
func (n *Net) UpdateInterfaces(iFaceDiscover IFaceDiscover) error {
	discoveredInterfaces := []*transport.Interface{}
	var err error
	if iFaceDiscover != nil {
		interfacesString := ""
		interfacesString, err = iFaceDiscover.IFaces()
		discoveredInterfaces = parseInterfacesString(interfacesString)
	} else {
		// fallback to the default discovering if custom IFaceDiscover wasn't provided
		discoveredInterfaces, err = discoverInterfaces()
	}
	if err != nil {
		return err
	}

	n.interfaces = n.filterInterfaces(discoveredInterfaces)
	return nil
}

func discoverInterfaces() ([]*transport.Interface, error) {
	ifs := []*transport.Interface{}

	oifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, oif := range oifs {
		ifc := transport.NewInterface(oif)

		addrs, err := oif.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			ifc.AddAddress(addr)
		}

		ifs = append(ifs, ifc)
	}

	return ifs, nil
}

// Interfaces returns a slice of interfaces which are available on the
// system
func (n *Net) Interfaces() ([]*transport.Interface, error) {
	return n.interfaces, nil
}

// InterfaceByIndex returns the interface specified by index.
//
// On Solaris, it returns one of the logical network interfaces
// sharing the logical data link; for more precision use
// InterfaceByName.
func (n *Net) InterfaceByIndex(index int) (*transport.Interface, error) {
	for _, ifc := range n.interfaces {
		if ifc.Index == index {
			return ifc, nil
		}
	}

	return nil, fmt.Errorf("%w: index=%d", transport.ErrInterfaceNotFound, index)
}

// InterfaceByName returns the interface specified by name.
func (n *Net) InterfaceByName(name string) (*transport.Interface, error) {
	for _, ifc := range n.interfaces {
		if ifc.Name == name {
			return ifc, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", transport.ErrInterfaceNotFound, name)
}

func parseInterfacesString(interfaces string) []*transport.Interface {
	ifs := []*transport.Interface{}

	for _, iface := range strings.Split(interfaces, "\n") {
		if strings.TrimSpace(iface) == "" {
			continue
		}

		fields := strings.Split(iface, "|")
		if len(fields) != 2 {
			log.Warnf("parseInterfacesString: unable to split %q", iface)
			continue
		}

		var name string
		var index, mtu int
		var up, broadcast, loopback, pointToPoint, multicast bool
		_, err := fmt.Sscanf(fields[0], "%s %d %d %t %t %t %t %t",
			&name, &index, &mtu, &up, &broadcast, &loopback, &pointToPoint, &multicast)
		if err != nil {
			log.Warnf("parseInterfacesString: unable to parse %q: %v", iface, err)
			continue
		}

		newIf := net.Interface{
			Name:  name,
			Index: index,
			MTU:   mtu,
		}
		if up {
			newIf.Flags |= net.FlagUp
		}
		if broadcast {
			newIf.Flags |= net.FlagBroadcast
		}
		if loopback {
			newIf.Flags |= net.FlagLoopback
		}
		if pointToPoint {
			newIf.Flags |= net.FlagPointToPoint
		}
		if multicast {
			newIf.Flags |= net.FlagMulticast
		}

		ifc := transport.NewInterface(newIf)

		addrs := strings.Trim(fields[1], " \n")
		foundAddress := false
		for _, addr := range strings.Split(addrs, " ") {
			ip, ipNet, err := net.ParseCIDR(addr)
			if err != nil {
				log.Warnf("%s", err)
				continue
			}
			ipNet.IP = ip
			ifc.AddAddress(ipNet)
			foundAddress = true
		}
		if foundAddress {
			ifs = append(ifs, ifc)
		}
	}
	return ifs
}

// InterfaceFilter is a function passed to ICE Agent to filter out not allowed interfaces
// to avoid building tunnel over them.
func InterfaceFilter(disallowList []string) func(string) bool {

	return func(iFace string) bool {

		if strings.HasPrefix(iFace, "lo") {
			// hardcoded loopback check to support already installed agents
			return false
		}

		for _, s := range disallowList {
			if strings.HasPrefix(iFace, s) {
				log.Debugf("ignoring interface %s - it is not allowed", iFace)
				return false
			}
		}
		// look for unlisted WireGuard interfaces
		wg, err := wgctrl.New()
		if err != nil {
			log.Debugf("trying to create a wgctrl client failed with: %v", err)
			return true
		}
		defer func() {
			_ = wg.Close()
		}()

		_, err = wg.Device(iFace)
		return err != nil
	}
}
