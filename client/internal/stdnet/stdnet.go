// Package stdnet is an extension of the pion's stdnet.
// With it the list of the interface can come from external source.
// More info: https://github.com/golang/go/issues/40569
package stdnet

import (
	"fmt"
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
}

// NewNet creates a new StdNet instance.
func NewNet(iFaceDiscover IFaceDiscover) (*Net, error) {
	n := &Net{}

	return n, n.UpdateInterfaces(iFaceDiscover)
}

// UpdateInterfaces updates the internal list of network interfaces
// and associated addresses.
func (n *Net) UpdateInterfaces(iFaceDiscover IFaceDiscover) error {
	ifacesString, err := iFaceDiscover.IFaces()
	if err != nil {
		return err
	}
	n.interfaces = parseInterfacesString(ifacesString)
	return err
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
