package stdnet

import (
	"fmt"
	"net"
	"strings"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
)

type mobileIFaceDiscover struct {
	externalDiscover ExternalIFaceDiscover
}

func newMobileIFaceDiscover(externalDiscover ExternalIFaceDiscover) *mobileIFaceDiscover {
	return &mobileIFaceDiscover{
		externalDiscover: externalDiscover,
	}
}

func (m *mobileIFaceDiscover) iFaces() ([]*transport.Interface, error) {
	ifacesString, err := m.externalDiscover.IFaces()
	if err != nil {
		return nil, err
	}
	interfaces := m.parseInterfacesString(ifacesString)
	return interfaces, nil
}

func (m *mobileIFaceDiscover) parseInterfacesString(interfaces string) []*transport.Interface {
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
			if strings.Contains(addr, "%") {
				continue
			}
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
