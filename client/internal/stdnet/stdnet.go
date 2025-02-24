// Package stdnet is an extension of the pion's stdnet.
// With it the list of the interface can come from external source.
// More info: https://github.com/golang/go/issues/40569
package stdnet

import (
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/pion/transport/v3"
	"github.com/pion/transport/v3/stdnet"
)

const updateInterval = 30 * time.Second

// Net is an implementation of the net.Net interface
// based on functions of the standard net package.
type Net struct {
	stdnet.Net
	interfaces    []*transport.Interface
	iFaceDiscover iFaceDiscover
	// interfaceFilter should return true if the given interfaceName is allowed
	interfaceFilter func(interfaceName string) bool
	lastUpdate      time.Time

	// mu is shared between interfaces and lastUpdate
	mu sync.Mutex
}

// NewNetWithDiscover creates a new StdNet instance.
func NewNetWithDiscover(iFaceDiscover ExternalIFaceDiscover, disallowList []string) (*Net, error) {
	n := &Net{
		iFaceDiscover:   newMobileIFaceDiscover(iFaceDiscover),
		interfaceFilter: InterfaceFilter(disallowList),
	}
	return n, n.UpdateInterfaces()
}

// NewNet creates a new StdNet instance.
func NewNet(disallowList []string) (*Net, error) {
	n := &Net{
		iFaceDiscover:   pionDiscover{},
		interfaceFilter: InterfaceFilter(disallowList),
	}
	return n, n.UpdateInterfaces()
}

// UpdateInterfaces updates the internal list of network interfaces
// and associated addresses filtering them by name.
// The interfaces are discovered by an external iFaceDiscover function or by a default discoverer if the external one
// wasn't specified.
func (n *Net) UpdateInterfaces() (err error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.updateInterfaces()
}

func (n *Net) updateInterfaces() (err error) {
	allIfaces, err := n.iFaceDiscover.iFaces()
	if err != nil {
		return err
	}

	n.interfaces = n.filterInterfaces(allIfaces)

	n.lastUpdate = time.Now()

	return nil
}

// Interfaces returns a slice of interfaces which are available on the
// system
func (n *Net) Interfaces() ([]*transport.Interface, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if time.Since(n.lastUpdate) < updateInterval {
		return slices.Clone(n.interfaces), nil
	}

	if err := n.updateInterfaces(); err != nil {
		return nil, fmt.Errorf("update interfaces: %w", err)
	}

	return slices.Clone(n.interfaces), nil
}

// InterfaceByIndex returns the interface specified by index.
//
// On Solaris, it returns one of the logical network interfaces
// sharing the logical data link; for more precision use
// InterfaceByName.
func (n *Net) InterfaceByIndex(index int) (*transport.Interface, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, ifc := range n.interfaces {
		if ifc.Index == index {
			return ifc, nil
		}
	}

	return nil, fmt.Errorf("%w: index=%d", transport.ErrInterfaceNotFound, index)
}

// InterfaceByName returns the interface specified by name.
func (n *Net) InterfaceByName(name string) (*transport.Interface, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, ifc := range n.interfaces {
		if ifc.Name == name {
			return ifc, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", transport.ErrInterfaceNotFound, name)
}

func (n *Net) filterInterfaces(interfaces []*transport.Interface) []*transport.Interface {
	if n.interfaceFilter == nil {
		return interfaces
	}
	var result []*transport.Interface
	for _, iface := range interfaces {
		if n.interfaceFilter(iface.Name) {
			result = append(result, iface)
		}
	}
	return result
}
