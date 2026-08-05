package upnp

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/huin/goupnp"
	"github.com/libp2p/go-nat"
)

var _ nat.NAT = (*NAT)(nil)

// igdClient is the subset of the goupnp IGD service client API used for port mappings.
type igdClient interface {
	GetExternalIPAddressCtx(ctx context.Context) (string, error)
	AddPortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16, protocol string, internalPort uint16, internalClient string, enabled bool, description string, leaseDuration uint32) error
	DeletePortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16, protocol string) error
	GetNATRSIPStatusCtx(ctx context.Context) (rsipAvailable bool, natEnabled bool, err error)
}

// NAT implements the go-nat NAT interface using a UPnP IGD discovered via
// unicast SSDP. Port mapping semantics match go-nat's UPnP implementation:
// a random external port is chosen and remembered per internal port so
// renewals keep the same mapping.
type NAT struct {
	client  igdClient
	natType string
	root    *goupnp.RootDevice

	mu    sync.Mutex
	ports map[int]int // internal port -> mapped external port
}

// Type returns the kind of NAT port mapping service that is used.
func (n *NAT) Type() string {
	return n.natType
}

// GetDeviceAddress returns the internal address of the gateway device.
func (n *NAT) GetDeviceAddress() (net.IP, error) {
	addr, err := net.ResolveUDPAddr("udp4", n.root.URLBase.Host)
	if err != nil {
		return nil, err
	}
	return addr.IP, nil
}

// GetExternalAddress returns the external address of the gateway device.
func (n *NAT) GetExternalAddress() (net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ipString, err := n.client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil, nat.ErrNoExternalAddress
	}
	return ip, nil
}

// GetInternalAddress returns the local address used to reach the gateway device.
func (n *NAT) GetInternalAddress() (net.IP, error) {
	conn, err := net.Dial("udp4", n.root.URLBase.Host)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.Close()
	}()

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, nat.ErrNoInternalAddress
	}
	return localAddr.IP, nil
}

// AddPortMapping maps a port on the local host to an external port.
func (n *NAT) AddPortMapping(ctx context.Context, protocol string, internalPort int, description string, timeout time.Duration) (int, error) {
	proto, err := mapProtocol(protocol)
	if err != nil {
		return 0, err
	}

	internalIP, err := n.GetInternalAddress()
	if err != nil {
		return 0, fmt.Errorf("get internal address: %w", err)
	}
	leaseDuration := uint32(timeout / time.Second)

	n.mu.Lock()
	externalPort := n.ports[internalPort]
	n.mu.Unlock()

	if externalPort > 0 {
		err = n.client.AddPortMappingCtx(ctx, "", uint16(externalPort), proto, uint16(internalPort), internalIP.String(), true, description, leaseDuration)
		if err == nil {
			return externalPort, nil
		}
	}

	for range 3 {
		port := randomPort()
		err = n.client.AddPortMappingCtx(ctx, "", uint16(port), proto, uint16(internalPort), internalIP.String(), true, description, leaseDuration)
		if err == nil {
			n.mu.Lock()
			n.ports[internalPort] = port
			n.mu.Unlock()
			return port, nil
		}
	}
	return 0, err
}

// DeletePortMapping removes a port mapping.
func (n *NAT) DeletePortMapping(ctx context.Context, protocol string, internalPort int) error {
	proto, err := mapProtocol(protocol)
	if err != nil {
		return err
	}

	n.mu.Lock()
	externalPort := n.ports[internalPort]
	delete(n.ports, internalPort)
	n.mu.Unlock()

	if externalPort == 0 {
		return nil
	}
	return n.client.DeletePortMappingCtx(ctx, "", uint16(externalPort), proto)
}

func mapProtocol(s string) (string, error) {
	switch s {
	case "udp":
		return "UDP", nil
	case "tcp":
		return "TCP", nil
	default:
		return "", fmt.Errorf("invalid protocol: %s", s)
	}
}

func randomPort() int {
	return rand.Intn(math.MaxUint16-10000) + 10000
}
