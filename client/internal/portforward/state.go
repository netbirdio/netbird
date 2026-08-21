//go:build !js

package portforward

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/netbirdio/go-nat"
	"github.com/netbirdio/go-nat/pcp"
	log "github.com/sirupsen/logrus"
)

// discoverGateway is the function used for NAT gateway discovery.
// It can be replaced in tests to avoid real network operations.
var discoverGateway = defaultDiscoverGateway

// pinholeDiscoveryTimeout is the slice of the discovery budget held back for
// the IPv6 pinhole probe.
//
// Sizing it is coarser than it looks: PCP retransmits on a 3s socket timeout
// and a 3s first backoff, so a second attempt needs about 9s. Anything from
// roughly 1s to 8s therefore buys exactly one attempt, and this only sets how
// long that attempt waits. A PCP server sits on the local link and answers in
// milliseconds, so 3s is margin rather than need, and the rest is left to
// gateway discovery, whose multicast SSDP search alone takes 5s. A probe lost
// to a dropped packet is retried by the next discovery round.
//
// It is a variable so tests can shorten it.
var pinholeDiscoveryTimeout = 3 * time.Second

// Discovery entry points, as variables so tests can drive the fallback without
// touching the network.
var (
	discoverNATGateway = nat.DiscoverGateway

	discoverPCPPinhole = func(ctx context.Context) (nat.NAT, error) {
		pinhole, err := pcp.DiscoverPCP(ctx)
		if err != nil {
			return nil, err
		}
		return pinhole, nil
	}
)

// defaultDiscoverGateway finds a gateway that can make the WireGuard port
// reachable. DiscoverGateway prefers PCP for IPv4, races UPnP and NAT-PMP
// behind it, and attaches an IPv6 pinhole independently of which IPv4 protocol
// wins.
//
// It reports no gateway on a network offering only IPv6, having no IPv4 mapping
// to attach a pinhole to. Such a network still needs one: there is no
// translation to traverse, but the router drops inbound IPv6 until something
// opens it. Fall back to PCP alone, which yields a gateway holding just the
// pinhole.
func defaultDiscoverGateway(ctx context.Context) (nat.NAT, error) {
	gatewayCtx, cancel := reserveForPinhole(ctx)
	defer cancel()

	gateway, err := discoverNATGateway(gatewayCtx)
	if err == nil {
		return gateway, nil
	}
	if !errors.Is(err, nat.ErrNoNATFound) {
		return nil, err
	}

	pinhole, pinholeErr := discoverPCPPinhole(ctx)
	if pinholeErr != nil {
		log.Debugf("no IPv6 pinhole after %v: %v", err, pinholeErr)
		return nil, err
	}

	log.Infof("no IPv4 gateway, continuing with an IPv6 pinhole only")
	return pinhole, nil
}

// reserveForPinhole shortens ctx so that a pinhole probe still has time to run
// afterwards. Finding nothing takes gateway discovery everything it is given,
// so on the unshortened context the probe would start already expired. A budget
// too small to divide is left to gateway discovery, which is the likelier win.
func reserveForPinhole(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.WithCancel(ctx)
	}

	remaining := time.Until(deadline)
	if remaining <= pinholeDiscoveryTimeout {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, remaining-pinholeDiscoveryTimeout)
}

// State is persisted only for crash recovery cleanup
type State struct {
	InternalPort uint16 `json:"internal_port,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
}

func (s *State) Name() string {
	return "port_forward_state"
}

// Cleanup implements statemanager.CleanableState for crash recovery
func (s *State) Cleanup() error {
	if s.InternalPort == 0 {
		return nil
	}

	log.Infof("cleaning up stale port mapping for port %d", s.InternalPort)

	ctx, cancel := context.WithTimeout(context.Background(), discoveryTimeout)
	defer cancel()

	gateway, err := discoverGateway(ctx)
	if err != nil {
		// Discovery failure is not an error - gateway may not exist
		log.Debugf("cleanup: no gateway found: %v", err)
		return nil
	}

	if err := gateway.DeletePortMapping(ctx, s.Protocol, int(s.InternalPort)); err != nil {
		return fmt.Errorf("delete port mapping: %w", err)
	}

	return nil
}
