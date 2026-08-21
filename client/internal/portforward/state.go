//go:build !js

package portforward

import (
	"context"
	"errors"
	"fmt"

	"github.com/netbirdio/go-nat"
	"github.com/netbirdio/go-nat/pcp"
	log "github.com/sirupsen/logrus"
)

// discoverGateway is the function used for NAT gateway discovery.
// It can be replaced in tests to avoid real network operations.
var discoverGateway = defaultDiscoverGateway

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
	gateway, err := discoverNATGateway(ctx)
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
