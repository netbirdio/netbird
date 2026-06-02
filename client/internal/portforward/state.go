//go:build !js

package portforward

import (
	"context"
	"fmt"

	"github.com/libp2p/go-nat"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/portforward/pcp"
)

// discoverGateway is the function used for NAT gateway discovery.
// It can be replaced in tests to avoid real network operations.
// Tries PCP first, then falls back to NAT-PMP/UPnP.
var discoverGateway = defaultDiscoverGateway

func defaultDiscoverGateway(ctx context.Context) (nat.NAT, error) {
	pcpGateway, err := pcp.DiscoverPCP(ctx)
	if err == nil {
		return pcpGateway, nil
	}
	log.Debugf("PCP discovery failed: %v, trying NAT-PMP/UPnP", err)

	return nat.DiscoverGateway(ctx)
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
