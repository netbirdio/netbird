//go:build !js

package portforward

import (
	"context"
	"fmt"

	"github.com/libp2p/go-nat"
	log "github.com/sirupsen/logrus"
)

// discoverGateway is the function used for NAT gateway discovery.
// It can be replaced in tests to avoid real network operations.
var discoverGateway = nat.DiscoverGateway

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
