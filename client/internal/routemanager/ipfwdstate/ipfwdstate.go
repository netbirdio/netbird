package ipfwdstate

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

// IPForwardingState is a struct that keeps track of the IP forwarding state.
// todo: read initial state of the IP forwarding from the system and reset the state based on it.
// todo: separate v4/v6 forwarding state, since the sysctls are independent
// (net.ipv4.ip_forward vs net.ipv6.conf.all.forwarding). Currently the nftables
// manager shares one instance between both routers, which works only because
// EnableIPForwarding enables both sysctls in a single call.
type IPForwardingState struct {
	enabledCounter int
}

func NewIPForwardingState() *IPForwardingState {
	return &IPForwardingState{}
}

func (f *IPForwardingState) RequestForwarding() error {
	if f.enabledCounter != 0 {
		f.enabledCounter++
		return nil
	}

	if err := systemops.EnableIPForwarding(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding with sysctl: %w", err)
	}
	f.enabledCounter = 1
	log.Info("IP forwarding enabled")

	return nil
}

func (f *IPForwardingState) ReleaseForwarding() error {
	if f.enabledCounter == 0 {
		return nil
	}

	if f.enabledCounter > 1 {
		f.enabledCounter--
		return nil
	}

	// if failed to disable IP forwarding we anyway decrement the counter
	f.enabledCounter = 0

	// todo call systemops.DisableIPForwarding()
	return nil
}
