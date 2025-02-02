package ipfwdstate

import (
	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

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
		return err
	}
	f.enabledCounter = 1

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

	if err := systemops.DisableIPForwarding(); err != nil {
		return err
	}
	return nil
}
