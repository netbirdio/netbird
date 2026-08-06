//go:build darwin && !ios

package cmd

import (
	"fmt"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

func newAgentResources() (vncserver.ScreenCapturer, vncserver.InputInjector, error) {
	// Ask for Screen Recording here and nowhere else: this process runs as the
	// console user, which is what TCC requires for a user-scope service, and it
	// is the point where somebody is demonstrably trying to view the screen.
	// Granting it also requires the capturing process to restart, which comes
	// for free since the agent is respawned per session.
	vncserver.PrimeScreenCapturePermission()

	capturer := vncserver.NewMacPoller()
	injector, err := vncserver.NewMacInputInjector()
	if err != nil {
		return nil, nil, fmt.Errorf("macOS input injector: %w", err)
	}
	return capturer, injector, nil
}
