//go:build darwin && !ios

package cmd

import (
	"fmt"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

func newAgentResources() (vncserver.ScreenCapturer, vncserver.InputInjector, error) {
	capturer := vncserver.NewMacPoller()
	injector, err := vncserver.NewMacInputInjector()
	if err != nil {
		return nil, nil, fmt.Errorf("macOS input injector: %w", err)
	}
	return capturer, injector, nil
}
