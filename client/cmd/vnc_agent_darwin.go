//go:build darwin && !ios

package cmd

import (
	"fmt"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

func newAgentResources() (vncserver.ScreenCapturer, vncserver.InputInjector, error) {
	// Ask for Screen Recording here and nowhere else. This process runs as the
	// console user, which TCC requires for a user-scope service, and it is fresh
	// per connection, which is what makes the dialog appear at all: TCC shows it
	// once per process. The request blocks until the user answers, so it also
	// keeps the Accessibility ask that follows the first input out of its way.
	vncserver.RequestScreenRecording()

	capturer := vncserver.NewMacPoller()
	injector, err := vncserver.NewMacInputInjector()
	if err != nil {
		return nil, nil, fmt.Errorf("macOS input injector: %w", err)
	}
	return capturer, injector, nil
}
