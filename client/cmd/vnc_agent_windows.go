//go:build windows

package cmd

import (
	log "github.com/sirupsen/logrus"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

func newAgentResources() (vncserver.ScreenCapturer, vncserver.InputInjector, error) {
	sessionID := vncserver.GetCurrentSessionID()
	log.Infof("VNC agent running in Windows session %d", sessionID)
	return vncserver.NewDesktopCapturer(), vncserver.NewWindowsInputInjector(), nil
}
